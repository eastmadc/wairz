# Patterns: Deployment Loop Closure (2026-04-18)

> Extracted: 2026-04-18
> Campaign: not a registered campaign — the
>   `/learn commit and ensure dockers are fully updated` wrap-up
>   segment of session 59045370
> Prior /learns this session:
>   - autopilot-seed-option-a-2026-04-18-patterns.md (6415d62)
>   - unpack-escape-symlink-fix-2026-04-18-patterns.md (c736bf7)
> Postmortem: none

## Context

Nine commits landed in this session, including two that changed
runtime behavior (the A.1 LAN bind and the escape-symlink fix).
Earlier validation used `docker cp` against a 15-hour-old container —
great for iteration speed (CLAUDE.md rule 20) but NOT deployment.
This segment closed the loop: rebuild the image, recreate the
container, and prove the runtime behavior matches the compose-file
claim.

## Successful Patterns

### 1. Two-phase `up -d` strategy — build where code changed, recreate where config changed

- **Description:** The session touched `backend/app/workers/*` (code
  change — image needs rebuild) AND `docker-compose.yml` ports for
  frontend (config change — image unchanged, container needs
  recreation). Right order of operations:

      docker compose up -d --build backend worker   # rebuild images
      docker compose up -d frontend                 # recreate only

  `--build` rebuilds and recreates atomically. The second command
  without `--build` just recreates to pick up the new port binding.
  Skipping `--build` on frontend saves ~3 min of cache-miss build
  time for no functional difference.
- **Evidence:** Build output showed `backend Built`, `worker Built`,
  recreate of both; second command showed only `Container
  wairz-frontend-1 Recreated`.
- **Applies when:** A session commits mixed changes across code and
  compose config, touching only a subset of services. Map each
  changed file to the services whose image/container it affects, then
  issue the minimal combination.

### 2. Smoke-test the fix function inside the FRESH image

- **Description:** After rebuild, ran:

      docker compose exec -T -w /app -e PYTHONPATH=/app backend \
          /app/.venv/bin/python -c "
      from app.workers.unpack_common import \
          remove_extraction_escape_symlinks as a
      import inspect
      assert 'binwalk3' in inspect.getsource(a)
      print('source-line count:', len(inspect.getsource(a).splitlines()))
      "

  Two signals: the import proves a callable of that name exists in
  the image, and `inspect.getsource` proves it's the correct
  implementation (docstring includes "binwalk3", 66 lines). Import
  alone could pass even if the new code never made it into the image
  (e.g. someone created a stub or the module was shadowed); source
  inspection catches that class of miss.
- **Evidence:** "fix function in NEW image: ...; source-line count:
  66; NEW image contains the fix" — confidence beyond just `exit 0`.
- **Applies when:** Rebuilding after a small surgical code change.
  30-second inline Python beats reading the image's manifest and
  trusting that the right layer was included. Also applies when
  CI-built images are deployed: `docker pull` can succeed but ship a
  stale digest if the tag wasn't moved.

### 3. LAN-bind verification via external IP, not just loopback

- **Description:** After the A.1 change and frontend recreate:

      LAN_IP=$(hostname -I | awk '{print $1}')
      curl -sf --max-time 2 http://127.0.0.1:8000/health     # expect 200
      curl -sf --max-time 2 http://${LAN_IP}:8000/health     # expect fail
      curl -sf --max-time 2 http://${LAN_IP}:3000/           # expect fail

  Three probes: (a) loopback works, (b) LAN IP refused for backend,
  (c) LAN IP refused for frontend. All three required to claim the
  A.1 mitigation is ACTIVE at the network layer. `docker compose
  config | grep host_ip` earlier showed `127.0.0.1` — that was the
  compose-file claim, not runtime reality (the 15-hour-old container
  still had the pre-A.1 0.0.0.0 bind).
- **Evidence:** "HTTP 000 / correctly refused from LAN" for both
  backend and frontend on 10.54.8.152 post-rebuild.
- **Applies when:** Any network-scoping change (port bind,
  middleware, firewall rule, iptables). The config says one thing;
  the kernel routes another. If a host has multiple interfaces or a
  multi-homed Docker network, the "correct in config" / "wrong at
  runtime" gap is especially easy to miss.

## Avoided Anti-patterns

### 1. Treating `docker cp` as deployment

- **What almost happened:** After committing the escape-symlink fix
  (90ed79c), it would have been tempting to stop — `git log` says
  the code is there, and `docker cp` earlier put the file into the
  running container for validation. If the session ended at that
  point, the next container restart (during a reboot, a cron-
  restart, or another `up -d --build` for an unrelated change)
  would silently revert to pre-fix behavior because the IMAGE
  doesn't have the file — only the running container's overlay does.
- **Failure mode:** Fix regresses on next restart. Between now and
  then, no git-bisect signal; "worked on my machine" without a
  clean explanation.
- **Evidence:** CLAUDE.md rule 20 explicitly documents this:
  "`docker cp` is for validation speed, not durable state. Still
  rebuild backend+worker before trusting for the next session." The
  user's directive "ensure dockers are fully updated" was the
  explicit close-the-loop prompt.
- **How to avoid:** A commit hash and a `docker cp` do not ship a
  fix. `docker compose up -d --build <services>` ships it. Include
  the rebuild in the definition-of-done for any change that modifies
  code inside `backend/app/` (or `/worker/` — same Dockerfile per
  rule #8).

### 2. Claiming network behavior from compose config alone

- **What almost happened:** Earlier in the session, I verified A.1
  via `docker compose config | grep host_ip` → four entries all
  `127.0.0.1`. That's a good first check, but it describes the
  compose-file's INTENT, not the running container's
  behavior. The 15-hour-old backend container still published
  `0.0.0.0:8000` (visible via `docker compose ps`'s `Ports` column
  before recreation).
- **Failure mode:** Reporting "LAN exposure closed" when the actual
  runtime still exposes 8000 to every host. A scanner on the LAN
  would still reach /ws.
- **Evidence:** pre-rebuild `docker compose ps` showed
  `0.0.0.0:8000->8000/tcp` for backend — the config-vs-runtime gap
  was visible at that moment.
- **How to avoid:** After any port / bind / network edit, verify by
  hitting the endpoint from the "wrong" interface externally. A
  refused-connection is the only proof that binding actually took
  effect.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Two-phase `up -d` (`--build backend worker` then `frontend` bare) | Frontend had no code change — rebuilding wastes ~3 min with no behavior delta | Fast, correctly scoped |
| Include `inspect.getsource` in smoke test, not just `import` | Import success is a weaker signal than source-line-count match — catches stub / shadowing | Source check confirmed 66-line function with expected docstring |
| Verify A.1 binding from LAN IP, not just loopback | Compose config had been verified earlier; runtime behavior is the user-facing concern | HTTP 000 on LAN for both backend and frontend — A.1 proven |
| Re-query DPCS10 canary AFTER rebuild | Container recreation could in principle lose DB state (though it doesn't); fastest to confirm | 260 / 27 / 439 unchanged |
| Skip emulation / fuzzing / vulhunt rebuild | They use separate Dockerfiles and no code in this session touched them | Saved minutes; no regression |

## Quality Rule Candidates

None. Each lesson is a procedural gate at deploy-time, not a
code-shape predicate. A regex like "commit message mentions
`workers/`" couldn't reliably trigger the "run rebuild" action
without risk of spurious nags.

If a future session produces a concrete "didn't rebuild after code
change" incident with a specific signature (e.g. `git log` shows
a `backend/app/` edit but no subsequent `docker compose up -d
--build` in the session's command history), that would be a
candidate for a session-end validation rule. Not today.
