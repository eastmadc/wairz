# Patterns: Wairz Intake Sweep — Phase 1 Security Sweep

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Phase: 1 of 7 (Security sweep)
> Commits: ab09e1c → 089347a (6 commits, one session 69f004fe)
> Streams: A (auth-hardening B.1.a/b/c), B (fuzzing shell injection), C (android/ZIP safe-extract), D (docker-socket-proxy)
> Postmortem: none (campaign still active)
> Audit: `.planning/telemetry/audit.jsonl` (phase 1 window)

## Scope delivered

Six commits in one session. Four security streams dispatched as two fleet waves of two (A+C then B+D). Phase-1 end-condition battery passed cleanly, including a mid-phase /health/deep regression caught by the archon self-correction step and fixed in-session.

## Successful Patterns

### 1. Intake status-header scan as the scope-exclusion filter at campaign creation

- **Description:** Before drafting the phase decomposition, ran `grep -m1 '^status:' .planning/intake/*.md` across the whole intake directory. Revealed three pre-completed intakes (`data-analysis-cache-operation-varchar-fix`, `backend-cwe-checker-session-fix`, `frontend-firmware-hook-dedup`) that would otherwise have been re-scoped. Net campaign shrunk from 20 → 17 items, preventing dormant-code production.
- **Evidence:** Campaign Decision Log entry "Skip 3 already-completed intakes" cites commit shas (1f6c72decc84, b9f625a, 97c7c7a) from predecessor sessions. Rule 19 applied at campaign-decomposition time, not at intake-execution time.
- **Applies when:** Any campaign that ingests a pre-existing intake pile. The scan takes <1 s and saves 10-60 min of re-scoping per stale item. Cheaper than letting a Fleet stream discover the no-op mid-execution.

### 2. Two waves of two over one wave of four on file-overlap risk

- **Description:** Phase 1 had four independent intakes (B.1.a/b/c, B.2, B.3, docker-socket-proxy). Naive dispatch = 4 parallel streams. Instead, split into Wave 1 (A=auth-hardening + C=safe_extract — touched `config.py` + workers) and Wave 2 (B=fuzzing + D=docker-socket-proxy — touched services + compose). A and D both needed `config.py` edits; co-dispatching them would have produced a merge conflict on the Settings class.
- **Evidence:** Wave 1 shipped ab09e1c + de3f6bd cleanly. Wave 2 shipped e443def + bac49ea cleanly. Zero merge conflicts across 6 commits. Wave 2 Stream D added `docker_host` field to the same `config.py` that Stream A had modified in Wave 1 — serial order (A then D) meant the addition was additive, not concurrent.
- **Applies when:** Fleet dispatch with 3+ independent items where any two touch the same top-level class or module. Pre-dispatch, `grep -l` the candidate target files for each stream; any same-file pair goes into different waves. Token budget also benefits — 2-agent waves run ~3× faster per wave than 4-agent because the orchestrator doesn't re-page context as often.

### 3. Single-entry-point helper for cross-cutting security concerns

- **Description:** Both Stream C (`safe_extract_zip`) and Stream D (`get_docker_client`) followed the same shape: create one shared module that encapsulates the security invariant, then migrate N direct call sites to the helper. Stream C: `backend/app/workers/safe_extract.py` + 3 call sites. Stream D: `backend/app/utils/docker_client.py` + 10 call sites. The helper owns the invariant; future additions reuse it by import, not by pattern repetition.
- **Evidence:** Stream C grep: `grep -rn "ZipFile.*extractall" backend/app/workers/ → 0 hits` post-migration. Stream D grep: `grep -rn "docker.from_env()" backend/app/ → 0 hits` post-migration. Both prove the helper is the ONLY path, so a future commit adding a raw call path would be immediately visible in review.
- **Applies when:** Security (or any invariant) that must hold across N call sites. Writing the helper first + migrating wins over annotating each site because the annotation discipline rots; the helper's single-path enforcement does not.

### 4. L1/L2/L3 fix hierarchy for shell-injection

- **Description:** Stream B documented three fix levels for shell-injection remediation, choosing per site:
  - **L1 — file staging + argv-list exec.** `container.put_archive(...)` + `container.exec_run(["sh", "/path/to/script.sh"])`. No shell-in-a-string; strongest isolation.
  - **L2 — argv-list without shell.** `container.exec_run(["cmd", "arg1", "arg2"])`. Works for single commands.
  - **L3 — `shlex.quote` on every var in a single-shell form.** Acceptable only when a shell wrapper is genuinely needed (e.g. redirection or pipe).
- **Evidence:** Stream B applied L1 at two fuzzing sites (AFL launch + GDB triage), L2 at one emulation site (chmod dirs from a hardcoded list), L3 at one emulation site (binary_path interpolation). Harness rule `auto-review-no-shell-interpolation` matches 0 files post-fix.
- **Applies when:** Any remediation of a shell-injection class. Document the choice per site explicitly; future reviewers can verify the level matches the risk surface. Prefer L1 unless per-site constraints force L2/L3.

### 5. `AliasChoices` for dual-env-var support on pydantic BaseSettings

- **Description:** Stream A's `allow_no_auth` needed to accept both `WAIRZ_ALLOW_NO_AUTH` (project-prefixed, preferred new form) and `ALLOW_NO_AUTH` (short form, backwards-compat). Pydantic-settings idiom:
  ```python
  from pydantic import AliasChoices, Field

  allow_no_auth: bool = Field(
      default=False,
      validation_alias=AliasChoices("WAIRZ_ALLOW_NO_AUTH", "ALLOW_NO_AUTH"),
  )
  ```
  Single setting, two env names, no setter code, backwards-compatible.
- **Evidence:** Stream A verification — both `WAIRZ_ALLOW_NO_AUTH=true` and `ALLOW_NO_AUTH=true` triggered the lifespan-guard bypass in testing.
- **Applies when:** Any pydantic-settings field where a rename / prefix-migration is wanted without a flag-day. Prefer over custom property shims; native pydantic support is less surprising.

### 6. Live backend-log + curl-matrix as verification oracle for Phase-level end conditions

- **Description:** Phase 1 end-condition battery was 6 curl calls + 1 psql canary + 1 proxy allowlist probe, all in under 10 s. Each call returns a single line of `CHECK=HTTP_CODE` output that's greppable for PASS/FAIL. Repeatable across rebuilds, cacheable in campaign file, rerunnable by a future session for regression detection.
- **Evidence:** Phase 1 close-out commit message includes the battery verbatim ("HTTP no-key → 401, good-key → 200, /health → 200, /health/deep → 200, slowapi 429 triggered, DPCS10 canary 260, shell-interpolation grep 0, proxy allowlist volumes→403 containers→19"). Ran twice — once mid-phase (caught /health/deep 503), once post-fix (clean 200).
- **Applies when:** Any phase whose contract is "system behaves this way from the outside." The battery lives in the campaign's Phase End Conditions table; treat it as the phase's runnable API contract.

### 7. Rebuild BOTH backend AND worker after rule-20 class-shape changes (verified twice this phase)

- **Description:** Rule 20 (CLAUDE.md) states that a class-shape change on cached Settings / dataclasses needs a process restart beyond `docker cp`. Phase 1 hit this twice: Stream A added `allow_no_auth` to config.py; Stream D added `docker_host` to config.py. Both required the full `docker compose up -d --build backend worker`. Stream A used two `docker compose restart backend worker` iterations for validation speed then flagged the full rebuild as an action-required; Stream D did the full rebuild up-front. Both approaches are valid; both must touch `worker` not just `backend`.
- **Evidence:** Stream A handoff action-required line: "docker compose up -d --build backend worker before trusting". Stream D committed after running `docker compose up -d --build backend worker`. My final Phase 1 close-out commit added a third config.py-touching change (health-check fix imports from `docker_client` which needed the docker_host field durable in the image).
- **Applies when:** Any diff that adds, removes, or renames a field on `config.py::Settings` or any `@dataclass` cached by `@lru_cache`. Codified in CLAUDE.md rule 20.

### 8. Archon-driven direct Agent dispatch with `isolation: "worktree"` — but agents commit to parent branch

- **Description:** Archon delegated Phase 1 work by calling the `Agent` tool directly (not `/fleet` skill). Each Agent call used `isolation: "worktree"` and ran in the background. On completion, each agent committed directly to `clean-history` — the worktree isolation apparently collapsed to the parent branch at commit time. Net effect: 4 clean commits on clean-history, no manual merge step, no worktree-prune needed.
- **Evidence:** Notification messages showed `<worktree><worktreePath>ok</worktreePath></worktree>` (not a path, just "ok"). `git log --oneline` showed all 4 stream commits on clean-history directly. Task #1 marked complete after all four landed + verified. No `git merge` or `git worktree` command ran this session.
- **Applies when:** Archon-driven Fleet waves where the phase's streams are intended to land on the same branch at completion. Worktree isolation is an agent-local sandbox, not a branch-level isolation. For true branch-level isolation, would need each agent to `git checkout -b` and archon to merge after. Current shape is simpler and works for phases where the streams' files are disjoint.

## Key Decisions

| Date | Decision | Rationale | Outcome |
|---|---|---|---|
| 2026-04-19 | 7-phase decomposition by domain | Clear intake-to-phase mapping; fleet parallelism plan per phase; serialisation where model/file overlap exists | Phase 1 complete in session 1; Phase 2-7 queued with pickup notes |
| 2026-04-19 | Skip 3 pre-completed intakes at campaign creation | Rule 19 evidence-first; DB/commit already reflects completion | Saved ~3 intake-worth of dormant code |
| 2026-04-19 | 2 waves of 2 for Phase 1 (not 1 wave of 4) | Config.py collision risk between A and D; token-budget per orchestrator turn | Zero merge conflicts; waves completed sequentially in under one session each |
| 2026-04-19 | Daemon budget $40 @ $2/session, trust level "Trusted" (110 sessions) | 2x safety margin over 10-session estimate per Archon protocol | Daemon.json `status: running` persisted; SessionStart hook will chain Phase 2 |
| 2026-04-19 | Socket-proxy allowlist minimal (CONTAINERS, IMAGES, NETWORKS, EVENTS, EXEC, POST; VOLUMES=0, SYSTEM=0) | Only what Wairz uses today; principle of least privilege | Broke `/health/deep` stat-based check; fix landed same session |
| 2026-04-19 | Health-check regression fix as the phase close-out commit (not Stream D follow-up) | The break was visible only at phase-boundary verification, not at stream-dispatch time; self-correction step of archon protocol | Clean /health/deep 200 at phase end; commit 29dba35 bundles fix + campaign artefacts |
| 2026-04-19 | Campaign continuation state written as a follow-up commit (089347a) | Phase-1 close-out commit is about the work; continuation state is about the daemon handoff — distinct concerns | Clean git log; next session reads 089347a's updated Continuation State |

## Quality Rule Candidates

### Adding: `auto-intake-sweep-1-no-stat-docker-sock`

- **Pattern regex:** `os\.path\.exists\([^)]*docker\.sock`
- **File pattern:** `backend/app/**.py`
- **Message:** "Stat-based `/var/run/docker.sock` presence check fails after the docker-socket-proxy migration (session 69f004fe, commit bac49ea). Probe via `get_docker_client().containers.list(limit=1)` — verifies both DOCKER_HOST connectivity AND the proxy's CONTAINERS allowlist."
- **Confidence:** high. Phase-1 /health/deep regression was caused by exactly this pattern. Direct evidence in commit 29dba35.

### Adding: `auto-intake-sweep-1-no-docker-from-env`

- **Pattern regex:** `docker\.from_env\(\)`
- **File pattern:** `backend/app/**.py`
- **Message:** "Use `get_docker_client()` from `app.utils.docker_client` instead of `docker.from_env()`. The factory honours `settings.docker_host` which routes through the socket proxy (commit bac49ea). Direct `from_env()` bypasses the proxy and fails once the raw socket mount is removed."
- **Confidence:** high. Stream D migrated 10 call sites across 8 files; a single regression would break emulation/fuzzing/terminal flows.

### Rejected: pre-accept WebSocket close

- Already rejected in B.1's pattern extraction (session 698549d4). No new evidence this phase.

### Rejected: campaign-file-ordering vs git stash

- Process rule, not code rule. Added as session-history note in the campaign file + in this patterns doc's Decisions table. Codifying as a regex would catch innocent stash commands.
