# Anti-patterns: Wairz Intake Sweep — Phase 1 Security Sweep

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md`
> Phase: 1 of 7

## Failed Patterns

### 1. `git stash --include-untracked` AFTER writing the campaign file swallows it

- **What was done:** Archon protocol Step 3.1 (Create phase checkpoint) was executed AFTER Step 2 (Write campaign file). The campaign file was untracked at stash time, so `git stash push --include-untracked -m "citadel-checkpoint-..."` captured it into the checkpoint.
- **Failure mode:** `ls .planning/campaigns/wairz-intake-sweep-2026-04-19.md` returned "No such file or directory" at the next Edit attempt. Campaign file was inside stash@{0}. Recovery required `git stash pop stash@{0}` which also restored Stream A's in-flight uncommitted changes (cosmetic noise on the pop diff).
- **Evidence:** Stash content inspection via `git stash show -p --include-untracked stash@{0}` showed the campaign file in the diff. Lost ~2 minutes to the recovery loop.
- **How to avoid:** Run the checkpoint stash BEFORE any untracked write. The Archon protocol sequence should be: (1) stash pre-phase state, (2) write campaign artefacts, (3) dispatch. If the campaign file is already written before this sequence, `git add` it first so it's tracked and won't be swept up by `--include-untracked`. Recorded in the campaign file's Session history + Continuation State for phase-2 pickup.

### 2. Stat-based docker-socket health check doesn't survive socket-proxy migration

- **What was done:** `backend/app/main.py` (pre-Phase-1) had `checks["docker"] = {"ok": os.path.exists("/var/run/docker.sock")}`. Stream D removed the `/var/run/docker.sock` mount from backend+worker and routed through the proxy. /health/deep immediately went from 200 → 503 with `"docker":{"ok":false,"error":"socket missing"}`.
- **Failure mode:** The health check was verifying *mount presence*, not *daemon reachability*. After the mount was moved to the proxy, the check had nothing to stat. Worse, the check did not fail closed at Stream D's verification pass because Stream D didn't invoke /health/deep. Regression only surfaced at phase-level end-condition battery.
- **Evidence:** Initial phase-1 regression run: `health-deep=503`. Response body: `{"status":"degraded","checks":{"db":{"ok":true},"redis":{"ok":true},"docker":{"ok":false,"error":"socket missing"},"storage":{"ok":true}}}`. Fix in commit 29dba35: replaced with `client.containers.list(limit=1)` via the new `get_docker_client()` factory.
- **How to avoid:** (a) Health checks should probe the *actual dependency*, not a filesystem proxy for it. `os.path.exists(socket)` is a mount-verification, not a daemon-verification. `client.containers.list(limit=1)` probes the full path: DOCKER_HOST env → proxy → daemon. (b) Stream-level verification batteries should include any phase-level end condition that touches the same subsystem — Stream D should have run /health/deep before declaring complete. Quality rule added (see patterns doc): `auto-intake-sweep-1-no-stat-docker-sock`.

### 3. Worktree isolation returned `ok` path but commits landed on parent branch

- **What was done:** Archon invoked the `Agent` tool with `isolation: "worktree"` on both Wave 1 streams. Notification for each completed stream showed `<worktree><worktreePath>ok</worktreePath></worktree>`. My dispatch plan assumed each agent would commit to an isolated branch that I'd later merge. Instead, each agent committed directly to `clean-history` (the parent branch).
- **Failure mode:** Not a broken outcome — all 4 streams' commits landed cleanly on clean-history. BUT: the dispatch plan's assumption of per-stream branches was wrong. If a stream had failed, there would have been no isolated branch to discard; the failing work would already be on the main branch. Recovery would require `git revert` or `git reset --hard`, not just "prune the worktree."
- **Evidence:** `git log --oneline -5` immediately after Stream C notification showed `ab09e1c` on clean-history, not on a separate branch. No `git worktree list` output showed active worktrees for the streams. The `worktreePath: ok` sentinel value is not a filesystem path.
- **How to avoid:** Treat `isolation: "worktree"` as an agent-local sandbox (memory + subprocess + CWD isolation) but NOT as branch-level isolation. For true branch isolation, the delegating agent must instruct the sub-agent to `git checkout -b` before committing and the delegator must merge after. For Phase 1's shape — disjoint-file streams on the same branch — the simpler model worked. Recorded in the campaign file as a procedural note.

### 4. Rate-limit in-memory counter persists across test bursts in the same minute

- **What was done:** After verifying the 100/min default rate limit (99×200 + 11×429 on a burst), immediately tried to test the 5/min upload limit with a separate curl matrix. Every subsequent call to `/api/v1/projects` — including the project-ID lookup for the upload test — returned `{"error":"Rate limit exceeded: 100 per 1 minute"}`.
- **Failure mode:** slowapi's in-memory counter keyed by source IP persists state across test commands. A 100-request burst leaves the IP rate-limited for the remainder of the minute. Any test that needs to read from the same endpoint during the cool-down fails with a misleading "rate limit exceeded" that looks like the upload limit but is actually the default.
- **Evidence:** Upload test failed to parse project_id: `type(d).__name__ == "dict"; keys=['error']`. Direct probe: `{"error":"Rate limit exceeded: 100 per 1 minute"}`. Upload 5/min limit was verified via source-code inspection instead of live burst (decorator at firmware.py:76 confirmed).
- **How to avoid:** Separate test buckets: either (a) run rate-limit burst tests LAST in the battery, (b) wait 60s between bursts, or (c) configure test-mode that uses a separate Limiter instance (more effort than its worth for Phase 1). For Phase 2+ verification, order the battery so rate-limit tests don't starve other tests of the same endpoint.

### 5. L1 shell-fix leaves persistent script files in the running container

- **What was done:** Stream B's L1 fix for fuzzing_service.py wrote `run.sh` and `triage_gdb.sh` into `/opt/fuzzing/` inside the fuzzing container via `container.put_archive(...)`. These files persist after the fuzzing campaign ends.
- **Failure mode:** Not a security regression — the fuzzing container is ephemeral and network-isolated. But: long-running containers accumulate script files across campaigns. If a future campaign reuses a stale script file name, there's no guarantee the right version runs. Also: campaign-scoped cleanup wasn't wired.
- **Evidence:** Stream B handoff "Unresolved Risks" section: "The run.sh and triage_gdb.sh script files persist in the container filesystem after the campaign ends."
- **How to avoid:** Include a cleanup step in `stop_session` (fuzzing_service) that unlinks campaign-scoped scripts, OR use a unique per-campaign filename (e.g. `/opt/fuzzing/run-{campaign_id}.sh`) so accumulation is bounded and identifiable. Not blocking; queue as a follow-on task for a future maintenance sweep. The L1 pattern itself is still preferred — the tradeoff (persistent file for eliminated shell-injection) favours the fix.

## Crosscutting lessons

- **Verification gap between stream-level and phase-level.** Stream-level batteries can pass while a phase-level battery fails (anti-pattern 2). Phase-level end conditions should be baked into each stream's verification battery when they touch shared surfaces (the docker socket in this case).
- **State-carrying test environments.** In-memory rate-limit counters, persistent container files, accumulated session tokens — all state that's invisible at dispatch time but observable at re-run time. Batteries should be idempotent or explicitly stateful-ordered.
- **Tool semantics ≠ tool sentinel values.** `worktreePath: ok` looked like a path but was a sentinel. Don't trust unparsed tool-output fields to match your mental model; verify via `git worktree list` or equivalent structural probe.
