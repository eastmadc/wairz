# Anti-patterns: Session 27 — Threat Intel Frontend + Intake Cleanup

> Extracted: 2026-04-10
> Commit: d86adad on clean-history

## Failed Patterns

### 1. Running `tsc --noEmit` locally but Docker uses `tsc -b`
- **What was done:** Ran `npx tsc --noEmit` locally which passed, but the Docker build uses `tsc -b && vite build` which has stricter checking (project references mode). The local check missed the `Record<FindingSource, ...>` errors.
- **Failure mode:** Docker build failed with TS2739 on two files that local typecheck didn't catch.
- **Evidence:** `tsc --noEmit` passed locally but `docker compose build frontend` failed.
- **How to avoid:** When expanding union types, grep for `Record<{TypeName},` across the codebase before building. Or run `npx tsc -b` locally to match Docker's exact check.

### 2. Unused import left in new component
- **What was done:** Imported `RefreshCw` from lucide-react in ThreatIntelTab but used `ShieldAlert` and `ShieldCheck` instead. The unused import survived the initial write.
- **Failure mode:** TS6133 error in Docker build.
- **Evidence:** `src/components/security/ThreatIntelTab.tsx(3,19): error TS6133: 'RefreshCw' is declared but its value is never read.`
- **How to avoid:** After writing a new component, scan the import list against actual usage. Remove any imports that were carried over from copy-paste of the template pattern.

### 3. Not force-rebuilding containers after frontend changes
- **What was done:** Ran `docker compose up -d --build` which showed "Up 10 hours" for frontend — the build context hadn't changed from Docker's perspective because the compose file wasn't modified.
- **Failure mode:** Frontend container kept serving stale assets. Had to explicitly run `docker compose build frontend` followed by `docker compose up -d frontend`.
- **Evidence:** Frontend showed "Up 10 hours" after initial `up -d --build`.
- **How to avoid:** After frontend code changes, always run `docker compose build frontend && docker compose up -d frontend` explicitly rather than relying on `--build` to detect changes.
