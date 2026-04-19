---
stream: gamma
wave: 3
date: 2026-04-19
baseline: c954039
branch: feat/stream-gamma-2026-04-19
mode: Rule-19 evidence-first maintenance sweep
---

# Stream Gamma Wave 3 — Phase 7 Maintenance Sweep Research

## Sub-item 1 — apk-scan-deep-linking close-out

**Intake body says:** Completed. **Intake YAML says:** `Status: Completed` (capitalized C; inconsistent with lowercase elsewhere).

**Live behaviour grep:**
- `frontend/src/components/findings/FindingDetail.tsx:73-75` emits deep-link URL `tab=apk-scan&apk=<apk>&finding=<rule>&line=<n>`.
- `frontend/src/pages/SecurityScanPage.tsx:40-42` reads `tab`, `apk`, `finding` from searchParams, passes `initialApk`, `initialFinding` to `ApkScanTab`.
- `frontend/src/components/apk-scan/ApkScanTab.tsx:101-106, 219-220, 386-393` handles `initialApk` via `initialApkHandled` ref + `setSelectedApk` + `setTimeout(0)` loadCachedResults.
- `frontend/src/components/apk-scan/SecurityScanResults.tsx:377-398` handles `initialFinding` via `deepLinkHandled` ref, matches by `title` or `ruleId`, expands and `scrollIntoView`.

All 4 "What Deep Linking Should Do" behaviours wired. **Close with YAML normalization. No code change.**

## Sub-item 2 — 5 security-* intakes

All 5 show `status: pending` but shipped in Phase 1:
- `security-auth-hardening.md` → parent of B.1/B.1.a/B.1.b/D.1. Shipped via `3d8aa10` + `de3f6bd` + `bac49ea` + `ab09e1c`.
- `security-auth-b1-asgi-middleware.md` → `3d8aa10`.
- `security-fuzzing-shell-injection.md` → `e443def`.
- `security-android-unpack-hardening.md` → `ab09e1c`.
- `security-docker-socket-proxy.md` → `bac49ea`.

Close as **1 bundled commit** (header edits atomic per Rule #25).

## Sub-item 3 — harness.json 4-rule adoption — BLOCKED

Proposal `.planning/proposals/citadel-protect-files-learn-exception.md` at LOW-urgency, decision gate UNRESOLVED. CLAUDE.md Rule #21 explicitly promotes Rules #23/#24/#25 as "alternative #3" — acknowledging harness-level enforcement has not landed.

Candidate rules when proposal is approved:
1. `auto-intake-sweep-1-no-stat-docker-sock`
2. `auto-intake-sweep-1-no-docker-from-env`
3. `auto-fleet-worktree-requires-branch-checkout`
4. `auto-frontend-tsc-requires-b-force`

**Decision: SKIP, document, defer.** Rule-19 canon.

## Sub-item 4 — Healthcheck `/health` → `/ready`

`docker-compose.yml:177-182` on backend service uses `/health`; switch CMD to `/ready` (added in Wave 2 commit `566637a`). `/health` route remains live for deep-surface callers. Compose-only change.

## Sub-item 5 — wairz-mcp --list-tools fix

`backend/app/mcp_server.py:662-685` `main()` has `--project-id` as required arg; `--list-tools` doesn't exist. Reproduced error: argparse rejection, NOT ModuleNotFoundError. Add `--list-tools` as `action="store_true"` that calls `_build_tool_registry()` and prints sorted manifest.

Tool count invariants:
- `create_tool_registry()` → **172** (global).
- `_build_tool_registry()` → **173** (MCP, +save_code_cleanup).

## Sub-item 6 — Orphan campaign archival

`.planning/campaigns/completed/` exists with 11 archived campaigns. Root has 12; 10 have `status: completed` and can move. Kept: `device-acquisition-v2.md` (blocked on hardware test) and `wairz-intake-sweep-2026-04-19.md` (active).

## Summary

| Sub-item | Verdict | Artefact |
|----------|---------|----------|
| 1 | Close (doc) | YAML normalize 1 file |
| 2 | Close (doc) | YAML status-bump 5 files, 1 commit |
| 3 | Skip/defer | Proposal gate unresolved |
| 4 | Code (1 line) | docker-compose.yml healthcheck |
| 5 | Code | `--list-tools` CLI flag |
| 6 | Archival | 10 `git mv` moves |

**Expected commits: 5.**
