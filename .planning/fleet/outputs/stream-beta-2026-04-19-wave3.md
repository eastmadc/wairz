# Stream Beta Wave 3 — Handoff

**Branch:** `feat/stream-beta-2026-04-19`
**Baseline:** `c954039` on `clean-history`
**Worktree:** `/home/dustin/code/wairz/.worktrees/stream-beta` (created via `git worktree add` after the shared checkout was twice stomped by parallel streams — see Rule #23 incident below).

## Commits

```
d231d3c feat: type device BROM surface end-to-end (backend + frontend)   (S3)
72cb20d feat(frontend): ProjectRouteGuard component + route wrap         (S2)
b68e090 feat(frontend): store project-id guards for async actions        (S1)
```

Per Rule #25: 3 sub-tasks → 3 separate commits. Each sub-task is independently revertable via `git revert <sha>` with no cross-commit entanglement.

## Rule-17 canary output

```
$ echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts
$ (cd frontend && npx tsc -b --force)
src/__canary.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.
CANARY_EXIT=2
OK: canary FAILED as expected — tsc is truly checking
```

Canary was re-run after creating the isolated worktree to confirm `npx tsc -b --force` still genuinely descends into `tsconfig.app.json` + `tsconfig.node.json` references. Passed both times.

## Research findings (Rule #19)

1. **Intake S1 claim of 2-arg `loadRootDirectory(projectId, firmwareId)` was wrong.** Actual signature is 1-arg; firmwareId is read from `useProjectStore.getState().selectedFirmwareId`. Widening would have broken 12+ call sites. S1 kept all public signatures unchanged and added `currentProjectId` as a store-level sentinel instead.
2. **Intake S3 premise was partially false.** The backend Pydantic schemas SILENTLY STRIPPED the 4 BROM-specific fields (`mode`, `available`, `error`, `chipset`) via Pydantic v2's default `extra="ignore"`. Verified in wairz-backend-1: `DeviceInfo(**{'mode':'brom',...}).model_dump()` returned only the 5 declared fields. Frontend `(dev as any).mode` evaluated to `undefined` at runtime — typing the frontend alone would have kept the BROM UI broken. S3 widened both backend and frontend schemas, and plumbed `chipset` through the service+router where it had been dropped at `device_service.py:76-82`.
3. **Intake S3 `DeviceMode` union would have been Rule-19 fabrication.** Intake proposed `'adb' | 'brom' | 'edl' | 'fastboot' | 'unknown'`. Grep of the bridge code showed EXACTLY these values: `adb`, `brom`, `preloader`. Applied union is `'adb' | 'brom' | 'preloader'` — no speculative values. Same for `soc`/`bootloader_version`/`security_patch`/`partitions: PartitionInfo[]` — these aren't top-level bridge fields, they come via `getprop` dict keys.
4. **Nothing from S1/S2/S3 was already solved.** `grep currentProjectId frontend/src/stores/` = 0; `ProjectRouteGuard.tsx` did not exist; `grep 'as any' DeviceAcquisitionPage.tsx` = 5. All three were live work.

## Verification evidence

### Stream-local

```
$ cd frontend && npx tsc -b --force && echo $?
0

$ grep -rn 'as any' frontend/src/pages/DeviceAcquisitionPage.tsx
(no hits)

$ grep -c currentProjectId frontend/src/stores/{explorerStore,projectStore,vulnerabilityStore}.ts
frontend/src/stores/explorerStore.ts:23
frontend/src/stores/projectStore.ts:7
frontend/src/stores/vulnerabilityStore.ts:14

$ ls frontend/src/components/ProjectRouteGuard.tsx
frontend/src/components/ProjectRouteGuard.tsx

$ grep -c ProjectRouteGuard frontend/src/App.tsx
14
# = 1 import + 1 comment + 12 per-project route wraps (all :projectId routes covered)
```

### Pydantic round-trip (in-container, Rule #20)

```
$ docker exec -i wairz-backend-1 /app/.venv/bin/python <NEW-SCHEMA-DEF>
adb: {..., 'mode': 'adb', 'available': None, 'error': None}
brom: {..., 'mode': 'brom', 'available': True, 'error': None}
detail with chipset: {..., 'chipset': 'MT6765'}
```

All four previously-stripped fields now preserved.

### Global health (unchanged by stream)

```
/health             200
/ready              200
/metrics            200
/api/v1/projects    401 (correctly unauth)
/health/deep        all_ok= True
DPCS10 blobs        260
alembic current     123cc2c5463a (head)
tool registry count 172
```

All pinned global checks pass. Stream is frontend + device-schema additive; no regression surface expected on any other router.

### Acceptance for S1 (manual — no Playwright in tree)

Manual repro recipe for next human reviewer:

1. `docker compose up -d --build frontend` (or ensure Vite dev is picking up the bind-mount).
2. In the UI, open two projects A and B that each have firmware (e.g. two different uploads).
3. In URL bar: `/projects/A/explore`. Wait for tree to load.
4. Paste `/projects/B/explore` in URL bar. Hit enter before A's tree fully re-renders.
5. Confirm: tree shows B's rootfs, NOT a stale A-rootfs node. SBOM vuln list on `/sbom` pages similarly resets.
6. Confirm: console has no late-race warnings / uncaught errors from the store guards dropping responses.

Pre-S1: stale A-tree sometimes displayed in B. Post-S1: guarded at two levels (per-action `currentProjectId` check + ProjectRouteGuard cleanup effect).

## Open threads (for Wave 4+ or future sessions)

1. **Discriminated union per acquisition mode** — once bridge adds EDL/fastboot/Qualcomm modes, the flat `DeviceInfo` with `mode?: DeviceMode` should split into `AdbDeviceInfo | BromDeviceInfo | PreloaderDeviceInfo` with `mode` as the discriminator literal. Not urgent today — bridge only emits three modes.
2. **Backend schema debt in `list_devices` router** — with the new optional fields, the existing `DeviceInfo(**d)` construction at `routers/device.py:51` now passes the BROM fields through correctly. No runtime change vs. old behavior for ADB devices. If BROM-specific fields multiply, the per-mode union (thread #1) is the cleaner shape.
3. **Playwright E2E for the A↔B rapid-switch scenario** — S1 acceptance today is manual. A 15-line Playwright test (`page.goto('/projects/A/explore'); await page.goto('/projects/B/explore'); await expect(tree).not.toHaveText(ATreeMarker)`) would lock this in. No tests exist under `frontend/src/pages/__tests__/` yet — would be the first.
4. **Rule-8 backend rebuild gate for S3** — the backend Pydantic class change means the running backend container still has the old schema until `docker compose up -d --build backend worker`. Frontend types are decoupled and ship immediately. Flagging for the orchestrator's merge gate.

## Rule #23 incident log

During Wave 3 execution, the shared `/home/dustin/code/wairz` on-disk checkout was twice switched between parallel branches:

- First: I was on `feat/stream-beta-2026-04-19`, edited three stores in memory, attempted `git commit`, received an error showing HEAD had become `feat/stream-alpha-2026-04-19`. A follow-up `git checkout feat/stream-beta-2026-04-19` found the three store files reverted to baseline (zero `currentProjectId` references). My edits were nullified.
- Second: After redoing the edits, the HEAD flipped to `feat/stream-gamma-2026-04-19`. Same loss.

Mitigation applied: `git worktree add .worktrees/stream-beta feat/stream-beta-2026-04-19` with `frontend/node_modules` symlinked from the main checkout to skip a 2GB reinstall. The `.worktrees/` path keeps the worktree inside PROJECT_ROOT so the `protect-files.js` hook still validates write targets. All three commits landed cleanly from the isolated worktree with no further stomps.

This is exactly the Rule #23 failure mode the rule warns about. The `worktreePath: "ok"` sentinel in the harness does NOT in fact create a separate on-disk worktree — confirmed by `git worktree list` showing only the shared entry until I created my own. Stream orchestrators should prefer `git worktree add` per-stream or, failing that, strict single-stream-at-a-time sequencing for any work requiring multi-file edits.

## Commit list (`git log --oneline feat/stream-beta-2026-04-19 ^clean-history`)

```
d231d3c feat: type device BROM surface end-to-end (backend + frontend)
72cb20d feat(frontend): ProjectRouteGuard component + route wrap
b68e090 feat(frontend): store project-id guards for async actions
```

Clean, linear, 3 commits, one per sub-task. Per-task revert works independently.

DO NOT merge into clean-history from this stream — orchestrator merges all three branches sequentially at the end.
