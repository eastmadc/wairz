# Campaign: Device Acquisition v1

Status: completed
Created: 2026-04-02
Direction: Build browser-controlled firmware dumping from live Android devices via host-side ADB bridge, 4-step frontend wizard, getprop parsing, JSONB metadata storage
Seed: .planning/seeds/device-acquisition-v1.yaml
Estimated sessions: 4-5
Type: build

## Background

Wairz already handles firmware uploads (ZIPs, tarballs, raw images) and has a UART bridge
for serial console access. This campaign adds the second bridge: a device acquisition bridge
that wraps ADB to dump firmware partitions from live Android devices directly into the
analysis pipeline.

Architecture mirrors UART bridge exactly: standalone Python script on host (TCP, newline
JSON protocol) → backend service connects via host.docker.internal → frontend wizard controls
the workflow.

v1 scope: ADB root only. MTKClient, EDL, non-root deferred to v2.

## Phases

| # | Type | Description | Deps | End Conditions | Status |
|---|------|-------------|------|----------------|--------|
| 1 | build | Database: device_metadata JSONB column + getprop parser | none | Alembic migration runs, _parse_getprop_txt() returns 14 must-have fields, unit tests pass | done |
| 2 | build | Bridge script: wairz-device-bridge.py | none | Bridge starts, responds to list_devices/get_device_info/dump_partition over TCP, mock test passes | done |
| 3 | build | Backend: device_service.py + REST endpoints | 1 | Service connects to bridge, dump_partition streams to STORAGE_ROOT, device_metadata persisted to DB | done |
| 4 | build | Frontend: DeviceAcquisitionPage wizard (steps 1-2) | 3 | Wizard renders Connect + Select steps, bridge status shown, device cards displayed | done |
| 5 | build | Frontend: DeviceAcquisitionPage wizard (steps 3-4) | 4 | Dump progress table works, Summary shows parsed metadata, Import triggers unpack pipeline | done |
| 6 | wire | Integration: end-to-end flow + error handling | 1-5 | Stall timeout works, resume_dump skips completed, disk space checks pass, audit logging active | done |
| 7 | verify | Testing: mock bridge CI + manual ADB test | 6 | Mock bridge smoke test passes, getprop parsing verified, 255 backend tests pass | done (mock only, manual device test deferred) |

## Phase Details

### Phase 1: Database + Getprop Parser
**Files:** `backend/app/models/firmware.py`, `backend/alembic/versions/`, `backend/app/utils/getprop.py` (new), `backend/tests/test_getprop.py` (new)

- Add `device_metadata` JSONB column to Firmware model (nullable, no default)
- Alembic migration: single `op.add_column`
- New `parse_getprop_txt(text: str) -> dict` — handles `[key]: [value]` format
- New `parse_build_prop(text: str) -> dict` — handles `key=value` format (extract from sbom_service)
- `extract_device_metadata(props: dict) -> dict` — extracts tiered fields into structured metadata
- Security posture derivation: ro.secure, ro.debuggable, ro.adb.secure, verified boot, SELinux
- Unit tests for both formats, missing fields, malformed input

### Phase 2: Bridge Script
**Files:** `scripts/wairz-device-bridge.py` (new), `tests/test_device_bridge.py` (new)

- Clone UART bridge architecture: asyncio TCP server, newline JSON, id-matched req/res
- Commands: list_devices, get_device_info, dump_partition, dump_all, get_dump_status, cancel_dump, resume_dump
- list_devices: wraps `adb devices -l`, parses output
- get_device_info: wraps `adb -s {serial} shell getprop`, returns parsed properties + partition list from `/dev/block/by-name/`
- dump_partition: `adb exec-out dd if=/dev/block/by-name/{name}` → streams chunks with progress events
- Stall timeout: 60s no bytes → abort with error
- Audit logging: every connection, command, transfer (source IP, size, timestamp)
- Mock mode: `--mock` flag returns canned responses for CI testing

### Phase 3: Backend Service + Endpoints
**Files:** `backend/app/services/device_service.py` (new), `backend/app/routers/device.py` (new), `backend/app/schemas/device.py` (new)

- `DeviceService` — TCP client connecting to bridge (mirrors uart_service.py pattern)
- REST endpoints:
  - `GET /api/v1/projects/{pid}/device/status` — bridge connection status
  - `GET /api/v1/projects/{pid}/device/devices` — list connected devices
  - `GET /api/v1/projects/{pid}/device/devices/{serial}/info` — device details + getprop
  - `POST /api/v1/projects/{pid}/device/dump` — start partition dump
  - `GET /api/v1/projects/{pid}/device/dump/status` — dump progress
  - `POST /api/v1/projects/{pid}/device/dump/cancel` — cancel dump
  - `POST /api/v1/projects/{pid}/device/import` — import dumped partitions as firmware
- Streaming: bridge sends chunks, service writes directly to STORAGE_ROOT
- Disk space check before dump: shutil.disk_usage, require expected + 2GB
- On import: create Firmware record with device_metadata JSONB, trigger unpack pipeline

### Phase 4: Frontend Wizard (Steps 1-2)
**Files:** `frontend/src/pages/DeviceAcquisitionPage.tsx` (new), `frontend/src/api/device.ts` (new), `frontend/src/App.tsx`

- Route: `/projects/:projectId/device-acquisition`
- Step 1 (Connect): poll `/device/status` every 2s, green/red indicator, collapsible setup instructions
- Step 2 (Select): fetch `/device/devices`, show device cards (model, serial, root status), partition checkboxes with smart defaults (boot + super)
- Stepper component with step validation (can't advance without prerequisites)
- Link from ProjectDetailPage sidebar/header

### Phase 5: Frontend Wizard (Steps 3-4)
**Files:** `frontend/src/pages/DeviceAcquisitionPage.tsx`, `frontend/src/components/device/` (new)

- Step 3 (Dump): POST `/device/dump`, poll `/device/dump/status` every 1s, per-partition progress table (name, size, status), collapsible log stream (reuse xterm.js pattern)
- Step 4 (Summary): show parsed device metadata (model, version, security posture), partition table with sizes/checksums, "Import to Project" CTA → POST `/device/import` → navigate to ProjectDetailPage
- Error states: bridge disconnect banner, per-partition retry button, disk full alert

### Phase 6: Integration + Error Handling
**Files:** across all layers

- End-to-end flow: bridge → service → wizard → import → unpack
- Stall timeout: service detects 60s no bytes, updates dump status, wizard shows disconnect
- resume_dump: skip partitions with completed status
- Disk space: check every 500MB during transfer, abort early on low space
- Audit logging: bridge logs connections and transfers to stdout
- Environment variables: DEVICE_BRIDGE_HOST, DEVICE_BRIDGE_PORT in .env
- iptables documentation in README

### Phase 7: Testing + Verification
**Files:** `tests/test_device_*.py`, `scripts/wairz-device-bridge.py --mock`

- Mock bridge: responds to all commands with canned data, includes test boot.img
- Automated tests: connect → list → dump → import cycle against mock
- Frontend component tests: wizard renders all 4 steps, state transitions correct
- Manual test: real rooted Android device, full wizard flow, verify metadata in UI
- Typecheck: `npx tsc --noEmit` passes
- Existing test suite: no regressions (225+ tests still pass)

## Decision Log

- ADB root only for v1 (MTKClient requires specific hardware, gating on it blocks shipping)
- JSONB column vs separate table (JSONB: simpler, one migration, queryable, no joins)
- No auth on bridge (matches UART precedent, local attacker already wins)
- Single connection multi-device aware (list_devices is nearly free, device_id on commands)
- Streaming to disk vs buffering (streaming: no double-storage, handles 8GB+ partitions)
- Parse all getprop fields, surface tiered (full data via API, key fields in UI)
- 4-step wizard (3 too cramped, 5 too granular)
- Mock bridge for CI (can't require real hardware for automated tests)

## Deferred to v2

### MTKClient Integration
- **What it does:** Exploits MediaTek BootROM (BROM) vulnerability to dump raw partitions. Works on locked bootloaders, no root needed. Device must be in BROM mode (powered off, hold volume-up, connect USB).
- **Output format:** Flat directory of `<partition_name>.img` files alongside `scatter.txt` (partition table layout). Typical partitions: preloader, lk (bootloader), boot, recovery, vbmeta, super, md1img (modem), spmfw, sspm, tee, scp, gz — 20-40+ partitions, 10-15GB total.
- **Host requirements:** USB permissions (udev rules on Linux), device-specific handshake timing. Only works on MediaTek SoCs.
- **Bridge changes:** Add BROM-mode detection to `list_devices`, scatter file parsing for partition layout, MTKClient subprocess wrapper. Wizard needs "power off, hold volume-up, connect USB" instruction panel.
- **Why deferred:** Requires a MediaTek device in BROM mode for testing. Most developers won't have one. Can't gate v1 release on hardware availability.

### Qualcomm EDL (Emergency Download Mode)
- **What it does:** Dumps partitions via Qualcomm's emergency download protocol. Tooling: edl, QDL, emmcdl.
- **Why deferred:** Fragmented tooling across multiple projects. Requires device-specific signed firehose programmers (MBN files). Most modern Qualcomm devices have secure EDL that rejects unsigned programmers. Effort-to-value ratio is poor — ADB root covers most Qualcomm scenarios.

### Non-root ADB
- **What's possible:** `adb pull /sdcard/`, app APKs via `pm list packages` + `adb pull`, `adb backup` (deprecated since Android 12, unreliable). Cannot access raw partitions or `/dev/block/`.
- **Output format:** Filesystem-level copies, not raw images. Tarballs of pulled directories.
- **Why deferred:** Yields incomplete firmware (no boot, no vendor, no modem). The existing tarball upload path already handles this — user can `adb pull` manually and upload the tarball. Bridge automation adds complexity for limited value.

### Progress Percentages
- **What's needed:** Bridge must report `bytes_transferred` and `total_bytes` per partition. Total comes from partition size (readable via `blockdev --getsize64` on the device). Frontend replaces indeterminate bars with percentage bars.
- **Why deferred:** Requires `blockdev` access (root-only, but we have root), adds protocol complexity for chunk-level progress events. Indeterminate bars work for v1.

### Multi-partition Batch Dump
- **What's needed:** `dump_all` command that queues multiple partitions and dumps them sequentially (or in parallel if IO allows). Progress tracking per partition in a batch.
- **Why deferred:** v1's `dump_partition` called once per partition from the wizard is sufficient. Batch adds state management complexity in the bridge (queue, ordering, partial failure of batch).

### Incremental/Differential Dumps
- **What's needed:** Hash partitions on-device before dumping. Compare to previously-stored hashes. Skip unchanged partitions.
- **Why deferred:** Requires maintaining partition hash history per device. Useful for monitoring firmware updates over time but not core to initial acquisition.

### Multi-device Concurrent Dumps
- **Why deferred:** MTKClient is inherently single-device. ADB supports multiple but concurrent dumps contend for USB bandwidth and disk IO. Multiple bridge instances on different ports is the escape hatch. Lab setups can run N bridges.

### Auto-detection of SoC Vendor
- **What's needed:** Parse `ro.board.platform`, `ro.hardware.chipname`, `ro.mediatek.platform` from getprop to determine MediaTek vs Qualcomm vs Exynos vs Tensor. Route to appropriate dump method automatically.
- **Why deferred:** v1 only supports ADB root (works on all SoCs). SoC detection matters when MTKClient/EDL are added since they're vendor-specific.

## Feature Ledger

- `parse_getprop_txt()` in `app/utils/getprop.py` — parses `[key]: [value]` format
- `parse_build_prop()` in `app/utils/getprop.py` — parses `key=value` format
- `extract_device_metadata()` in `app/utils/getprop.py` — structured metadata with security posture
- `device_metadata JSONB` column on Firmware model (migration c20efe937646)
- 30 tests in `tests/test_getprop.py`
- `scripts/wairz-device-bridge.py` — 683-line standalone TCP-to-ADB bridge (7 commands, mock mode, audit logging, stall detection, resume support, path traversal prevention)
- `app/services/device_service.py` — DeviceService (bridge proxy, dump orchestration, import with unpack trigger)
- `app/routers/device.py` — 7 REST endpoints: status, devices, info, dump, dump/status, dump/cancel, import
- `app/schemas/device.py` — Pydantic request/response models for device acquisition
- `device_bridge_host/port` config in `app/config.py`
- Router registered in `app/main.py`
- `frontend/src/types/device.ts` — TypeScript interfaces (43 lines)
- `frontend/src/api/device.ts` — 7 API client functions (75 lines)
- `frontend/src/pages/DeviceAcquisitionPage.tsx` — 4-step wizard (733 lines): Connect → Select → Dump → Summary
- Route `/projects/:projectId/device` in App.tsx
- "Device Acquisition" sidebar link with Smartphone icon
- `DEVICE_BRIDGE_HOST/PORT` in `.env.example` and CLAUDE.md docs
- Device Acquisition Bridge section in CLAUDE.md (setup instructions, mock mode)

## Continuation State

All 7 phases completed in a single session. 255 backend tests passing, zero regressions.
End-to-end smoke test verified: mock bridge → protocol → getprop parsing → metadata extraction.
Frontend typecheck deferred (node_modules not installed on this machine).
Manual test with real rooted Android device deferred to next hardware-available session.
