# Campaign: Device Acquisition v2

Status: blocked (Phase 10 — manual hardware test)
Created: 2026-04-02
Direction: Add MTKClient support, progress percentages, batch dump orchestration, EDL dump import, and reliability improvements to the device acquisition pipeline
Seed: (research fleet 2026-04-02)
Estimated sessions: 4-6
Type: build

## Background

v1 delivered ADB root dumping with a 4-step wizard (7 bridge commands, 7 REST endpoints,
733-line frontend). v2 extends coverage to MediaTek devices via MTKClient BROM exploit
and adds UX/reliability improvements identified during v1 development.

### Key Research Findings

**MTKClient** (bkerler/mtkclient, GPLv3):
- Python tool exploiting MediaTek BootROM hardware vulnerability (unfixable, ROM-burned)
- Covers 100+ chipsets: MT6261 through MT6893 (Dimensity line). Newer flagship SoCs (MT6983+) have partial/experimental support
- CLI: `mtk r <partition> <file>`, `mtk rl <dir>`, `mtk printgpt`
- Requires `pyusb`, `pycryptodome`, `pyserial` on host. GUI deps (pyside6) not needed
- Detection: USB VID:PID `0E8D:0003` (BROM) or `0E8D:2000` (preloader)
- Writes to files (not stdout) — progress tracking via file size polling
- No built-in mock mode — extend existing bridge mock
- User flow: power off → hold Vol Down → connect USB → device appears in BROM mode
- **Integration approach: subprocess wrapping** (same as ADB pattern), not Python imports

**Qualcomm EDL** — research recommends **import-only, defer live acquisition**:
- Requires device-specific signed firehose programmer (MBN file)
- Secure EDL on modern Qualcomm blocks unsigned programmers (~75-85% of devices)
- Poor automation profile vs MTKClient's generic exploit
- EDL dumps are raw partition images — already mostly handled by existing unpack pipeline
- Add classification pattern only (no new bridge, no dependencies)

**Progress Percentages**:
- Pre-dump partition size: `adb shell blockdev --getsize64 /dev/block/by-name/{partition}` (root required)
- MTKClient: `printgpt` output includes partition sizes
- Add `total_bytes`, `progress_percent`, `throughput_mbps` to protocol
- Frontend: replace indeterminate status with percentage bars + ETA

**Batch Dump**:
- v1 already has `dump_all` with sequential processing
- v2: add configurable partition presets (minimal: boot+super, full: all except userdata)
- No parallel dump (USB bandwidth contention; MTKClient is inherently sequential)

## Architecture Decisions

### Bridge Device Mode Abstraction

Extend `list_devices` to return devices with a `mode` field:
```json
{"serial": "FA99123456", "mode": "adb", "model": "Pixel 6", ...}
{"serial": "MTK_0E8D0003", "mode": "brom", "chipset": "MT6765", ...}
```

ADB and BROM are mutually exclusive — a device in BROM mode won't appear in `adb devices`.
The bridge detects both and routes commands to the appropriate backend.

### MTKClient as Optional Dependency

The bridge should work without MTKClient installed (v1 ADB-only behavior).
If `mtk` is not on PATH, BROM devices are listed with `"available": false` and a
message directing the user to install mtkclient.

### Scatter File vs printgpt

Use `mtk printgpt` for partition enumeration (not scatter files). Scatter is an SP Flash
Tool concept; printgpt reads the device's GPT directly and outputs partition names/sizes.
If a user has a scatter file, they can import the dump manually via the existing tarball upload.

### EDL Import Classification

Add a `qualcomm_edl_dump` classification to the firmware classifier. Trigger: tarball/directory
containing 3+ of: `aboot.img`, `rpm.img`, `tz.img`, `modem.img`, `boot.img`, `hyp.img`.
Route through the existing partition-image unpack path.

## Phases

| # | Type | Description | Deps | End Conditions | Status |
|---|------|-------------|------|----------------|--------|
| 1 | build | Progress: partition size pre-query + percent in protocol | none | `dump_partition` response includes `total_bytes` and `progress_percent`; frontend shows percentage bars with throughput | done |
| 2 | build | MTKClient device detection in bridge | none | `list_devices` returns BROM/preloader devices with mode field; detects `0E8D:0003`/`0E8D:2000` via lsusb; graceful when mtkclient not installed | done |
| 3 | build | MTKClient partition enumeration | 2 | `get_device_info` for BROM devices returns partition list from `mtk printgpt`; includes partition sizes | done |
| 4 | build | MTKClient partition dump | 2,3 | `dump_partition` for BROM devices invokes `mtk r`; progress tracked via file size polling; stall timeout works | done |
| 5 | build | Frontend: mode-aware wizard | 1,2 | Device cards show mode badge (ADB/BROM); BROM mode shows setup instructions (Vol Down + USB); partition checkboxes show sizes | done |
| 6 | build | Batch dump presets + UX | 1 | Preset buttons in wizard: "Minimal (boot+super)", "Standard (boot+super+vendor+system)", "Full (all except userdata)"; one-click dump start | done |
| 7 | build | EDL dump import classification | none | `classify_firmware()` returns `partition_dump_tar` for tarballs with partition images; routed through Android unpack pipeline | done |
| 8 | build | Mock mode extension for MTKClient | 4 | `--mock` flag simulates BROM device detection + partition dump; CI-testable without hardware | done |
| 9 | wire | Error handling + retry | 4 | Per-partition retry (up to 2 attempts with backoff); USB disconnect recovery; udev permission error detection with user-friendly message | done |
| 10 | verify | End-to-end testing | all | Mock bridge CI passes; manual test with real MediaTek device (if available); ADB path unchanged (regression-free) | ready for manual test |

## Phase Details

### Phase 1: Progress Percentages

**Files:** `scripts/wairz-device-bridge.py`, `backend/app/schemas/device.py`, `frontend/src/pages/DeviceAcquisitionPage.tsx`, `frontend/src/types/device.ts`

**Bridge changes:**
- Before dumping, query partition size:
  - ADB: `adb -s {serial} shell blockdev --getsize64 /dev/block/by-name/{partition}`
  - MTKClient: parse from `printgpt` output (cached after first call)
- Add fields to progress events:
  ```json
  {"event": "progress", "partition": "boot", "bytes_written": 8388608, "total_bytes": 67108864, "progress_percent": 12.5, "throughput_mbps": 42.3}
  ```
- Add `total_bytes` to partition result

**Schema changes:**
- `DumpPartitionStatus`: add `total_bytes: int | None`, `progress_percent: float | None`, `throughput_mbps: float | None`

**Frontend changes:**
- Replace bytes-only display with progress bar + percentage
- Show throughput (e.g., "42.3 MB/s") and ETA
- Partition selection shows sizes (e.g., "boot (64 MB)")

### Phase 2: MTKClient Device Detection

**Files:** `scripts/wairz-device-bridge.py`

- Add `_detect_mtk_devices()` method that parses `lsusb` for VID `0E8D`
- Check if `mtk` binary is on PATH (via `shutil.which("mtk")`)
- Extend `list_devices()` to merge ADB and MTK device lists:
  ```python
  devices = await self._detect_adb_devices()
  devices += await self._detect_mtk_devices()
  return devices
  ```
- MTK device format:
  ```json
  {
    "serial": "MTK_BROM_0",
    "mode": "brom",
    "chipset": null,
    "available": true,
    "model": "MediaTek BROM",
    "state": "brom"
  }
  ```
- If mtkclient not installed: `"available": false, "error": "mtkclient not installed"`

### Phase 3: MTKClient Partition Enumeration

**Files:** `scripts/wairz-device-bridge.py`

- Implement `_mtk_get_device_info()`:
  ```python
  proc = await asyncio.create_subprocess_exec(
      "mtk", "printgpt",
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
  )
  ```
- Parse `printgpt` output to extract partition names, sizes, offsets
- Cache parsed GPT for the session (device won't change while in BROM mode)
- Return same response format as ADB `get_device_info` but with partition sizes

### Phase 4: MTKClient Partition Dump

**Files:** `scripts/wairz-device-bridge.py`

- Implement `_mtk_dump_partition()`:
  ```python
  output_path = os.path.join(output_dir, f"{partition}.img")
  proc = await asyncio.create_subprocess_exec(
      "mtk", "r", partition, output_path,
      stdout=asyncio.subprocess.PIPE,
      stderr=asyncio.subprocess.PIPE,
  )
  ```
- Progress via file size polling (check every 500ms):
  ```python
  while proc.returncode is None:
      try:
          size = os.path.getsize(output_path)
          emit_progress(size, total_bytes)
      except FileNotFoundError:
          pass
      await asyncio.sleep(0.5)
      await proc.wait()  # or poll
  ```
- Timeout: 30 minutes per partition (same as ADB)
- Handle MTKClient-specific errors: "Device not found", "DA handshake failed", "Permission denied"

### Phase 5: Frontend Mode-Aware Wizard

**Files:** `frontend/src/pages/DeviceAcquisitionPage.tsx`, `frontend/src/types/device.ts`

- Device cards show mode badge: green "ADB" or orange "BROM"
- BROM device card shows chipset if available
- Step 0 (Connect): add "MediaTek BROM Mode" section with instructions:
  - "1. Power off the device"
  - "2. Hold Volume Down"
  - "3. Connect USB cable"
  - "4. Release when device is detected"
- BROM devices don't have getprop — skip metadata display, show raw partition table
- Partition sizes shown next to checkboxes (from printgpt)

### Phase 6: Batch Dump Presets

**Files:** `frontend/src/pages/DeviceAcquisitionPage.tsx`

- Preset buttons above partition checkboxes:
  - **Minimal**: boot + super (or system on non-dynamic-partition devices)
  - **Standard**: boot + super + vendor + system + product
  - **Full**: all partitions except userdata
- One-click "Dump Selected" button
- Presets are frontend-only (no backend changes needed)

### Phase 7: EDL Dump Import

**Files:** `backend/app/workers/unpack_common.py`

- Add `is_qualcomm_edl_dump()` classifier:
  ```python
  QUALCOMM_MARKERS = {"aboot.img", "rpm.img", "tz.img", "hyp.img", "modem.img"}
  # If 3+ markers present in tarball/directory → qualcomm_edl_dump
  ```
- Route through existing partition-image unpack path (shared with Android OTA)
- Parse partition names for content-based identification (reuse `_identify_partition_by_content()`)

### Phase 8: Mock Mode Extension

**Files:** `scripts/wairz-device-bridge.py`

- Extend mock data with MTK device:
  ```python
  MOCK_MTK_DEVICE = {
      "serial": "MTK_MOCK001",
      "mode": "brom",
      "chipset": "MT6765",
      "model": "Mock MediaTek (BROM)",
      "state": "brom",
  }
  MOCK_MTK_PARTITIONS = [
      {"name": "boot", "size": 67108864},
      {"name": "recovery", "size": 67108864},
      {"name": "super", "size": 8589934592},
      {"name": "vbmeta", "size": 65536},
      {"name": "md1img", "size": 134217728},
  ]
  ```
- Mock `printgpt` response with realistic partition layout
- Mock dump: write sized zeros with progress events

### Phase 9: Error Handling + Retry

**Files:** `scripts/wairz-device-bridge.py`, `backend/app/services/device_service.py`

**Bridge:**
- Per-partition retry: up to 2 retries with 5s backoff
- USB disconnect detection: check if device still present before retry
- Udev permission error: detect "Permission denied" / "Access denied" from mtk subprocess stderr, return actionable error message

**Service:**
- Track retry count in partition status
- Add `retries` field to `DumpPartitionStatus`

### Phase 10: End-to-End Verification

- Mock bridge test: full wizard flow with MTK mock device
- ADB regression: existing mock tests still pass
- Manual test plan (when hardware available):
  1. Connect MediaTek device in BROM mode
  2. Verify device appears in wizard with BROM badge
  3. View partition table with sizes
  4. Dump boot + super partitions
  5. Verify progress percentages display correctly
  6. Import dump → verify unpack pipeline processes it
  7. Check device metadata in project detail

## Rollout Strategy

### Session 1: Progress + Detection (Phases 1-2)
- Progress percentages (bridge + frontend)
- MTKClient device detection (lsusb polling)
- Milestone: progress bars working in ADB dumps; BROM devices visible

### Session 2: MTKClient Core (Phases 3-4)
- Partition enumeration via printgpt
- Partition dump via `mtk r`
- Milestone: can dump a partition from a MediaTek device

### Session 3: UX + Import (Phases 5-7)
- Mode-aware wizard UI
- Batch presets
- EDL dump import classification
- Milestone: full wizard flow for both ADB and BROM

### Session 4: Reliability + Testing (Phases 8-10)
- Extended mock mode
- Error handling + retry
- End-to-end verification
- Milestone: CI-testable, production-ready

## Decision Log

- Subprocess wrapping for MTKClient (not Python imports) — avoids dependency conflicts, matches ADB pattern
- EDL import-only (defer live acquisition) — poor automation profile, 75-85% of Qualcomm devices block unsigned firehose
- No parallel dump — USB bandwidth contention for both ADB and MTKClient; sequential is safer
- lsusb for detection (not pyusb) — simpler, no new host dependency, parsed output is sufficient
- printgpt over scatter files — scatter is SP Flash Tool concept; printgpt reads GPT directly from device
- GPLv3 license note: MTKClient is GPLv3, but Wairz invokes it as a subprocess (not linking), so no license conflict with Wairz's own license

## Deferred to v3

### SoC Auto-detection
Parse getprop fields (`ro.board.platform`, `ro.mediatek.platform`) to auto-route to correct dump method. Only matters when both ADB and MTKClient are available.

### Firmware Editor (Write-back)
Push modified partitions back to device. Requires signature validation bypass, anti-rollback detection. High complexity, high risk.

### Incremental Dumps
Hash partitions on-device before dumping; skip unchanged. Requires maintaining partition hash history per device.

### Samsung Odin Protocol
Samsung devices use Odin (Download Mode) instead of standard Qualcomm EDL. Separate protocol, separate tooling (Heimdall). Niche but high-value for Samsung-specific firmware analysis.

## Feature Ledger

- `_make_progress_event()` in bridge — builds progress events with total_bytes, progress_percent, throughput_mbps
- `_get_partition_sizes()` in bridge — batch blockdev --getsize64 query for all partitions
- `_get_partition_size()` in bridge — single partition size query (used pre-dump)
- `MOCK_PARTITION_SIZES` in bridge — realistic mock partition sizes for CI testing
- `partition_sizes` field in bridge `get_device_info` response — partition names with sizes
- `total_bytes`, `progress_percent`, `throughput_mbps` in progress events and dump status
- `PartitionInfo` type in schemas/device.py — name + size for partition enumeration
- `total_bytes`, `progress_percent`, `throughput_mbps` in `DumpPartitionStatus` schema
- `partition_sizes` field passed through in device_service.py `get_device_info()`
- Frontend progress bars in DeviceAcquisitionPage Step 2 (dump progress table)
- Frontend partition sizes shown next to checkboxes in Step 1 (device selection)
- `PartitionInfo` TypeScript type + `partition_sizes` on `DeviceDetail`
- `total_bytes`, `progress_percent`, `throughput_mbps` on `PartitionStatus` TypeScript type
- `_detect_mtk_devices()` in bridge — lsusb-based MediaTek BROM/preloader detection
- `_check_mtk_available()` in bridge — checks if `mtk` CLI is on PATH
- `MTK_BROM_VID_PID`, `MTK_PRELOADER_VID_PID` constants — USB identifiers
- `MOCK_MTK_DEVICE`, `MOCK_MTK_PARTITIONS` — mock data for MTK CI testing
- `mode` field on all device entries — "adb", "brom", or "preloader"
- `available`/`error` fields on MTK devices — graceful when mtkclient not installed

## Continuation State

Phases 1-9 completed in session 3. Phase 10 (E2E verification) ready for manual hardware test.
Mock mode verified: 2 devices (ADB + BROM), partition sizes, chipset detection all working.
printgpt parser handles human-readable sizes, hex LBAs, noisy output, and chipset ID lines.
Retry logic: up to 2 retries with 5s/10s backoff, no retry for permission errors.
User has real MediaTek hardware available for Phase 10 testing.

<!-- session-end: 2026-04-02T23:01:28.550Z -->

<!-- session-end: 2026-04-02T23:01:28.728Z -->

<!-- session-end: 2026-04-03T00:08:20.467Z -->

<!-- session-end: 2026-04-03T00:08:58.684Z -->
