# Downstream Consumer Audit

> Scout 2 of 4
> Date: 2026-04-17

## Summary

Across the backend, roughly 20 distinct consumers dereference `Firmware.extracted_path`. For Android OTAs specifically, `extracted_path` is set to the filesystem root inside `extraction_dir/rootfs/` (set by `find_filesystem_root` — see `backend/app/workers/unpack.py:126`, `backend/app/workers/unpack_common.py:315`). Raw partition images (`preloader_*.bin`, `lk.img`, `md1dsp.img`, `tee.img`, `scp.img`, `sspm.img`, `cam_vpu*.img`, `dtbo.img`, `vbmeta*.img`, `boot.img`, `vendor_boot.img`) remain in `extraction_dir` or a zip-basename sub-directory and are invisible to every consumer that walks `extracted_path`.

Breakdown:

- **2 consumers already solved the sibling-partition problem** (SbomService, security_audit_service via router-level fan-out).
- **~13 consumers walk `extracted_path` as a single opaque root** and are affected.
- **~5 consumers are DB-only or per-file scoped** and are unaffected.
- **2 consumers have deeper gaps** (SELinuxService scope, virustotal 200-file cap, known_good 100-file cap) independent of the partition-image issue.

The detector (`hardware_firmware`) does ship a `_pick_detection_root` helper today at `backend/app/workers/unpack.py:52`, but (a) it's only invoked by the post-unpack detection callback, (b) its heuristic misses the DPCS10 layout because `rootfs/` is the parent name and `rootfs/*_erofs/` partitions don't live as top-level sibling dirs, and (c) no other consumer imports or uses it.

## Affected Consumers (blind to sibling partition dirs)

### hardware_firmware.detector.detect_hardware_firmware
- **File:** `backend/app/services/hardware_firmware/detector.py:192-202`
- **Walk root:** single `extracted_path` argument passed in. The pre-walker `_pick_detection_root` lives in `backend/app/workers/unpack.py:52-68` and only runs at the fire-and-forget post-unpack call.
- **Scope gap:** Called with the caller's `detection_root`. For DPCS10, `Firmware.extracted_path = extraction_dir/rootfs/` — `_pick_detection_root(rootfs/)` sees siblings like `DPCS10_260414-1134/`, `partitions/`, `boot/` inside `extraction_dir/` but the `partition_like` check requires at least 2 entries starting with `partition_` and `_ANDROID_PARTITION_SIBLINGS` only matches if rootfs/'s PARENT (extraction_dir) contains vendor/system/odm/product siblings. On DPCS10 they don't — they live as subdirs of `rootfs/`. So `detection_root == rootfs/` and the 21 partition images in `DPCS10_260414-1134/` are missed.
- **User-visible impact:** Confirmed in intake — zero preloader/lk/md1dsp/tee/scp/sspm/cam_vpu hits. The Phase 3 MTK parsers are unreachable.
- **Fix difficulty:** moderate. Need to either widen `_pick_detection_root` to recognize "zip-basename sibling dir" patterns, or make the detector walk the extraction root AND the fs root. Option C in the intake aligns with this.

### yara_service.scan_firmware
- **File:** `backend/app/services/yara_service.py:111-188`
- **Walk root:** `os.walk(scan_root)` where `scan_root = os.path.realpath(extracted_path)`.
- **Scope gap:** Only sees `rootfs/`. The 21 partition images are skipped — not scanned by any YARA rule (crypto patterns, malware signatures, firmware header magic).
- **User-visible impact:** "Scan firmware with YARA" misses preloader / LK / TEE / modem images. Anything MediaTek-specific in `.yar` rules never matches.
- **Fix difficulty:** trivial — add a sibling-iteration loop like SbomService uses, or accept a list of roots.

### security_audit_service (all `_scan_*` functions)
- **File:** `backend/app/services/security_audit_service.py:938-976` (orchestrator), individual scanners at `:103-230,226-331,...`. Each walker uses `os.walk(root)` with the passed-in root.
- **Walk root:** `extracted_root` parameter — in all production call sites this is `firmware.extracted_path` (see `backend/app/routers/security_audit.py:125,592,822,993`). The router at `backend/app/routers/security_audit.py:237-248` DOES try to broaden scan roots via `firmware.extraction_dir`, but only for the attack-surface endpoint, and only by scanning `extraction_dir`'s top level — partition IMG files at the root aren't walked recursively.
- **Scope gap:** The core scans (credentials, shadow, crypto material, setuid, init services, world-writable, TruffleHog, NoseyParker, shellcheck, bandit) all run against `rootfs/` only. Hardcoded credentials inside `preloader_*.bin` strings, or key material in `tee.img`, are never inspected.
- **User-visible impact:** Security audit "confidence" is reported against ~rootfs content only.
- **Fix difficulty:** moderate. Same shape as SbomService — discover sibling roots, loop with `_scan_*` per root.

### clamav_service.scan_directory
- **File:** `backend/app/services/clamav_service.py:89-116`
- **Walk root:** `os.walk(dir_path)` where `dir_path` is passed in. Called with `firmware.extracted_path` at `backend/app/routers/security_audit.py:592`.
- **Scope gap:** Only rootfs. Hostile content inside partition images not inspected by ClamAV.
- **User-visible impact:** clamscan "clean" result is misleading for Android uploads.
- **Fix difficulty:** trivial — accept list or allow caller fan-out.

### virustotal_service.scan_firmware
- **File:** `backend/app/services/virustotal_service.py:170-203`
- **Walk root:** `os.walk(extracted_root)` with `max_files=50` (from the router) or 200 in the service default.
- **Scope gap:** Only rootfs. In addition, capped at 50-200 files, so even within rootfs the coverage is thin.
- **User-visible impact:** Hashes uploaded to VT come entirely from rootfs binaries.
- **Fix difficulty:** trivial for scope, moderate to redesign file prioritization (already a deeper issue — see "Deeper Bugs" below).

### abusech_service (known_good_scan also)
- **File:** `backend/app/services/abusech_service.py` — same shape as VT.
- **Scope gap:** Same — hash-based lookups only across rootfs binaries.
- **Fix difficulty:** trivial.

### update_mechanism_service.detect_update_mechanisms
- **File:** `backend/app/services/update_mechanism_service.py:690`
- **Walk root:** `real_root = os.path.realpath(extracted_root)`, passed to detectors like `_detect_swupdate`, `_detect_android_ota`.
- **Scope gap:** Android OTA detector can't see the raw OTA metadata files that live in `DPCS10_260414-1134/` (e.g., `payload_metadata.bin`, `metadata`). Some OTA-flavor detectors pattern-match on filenames that never appear under `rootfs/`.
- **User-visible impact:** Android OTA update mechanism may classify incorrectly or miss "A/B OTA with payload.bin" signatures.
- **Fix difficulty:** moderate.

### assessment_service.AssessmentService
- **File:** `backend/app/services/assessment_service.py:35-41` (constructor takes a single `extracted_path`), then `:209-215` and `:301-307` and `:382-454` and `:519-605` all use `self.extracted_path` as the single walk root.
- **Scope gap:** The full security assessment (all 7 phases including credential_crypto, config_filesystem, binary_protections, malware_detection, android, compliance) only sees rootfs. `_scan_android_apps` specifically hardcodes `os.path.join(self.extracted_path, "system", "app")` and `"system", "priv-app"` — misses APKs in `product/priv-app`, `vendor/priv-app`, `system_ext/priv-app` that live under sibling partitions.
- **User-visible impact:** The main "run security assessment" action reports an incomplete picture on any multi-partition Android OTA.
- **Fix difficulty:** architectural — AssessmentService is deep enough that retrofitting a multi-root loop requires touching every phase method.

### component_map_service.ComponentMapService
- **File:** `backend/app/services/component_map_service.py:93-111`, walks `os.walk(self.extracted_root)` at line 133.
- **Scope gap:** Only rootfs. Dependency-graph nodes don't include binaries/libraries that live only in sibling partition images. On extracted Android (where rootfs/ DOES contain vendor/product/odm as subdirs), this is mostly fine — BUT on raw, un-extracted partition images (preloader/lk/tee), the graph is incomplete.
- **Fix difficulty:** trivial.

### selinux_service.SELinuxService
- **File:** `backend/app/services/selinux_service.py:41-42`, uses `os.walk(abs_dir)` at lines 204, 254, hardcoded to `abs_dir = os.path.join(self.extracted_root, "system", "etc", "selinux")` etc.
- **Scope gap:** Only looks inside rootfs for SELinux policy. On DPCS10-style layouts where `vendor/etc/selinux/` contains the vendor policy, the scan hits — BUT if vendor is a sibling partition (not mounted in rootfs), it's missed.
- **User-visible impact:** Partial policy parsing.
- **Fix difficulty:** trivial — add sibling fan-out.

### File service (UI tree + MCP list_directory/read_file/search_files/find_files_by_type)
- **File:** `backend/app/services/file_service.py:130-190` (constructor), `:337-391` (list_directory), `:513-540` (search_files). Tool wrappers at `backend/app/ai/tools/filesystem.py:108-194`.
- **Walk root:** `extracted_root=firmware.extracted_path` with optional `extraction_dir=firmware.extraction_dir`. When `extraction_dir` is set, the service builds a virtual `/` showing `rootfs/` + sibling extracted partition dirs (`*-root`, `*-root-N`).
- **Scope gap:** The virtual root logic filters only names matching `_ROOT_DIR_PATTERN` (matches `*-root`, `*-root-0..N`). It does NOT show `DPCS10_260414-1134/` as a virtual top-level because that directory name doesn't match the `*-root` pattern. User can't browse to `preloader_*.bin` through the UI.
- **User-visible impact:** The partition-image files at the root of `extraction_dir/DPCS10_260414-1134/` are invisible to the "Files" page in the UI, `search_files`, `find_files_by_type`, etc. The MCP filesystem tools are equally blind.
- **Fix difficulty:** moderate — relax the virtual-root filter to include any non-rootfs directory with >=1 file OR add explicit "partitions/" display.

### attack_surface_service
- **File:** called as `for dirpath, _dirs, files in safe_walk(scan_root)` — see `backend/app/services/attack_surface_service.py:444`. `scan_root` derives from the `extracted_root` argument (line 416, 430).
- **Scope gap:** Only rootfs. Attack-surface analysis (open-ports binaries, setuid, socket listeners from strings) never inspects partition images.
- **Fix difficulty:** trivial.

### sbom (syft) via router.attack_surface for bytecode scan
- Uses `firmware.extracted_path` (line 102 in `backend/app/routers/attack_surface.py`).
- Same single-path constraint.

### MCP strings tools — extract_strings, search_strings, find_hardcoded_ips, find_crypto_material
- **File:** `backend/app/ai/tools/strings.py:188,239,741,...`
- **Walk root:** via `context.extracted_path` or `context.resolve_path(input_path)`. When the user specifies a path like `"/"`, it resolves to rootfs. When they specify `/rootfs/`, same thing.
- **Scope gap:** No way via these tools for the user to reach `preloader_*.bin` because `extracted_path` bounds the sandbox. `context.extracted_path` IS rootfs.
- **User-visible impact:** MCP Claude can't strings-search the bootloader or DSP images. Critical for reverse-engineering work.
- **Fix difficulty:** moderate — requires widening the sandbox or exposing an additional virtual partition root.

### MCP binary tools — list_functions, disassemble_function, decompile_function, etc.
- **File:** `backend/app/ai/tools/binary.py:784,1415`, various others.
- **Walk root:** via `context.resolve_path` + `safe_walk`. Same sandbox as strings.
- **Scope gap:** Same — can't Ghidra-analyze `preloader_*.bin` or `tee.img` because they're outside the sandbox root.
- **Fix difficulty:** same as strings.

### MCP security tools (security.py)
- **File:** `backend/app/ai/tools/security.py:972,1079,1547,...` — 15+ tools use `context.extracted_path` as a single walk root.
- **Scope gap:** Every security MCP tool (`check_kernel_hardening`, `analyze_certificate`, `find_crypto_material`, `scan_with_yara`, ClamAV, etc.) is rootfs-only.
- **Fix difficulty:** architectural if fixed at `ToolContext`, trivial per-tool.

## Unaffected Consumers

### SbomService (multi-partition aware)
- **File:** `backend/app/services/sbom_service.py:401-441,610-630,1226-1236`
- **Why unaffected:** `_get_all_scan_roots()` explicitly enumerates sibling partitions when `parent` is named `rootfs`, `partitions`, or `images`. It swaps `self.extracted_root` for each sibling pass (`:459-477`).
- **Caveat:** Only enumerates DIRECTORY siblings. Partition IMAGE files (`preloader_*.bin`, `lk.img`) that live as FILES in the parent, not directories, are still missed. Parses ELF/package-manifest content only — raw partition images aren't parsed by Syft anyway.
- **Partial affected:** If a partition's parent is named something other than `rootfs`/`partitions`/`images` (e.g., `DPCS10_260414-1134`), the heuristic at `:416` fails. This is a latent bug.

### GrypeService
- **File:** `backend/app/services/grype_service.py`
- **Why unaffected:** Pure DB-only. Reads `SbomComponent` rows (whatever SbomService wrote), runs Grype, writes `SbomVulnerability` rows. No filesystem walk.

### VulnerabilityService / AnalysisService (binary protections)
- **File:** `backend/app/services/analysis_service.py` (single-binary ELF inspection)
- **Why unaffected:** Operates on single binary paths provided by the caller. The caller is responsible for the path.

### FindingService, export_service (DB ops only)
- **Why unaffected:** Read/write findings from the DB. Export bundles `fw.extracted_path` as a tarball (`backend/app/services/export_service.py:393`) — which IS affected when building the archive, but doesn't perform scanning.

### BytecodeAnalysisService, MobSFScanService (per-APK)
- Called with an explicit APK path. Invariant: caller (apk_scan router) must have located the APK correctly. The APK lookup in `backend/app/routers/apk_scan.py:166-184` uses `firmware.extracted_path` as the scope, so APKs outside rootfs (in sibling partitions) can't be found — but that's a router-level bug, not a service-level one.

### androguard_service, mobsf_runner, wairz_runner
- Per-APK APIs. Unaffected by walk-root issue.

### SysrootService, RtosDetectionService
- No `extracted_path` grep hits — appear to operate on component-level data.

### comparison_service (diff_filesystems)
- **File:** `backend/app/services/comparison_service.py:93-111`
- **Why partially unaffected:** Walks the specific path passed in. Caller supplies the root. When called with `firmware.extracted_path` it IS affected (rootfs-only), so dif between two Android uploads misses partition-image-level changes.

### hardware_firmware.graph.build_driver_firmware_graph
- **File:** `backend/app/services/hardware_firmware/graph.py:180-196`
- **Why unaffected:** Operates on HardwareFirmwareBlob rows already in DB. But: IF the detector didn't find the blobs (because of the single-root bug), the graph has nothing to work with. So upstream-blocked.

## Consumers With DEEPER Bugs Found

1. **`virustotal_service` and `abusech_service` caps (50-200 files, 100 for known_good).** Even on rootfs-only, these won't submit every binary — they prioritize libs > executables > others, then cap. Not a scope bug, but combined with single-root, coverage is very thin.
2. **`security_audit_service._scan_android_apps` hardcodes `system/app` + `system/priv-app`.** Misses `product/priv-app`, `vendor/priv-app`, `system_ext/priv-app`. See `backend/app/services/assessment_service.py:519,591-592`. Applies even when scope is correct.
3. **`apk_scan._find_apk_in_firmware` at `backend/app/routers/apk_scan.py:166-188`** uses `extracted_path` as the root. If the APK lives in a sibling partition that's not under rootfs (rare on well-extracted Android, but possible), it can't be found.
4. **`file_service._ROOT_DIR_PATTERN` filter** hides `DPCS10_260414-1134/` from the UI's virtual top-level. Any directory not matching `*-root` is invisible even when `extraction_dir` is set.
5. **`SbomService._get_all_scan_roots` heuristic** only triggers when the parent dir is named `rootfs`, `partitions`, or `images`. For DPCS10-style layouts where the parent is `extracted/`, the heuristic fails silently. Latent.

## Firmware Model Column Usage

`backend/app/models/firmware.py:27-29`:
```
storage_path: Mapped[str | None] = mapped_column(String(512))
extracted_path: Mapped[str | None] = mapped_column(String(512))
extraction_dir: Mapped[str | None] = mapped_column(String(512))
```

Set by the unpack worker in `backend/app/workers/arq_worker.py:103-104`:
```
firmware.extracted_path = result.extracted_path
firmware.extraction_dir = result.extraction_dir
```

Where `result.extracted_path = find_filesystem_root(extraction_dir)` (see `backend/app/workers/unpack.py:126`) — i.e., the deepest directory containing Linux-like markers (`etc/`, `bin/`, `system/`, etc.). For Android, this lands inside `extraction_dir/rootfs/` or deeper (`rootfs/partition_2_erofs/`).

`extraction_dir` is set to the binwalk/unblob output dir (`backend/app/workers/unpack.py:139,169,307,...`). It's the PARENT of rootfs and of all the raw partition images. Only `FileService` reads it (`backend/app/routers/files.py:19`, `backend/app/ai/tool_registry.py:29`). Every other consumer ignores `extraction_dir` entirely and uses `extracted_path` alone.

`firmware_service.py:335,429,521` all set `extracted_path = fs_root` (from `find_filesystem_root`). The one exception: `backend/app/services/firmware_service.py:568` uses `extracted_path` to compute a parent for deletion.

No `detection_roots` column exists. No list-valued path column exists. Every consumer's scope is either `extracted_path` (string) or — for FileService + routers/security_audit.py only — `extraction_dir` (also string).

## Recommendation Preview

Option C from the intake (single-consumer-focused helper) leaves 13+ consumers untouched and each will have to opt in. Option B (hard-link partition images into `rootfs/partitions/`) is the lowest-blast-radius fix: every existing consumer walks `rootfs/` and would pick up partitions automatically. It risks size bloat if files aren't hard-linked, and breaks for filesystems that aren't on the same inode table as the source extraction, but on a single-host Docker volume that's fine.

For a longer-term fix: add a `Firmware.detection_roots: JSONB` column containing a list of absolute paths, populated by the unpacker. Provide a helper `walk_roots(firmware) -> list[str]` in a new `app/utils/firmware_roots.py`. Update the ~13 affected consumers to iterate. This is ~1-2 days of careful refactoring but eliminates the recurrence of the same bug class.

Short-term: Option B (unpacker hard-links into `rootfs/partitions/`) buys immediate correctness for hardware-firmware detection, YARA, security audit, and ClamAV/VT without refactoring. File UI/MCP filesystem tools still need the virtual-root filter relaxed regardless.

## Confidence

high — every cited file:line was read directly. The one un-verified claim is the actual DPCS10 directory layout, which is described in the intake doc; all code behavior statements rely on the observed code only. The detector's "miss" was confirmed empirically by Dustin (246 blobs found, zero from partition images).
