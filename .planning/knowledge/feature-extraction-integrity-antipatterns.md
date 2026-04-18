# Anti-patterns: Extraction Integrity Campaign

> Extracted: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-extraction-integrity.md`

## Failed Patterns

### 1. `git stash --include-untracked` with freshly-written planning files (RECURRING)

- **What was done:** Archon created new campaign + scope-claim files (untracked), then ran `git stash push --include-untracked -m "checkpoint-phase-N"` to create a phase checkpoint.
- **Failure mode:** Stash swallowed the untracked planning files. Working tree lost them; `git stash pop` conflicted with subsequent file creations.
- **Evidence:** Same failure pattern as in `feature-hw-firmware-phase2-enrichment` campaign (see its antipatterns.md #1). Now observed 2x.
- **How to avoid:** Commit the campaign file + scope claim BEFORE creating any phase checkpoint stash. Use `git reset --hard HEAD` for rollback, OR stash only tracked source files after planning docs are committed. Consider adding to Archon's protocol as "Step 2.X: commit planning docs before phase-1 checkpoint."

### 2. Docker `COPY` bake during live agent writes

- **What was done:** User triggered `docker compose up -d --build backend worker` while a Phase 5 agent was still writing `routers/firmware.py`. The Dockerfile's `COPY . .` captured the source tree mid-write.
- **Failure mode:** Baked image contained partial Phase 5 code. New `/audit` endpoint was present in `inspect.getsource()` (that ran a fresh Python from disk) but missing from the running uvicorn worker's OpenAPI spec (its in-memory route table came from the stale bake).
- **Evidence:** `curl /audit` returned 404 despite disk-file having the route. Required a second rebuild after the agent completed.
- **How to avoid:** Treat `docker build` as a barrier. Either (a) do all code writes THEN rebuild, or (b) use a bind-mount + `uvicorn --reload` for dev iterations. Never parallelize a rebuild with an agent that might still be writing.

### 3. `uvicorn` without `--reload` combined with `docker cp`

- **What was done:** Did `docker cp` into running container to test code changes without rebuilding. Ran fresh `python -c "inspect..."` and confirmed the new code was in the module. Assumed the running uvicorn worker would also pick it up.
- **Failure mode:** uvicorn imports modules once at startup. `docker cp` updates disk but not the interpreter's `sys.modules` cache. Every subprocess `python -c` reads fresh-from-disk, so it looks like the fix is live. But the actual running worker still serves requests with the CACHED module.
- **Evidence:** User's new firmware upload hit the OLD code path despite "confirmed" fix via subprocess inspect. Had to manually re-run the extraction/detection.
- **How to avoid:** Either add `--reload` to uvicorn in dev, or always rebuild + restart the container after a code change (`docker compose up -d --build`). Don't use `docker cp` as a "live hot-reload" mechanism for interpreted code.

### 4. Single-string `extracted_path` as walk root for multi-dir extractions

- **What was done:** Original design stored the "primary" extraction root on Firmware as a single string. Every downstream walker read it. Worked fine for single-image uploads + typical Linux rootfs tarballs.
- **Failure mode:** Android OTA uploads produce `extracted/rootfs/` + `extracted/<zip-basename>/` siblings. Medical/embedded ZIPs (RespArray) produce `zip_contents/target/` with many sibling archives. Single-string column can only point at one. Siblings become invisible to every downstream walker.
- **Evidence:** ~1,218 projected orphan blobs across 10 firmware in the live DB audit. 7 sibling tar.xz archives in RespArray invisible without Phase 1+2 fixes.
- **How to avoid:** When a data type can have multiple "authoritative" locations, model it as a list from the start. Even if today's upload flow produces only one root, future flows won't. Defensive API shape costs nothing.

### 5. 1-MiB minimum-size filter on partition images

- **What was done:** `unpack_android.py` had a blanket `if size < 1_048_576: skip` filter on OTA partition images, presumably to avoid cluttering the extraction with hash files or manifests.
- **Failure mode:** DPCS10 ships `modem.img` at 528 bytes (non-cellular tablet stub) and `md1dsp.img` at 2 KB. Both dropped silently. User-visible: "md1dsp.img is missing from the firmware view."
- **Evidence:** Scout 1 identified the exact lines (`unpack_android.py:429-430` and `:323-324`).
- **How to avoid:** Use strict filters (file MIMEs, magic bytes, explicit extensions) rather than size heuristics. If you must have a floor, set it at the level of "definitely not a firmware blob" (e.g., 64 bytes — smaller than the smallest valid header). Document the reason inline.

### 6. `os.remove()` after failed mount

- **What was done:** When a partition image failed to mount (corrupt EROFS, unsupported filesystem), `unpack_android.py` deleted the raw image to save disk space.
- **Failure mode:** Phase 3 MediaTek/Qualcomm parsers operate on RAW BYTES, not a mounted filesystem. Deleting the image meant those parsers got nothing. Critical for blobs where mount is inherently expected to fail (e.g., signed/encrypted partitions).
- **Evidence:** 3 `os.remove` sites at `unpack_android.py:457, 476, 483`.
- **How to avoid:** Don't delete raw inputs during extraction. Keep them until the next phase is confirmed done. Disk space concerns are mitigated by the extraction-dir cleanup at the container-lifetime level.

### 7. Classifier assumes all `*.tar.xz` files are real xz-compressed tar

- **What was done:** The recursive-extract helper tried `tarfile.open("...tar.xz", "r:*")` on every file with a `.tar.xz` extension.
- **Failure mode:** RespArray ships 6 files with `.tar.xz` extension but a custom `\xa3\xdf\xbb\xbf` magic (proprietary signed archive format). `tarfile` errored on each. Helper caught the errors — but no signal surfaced to the user that these ARE firmware blobs worth flagging.
- **Evidence:** RespArray live audit — 6 "archives" failed to extract, 0 classified as anything, invisible in the UI.
- **How to avoid:** Classification by extension alone is fragile. Magic-byte checks + "unknown signed blob" categories give the user visibility even when we can't decode. Follow-up intake queues this explicitly.

### 8. Unblob picks "the largest archive" as the firmware target

- **What was done:** `_extract_firmware_from_zip` picks the largest file in the ZIP as the "primary firmware." Unblob then runs on that one file only. For single-image uploads this works fine.
- **Failure mode:** Multi-file firmware ZIPs (RespArray: 28 files including 7 sibling tar.xz archives + 4 MCU .bin files) get ONE archive treated as "the" firmware. The rest of the ZIP contents land in `zip_contents/` but aren't recursively processed.
- **Evidence:** RespArray before live-fix: 0 detected blobs despite 28 files in zip_contents.
- **How to avoid:** For multi-file containers, either (a) treat the whole container as the firmware and recurse, or (b) create multiple Firmware rows — one per significant archive. Option (a) chosen for this campaign; (b) remains a future refactor if single-firmware-one-device semantics become important.

## Decisions NOT Made (worth noting)

- **New `Firmware.detection_roots: ARRAY(Text)` column:** rejected. Migration cost + double-write hazard (two places to keep in sync).
- **Normalize extraction layout so everything lives under `rootfs/`:** rejected. Breaks `detect_architecture`/`detect_os_info`/`detect_kernel` which assume unix-shaped rootfs directly under the returned path. High regression risk.
- **Normalized `FirmwarePath` table:** rejected for now. Overkill for current scope; Option A's list-based return type can promote to `list[FirmwarePath]` later if LATTE/iOS IPSW demand per-path provenance.
- **`md1imgpy`, `kaitaistruct`, `fakeredis` pip deps:** rejected (in prior campaigns too). Pattern: prefer native implementation for ~200-500 LOC problems. Avoids GPL-3/AGPL review, Docker build fragility, backend+worker rebuild coupling.

## Live-Discovered Real-World Edge Cases

1. **Proprietary archive magic `\xa3\xdf\xbb\xbf` (RespArray medical firmware).** Looks like tar.xz by extension; isn't. Correctly skipped by helper; needs surface-as-unknown for user visibility.
2. **Tar archives that unblob extracts via a symlink-only output** (RespArray's `target/extracted/rootfs_partition.tar.xz -> ../rootfs_partition.tar.xz`). Classifies as "extraction success" to unblob because it wrote one file, but the extraction is logically empty. Triggers the shallow-container case.
3. **Android partition stubs at 528 bytes** (DPCS10 modem.img on a non-cellular tablet). Legitimate content that size heuristics falsely-reject.
4. **Pre-detector uploads with `blobs = 0` in DB.** 3 of 10 firmware in the sample had never been detected at all — backfill recovered 1,000+ blobs.
5. **Linux kernel zImage at top level of an extracted archive.** Detected by magic-byte scan but not (yet) classified as hw-firmware. Queued for follow-up.

---

## Follow-up anti-patterns — discovered 2026-04-18 (24 hours post-campaign)

### 9. Phase-in-isolation testing — Phase 1 output never fed into Phase 2 scan

- **What was done:** Phase 1 (`_relocate_scatter_subdirs`, commit 72a2049)
  and Phase 2 (`firmware_paths._compute_roots_sync`, commit ceade9a)
  were each individually unit-tested.  Phase 1 tests verified files
  moved out of the scatter subdir; Phase 2 tests verified roots were
  discovered in a pre-constructed multi-subdir fixture.  No test
  piped Phase 1's output into Phase 2's input.
- **Failure mode:** Production behaviour after both phases: scatter
  zip unzips into `extracted/DPCS10_*/` → relocation moves `.img`
  files to `extracted/` top level → Phase 2 scans SUBDIRECTORIES of
  `extracted/` and finds only `rootfs/` (top-level `.img` files are
  invisible because scan doesn't look at files, only dirs).  DPCS10
  `0ed279d8` lost 14 MTK blobs the existing 260-blob 188c5b24 run
  had captured (because 188c5b24 was uploaded pre-Phase-1, its files
  were still in the subdir that DID qualify).
- **Evidence:** 24 h after campaign close, a new upload exposed the
  gap.  Fix + regression tests shipped in same-session:
  `test_post_relocation_layout_includes_container`,
  `test_linux_rootfs_only_container_not_included`,
  `test_pre_relocation_scatter_subdir_still_detected` in
  `test_firmware_paths.py`.  Captured as CLAUDE.md Learned Rule #18.
- **How to avoid:** When a multi-phase campaign changes the same
  data shape (here: on-disk extraction layout), at minimum ONE test
  in the campaign's test suite must chain Phase-N-output →
  Phase-N+1-input.  Not "each phase passes its fixtures" — "the
  campaign passes its own pipeline."  Add a phase-end condition
  explicitly: `integration_test_combined_phases_passes`.

### 10. User-data partition sparse-expansion inflating bomb-cap walk

- **What was done:** Phase 1 added simg2img conversion for sparse
  Android images + kept the raw bytes for downstream parsers.  No
  partition-name filter was applied: `userdata.img`, `cache.img`,
  `metadata.img`, `persist.img`, `misc.img` were all treated as
  firmware and expanded from sparse to raw.
- **Failure mode:** `userdata.img` declared-sparse size on OEM
  Android is multi-GB of mostly-zero data.  After simg2img, the
  raw file sat on disk alongside the retained super.img.raw
  (another ~9 GB).  The combined size tripped the 10 GB
  extraction-bomb cap even on legitimate firmware, which triggered
  `shutil.rmtree(extraction_dir)` — wiping ALL prior successful
  extraction.  User saw "Unpacking Failed" for a firmware whose
  extraction had actually succeeded before cleanup ran.
- **Evidence:** DPCS10 1.1 GB scatter zip tripped
  `Extraction bomb detected: total size (10256MB) exceeds limit
  (10240MB)` — 16 MB over.  Fixed with `_is_user_data_partition`
  skip + super-raw deletion when `_scan_super_partitions` reports
  full success.  9 new tests in `test_unpack_integrity.py`.
- **How to avoid:** When adding a generic "extract every
  partition" loop, include a domain-knowledge skip-list for
  partitions that are not firmware code.  Android's canonical
  user-data set is documented by AOSP; other ecosystems have
  analogues (iOS user data containers, Windows `Users/`-shaped
  partitions).  Don't rely on the bomb-cap to catch "this wasn't
  firmware" — the cap is a defensive safeguard, not a classifier.

### 11. Bomb-cap trip wipes successful extractions (rmtree too aggressive)

- **What was done:** The four `check_extraction_limits` call sites in
  `unpack.py` (android / partition_dump_tar / linux_rootfs_tar /
  fallback chain) all followed the same shape: call the check, on
  error set `result.error`, `shutil.rmtree(extraction_dir)`, return.
  The rmtree ran BEFORE `_analyze_filesystem` had a chance to report
  whether the extraction produced a valid rootfs.
- **Failure mode:** A 16 MB-over-budget successful extraction (valid
  rootfs, 8 super partitions extracted, 22 scatter blobs on disk)
  was rmtree'd identically to a 50 GB malicious zip-bomb producing
  nothing.  User-visible: "Unpacking Failed."  The defensive
  cleanup couldn't distinguish "bomb" from "successful big firmware."
- **Evidence:** DPCS10 post-user-data-skip still tripped because
  super.img.raw (9.2 GB) was retained. Fix reorders all four sites:
  run `_analyze_filesystem` FIRST; if analysis succeeds, keep the
  extraction + log WARNING; rmtree only when analysis ALSO fails.
- **How to avoid:** Never couple a defensive budget check to a
  destructive cleanup when another signal (analysis success) can
  prove the work was legitimate.  If the budget is being tripped by
  legitimate work, either raise the budget, exclude known-safe
  artefacts (e.g. super-img container that's retained
  intentionally), or move the check earlier (pre-extraction bomb
  check, not post).

## Campaign-completeness lesson

A campaign being "closed" + its postmortem filed doesn't mean the
system it touched is stable.  This campaign's post-close gap appeared
24 h after closure.  The general pattern: large multi-phase
refactors have a tail of integration-only bugs that unit tests don't
catch.  **Keep the campaign file open for revisit** (or explicitly
document follow-up candidates) for at least one real-world usage
cycle after close.  The knowledge files themselves become the record
of that tail.
