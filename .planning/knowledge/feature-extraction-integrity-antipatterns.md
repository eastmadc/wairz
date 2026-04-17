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
