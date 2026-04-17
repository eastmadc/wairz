# Upstream Extraction Gap Audit

> Scout 1 of 4
> Date: 2026-04-17

## Summary

Found **12 concrete silent-drop sites** in the extraction pipeline, **9 of which can cause partition images / firmware blobs to be completely absent from disk** or mis-placed to a sibling dir the detector never walks. The DPCS10 gap is not a one-off — the Android OTA path (`_extract_android_ota`) systematically hides raw partitions in `extracted_path/<zip-basename>/` or `extracted_path/partitions/` while the code downstream treats `rootfs/` as the single source of truth. The severity is HIGH: every MediaTek / Qualcomm / Samsung OTA that contains auxiliary partitions (preloader, LK, TEE, SCP, SSPM, modem, DSP, vbmeta, DTBO) loses them to downstream analysis.

## Gap Inventory (ranked by severity)

### Gap 1: OTA zip extraction writes raw `.img` files into `extraction_dir` alongside `rootfs/` — they stay there forever

- **Where:** `backend/app/workers/unpack_android.py:372-401`
- **What's lost:** Every auxiliary partition image: `preloader_*.bin`, `lk.img`, `tee.img`, `scp.img`, `sspm.img`, `spmfw.img`, `md1dsp.img`, `md1img.img`, `modem.img`, `cam_vpu*.img`, `dtbo.img`, `vbmeta*.img`, `logo.bin`, etc.
- **Symptom:** Hardware-firmware detector walks `rootfs/` — these partitions are at `extracted/<basename>/` or `extracted/`. Phase 3 MediaTek/Qualcomm parsers never see them. This is the DPCS10 bug.
- **How to detect:** After extraction, compare `os.listdir(extraction_dir)` vs `os.listdir(extracted_path)`. Any `.img` / `.bin` sitting at the parent level is orphaned.

### Gap 2: `payload.bin` partition-dumper writes to `extraction_dir/partitions/` — a sibling dir outside `rootfs/`

- **Where:** `backend/app/workers/unpack_android.py:380-394`
- **What's lost:** Every partition extracted from A/B OTA payload.bin (system, vendor, product, modem, boot, preloader, etc.). After `payload-dumper-go` writes them to `partitions/`, later code copies *only the ones that mount as ext4/EROFS* into `rootfs/`. Everything else is abandoned at `partitions/`.
- **Symptom:** On A/B OTA images (Samsung, Pixel, most modern Android), the `partitions/` subtree contains every raw image but `extracted_path` points at `rootfs/`. Detector misses them all.
- **How to detect:** `payload-dumper-go` presence + `partitions/` dir existence after unpack.

### Gap 3: `_extract_android_ota` silently filters partition images `< 1 MB`

- **Where:** `backend/app/workers/unpack_android.py:429-430`
  ```python
  if os.path.getsize(img_path) < 1024 * 1024:
      continue
  ```
- **What's lost:** `modem.img` on DPCS10 is **528 bytes** — below this threshold. Any small partition (stub modem on non-cellular devices, tiny SPI flash dumps, micro-bootloaders, proto partition placeholders) is never processed by `_try_extract_partition` and never renamed/identified.
- **Symptom:** Partitions smaller than 1 MB are left as raw `.img` files in the OTA extraction dir and never mounted, never detected.
- **How to detect:** `grep -n "1024 \* 1024" backend/app/workers/unpack_android.py`

### Gap 4: Super-image partition scanner skips embedded partitions `< 1 MB`

- **Where:** `backend/app/workers/unpack_android.py:323-324`
  ```python
  if part_size < 1024 * 1024:
      continue
  ```
- **What's lost:** Small embedded partitions inside super.img (tiny vendor firmware blobs, signing metadata regions). Same 1 MB floor.
- **Symptom:** Partitions between 0 and 1 MB in super.img are detected by magic scan but never extracted.

### Gap 5: Super-image magic scan walks in 1 MB strides — mid-MB partitions are missed

- **Where:** `backend/app/workers/unpack_android.py:296-302`
  ```python
  for offset in range(1024, min(size, 10 * 1024**3), 1024 * 1024):
      if mm[offset:offset + 4] == EROFS_MAGIC:
  ```
- **What's lost:** Any EROFS/ext4 partition whose magic bytes are NOT on a 1 MiB boundary (atypical, but some proprietary super formats don't align partitions to 1 MiB). Also limited to the first 10 GB.
- **Symptom:** Silent miss — the partition exists in super.img, the detector never finds it because the stride-step is too coarse.

### Gap 6: `fsck.erofs` / `debugfs` extract failures delete the destination dir and return False — raw image is then discarded

- **Where:** `backend/app/workers/unpack_android.py:45-100`, specifically lines 96-100 where `os.rmdir(dest_dir)` runs when both extractors fail
- **What's lost:** If a partition can't be mounted (corrupt filesystem, unsupported variant, wrong tool version), it's treated as a total failure. The raw `.img` is deleted by the OTA extraction path (line 457 `os.remove(img_path)` after simg2img success, line 476 `os.remove(raw_path)` for super, line 483 `os.remove(raw_path)` for plain partitions).
- **Symptom:** A partition that we COULD analyze via hw-firmware parsers (preloader GFH, LK header, modem DSP) is deleted because the mount failed. The parser would have worked on the raw bytes; we never get the chance.

### Gap 7: Timeouts on partition extract are silent — the kill happens, the raw file is deleted

- **Where:** `backend/app/workers/unpack_android.py:72-74` (fsck.erofs timeout), 92-94 (debugfs timeout)
  ```python
  except asyncio.TimeoutError:
      proc.kill()
      log_lines.append(f"fsck.erofs timed out on {partition_name}")
  ```
- **What's lost:** Whatever portion of the partition had been extracted before the 300s timeout. The dest dir is left partially populated. The caller doesn't know — `return False` only if `os.listdir(dest_dir)` is empty. If it's non-empty but incomplete, the partition is marked "extracted" with missing files.
- **Symptom:** Partial rootfs gets promoted to "successfully extracted"; downstream tools think they're looking at a complete partition.

### Gap 8: simg2img failure deletes the sparse image but falls through to "can't convert" log line only

- **Where:** `backend/app/workers/unpack_android.py:446-460`
  ```python
  os.remove(img_path)
  ...
  except Exception as e:
      log_lines.append(f"Error converting {img_name}: {e}")
      continue
  ```
- **What's lost:** If simg2img corrupts or truncates the output (silent format mismatch, insufficient disk), original sparse image is already deleted on line 457 BEFORE the exception check. The `.raw` file may be partial and the original sparse is gone.
- **Symptom:** Sparse → raw conversion can leave a truncated `.raw` with no way to recover the original; no size check is performed after simg2img completes.
- **How to detect:** No post-conversion size check exists. The output size is not compared against the sparse file's declared expanded size.

### Gap 9: Sparse conversion has NO magic/CRC/size verification

- **Where:** `backend/app/workers/unpack_android.py:448-456` — `simg2img img_path raw_path` runs, the only success criterion is `proc.communicate()` not raising. Only a size log is printed (`os.path.getsize(raw_path) // (1024*1024)}MB`). No magic check on output.
- **What's lost:** Silent conversion failures produce a file of some size but with garbage content.
- **Symptom:** A "successful" partition dump that contains random bytes; downstream mount fails with no actionable error.

### Gap 10: MediaTek scatter zip: version-named subdir extracted, but nothing is relocated

- **Where:** `backend/app/workers/unpack_android.py:416-418`
  ```python
  for entry in os.scandir(extraction_dir):
      if entry.is_dir(follow_symlinks=False) and entry.name not in ("rootfs", "partitions", "boot"):
          search_dirs.append(entry.path)
  ```
- **What's lost:** The code only SCANS the version-named subdir for `.img` files to process. It does NOT move them into rootfs. After processing, the raw images stay in the version subdir (the DPCS10 `DPCS10_260414-1134/` dir). This is the exact root cause of the reported bug — and it's explicitly coded that way.
- **Symptom:** Partition images processed but left in sibling dir; `extracted_path` points at `rootfs/`; detector only walks `rootfs/`.

### Gap 11: Android OTA path does not recursively extract nested archives

- **Where:** `backend/app/workers/unpack_android.py:398-401`
  ```python
  for name in names:
      if name.endswith(".img") or name.endswith(".bin"):
          zf.extract(name, extraction_dir)
  ```
- **What's lost:** Nested `firmware-update.zip` (Samsung Odin packages wrap a tar.md5 that wraps a zip), nested `.tar` inside an OTA, `.lz4`-compressed partitions. Also `.elf`, `.mbn`, `.signed`, `.img.gz`, `.tar.xz` — anything not ending in `.img` or `.bin`.
- **Symptom:** Compressed / nested partitions survive the OTA zip extraction as archives but are never decompressed or processed.

### Gap 12: `cleanup_unblob_artifacts` deletes raw chunks that we might want

- **Where:** `backend/app/workers/unpack_common.py:65-104` + `backend/app/workers/unpack.py:680-686`
  ```python
  extract_dir = entry.path + "_extract"
  if os.path.isdir(extract_dir):
      os.unlink(entry.path)  # deletes the raw chunk
  ```
- **What's lost:** Raw chunks unblob identified (e.g. `0-12345678.preloader_gfh`) are deleted once their `_extract` dir exists. If unblob produced an empty `_extract` dir but the chunk had parseable content, we lose both. Also `.unknown` files are always deleted, which means unidentified bootloader tails, padding with embedded signatures, etc., are gone before any other parser can look.
- **Symptom:** hw-firmware parsers that could identify proprietary headers (GFH, HMBN, Qualcomm MBN envelopes) on unblob's `.unknown` chunks never see them.

## Sibling-Directory Pattern (the DPCS10 root-cause pattern)

Places where extraction writes outside `extracted_path` (where `extracted_path` is eventually `rootfs/...`):

| Location | File:line | Output dir | Result |
|----------|-----------|-----------|--------|
| OTA zip extract all .img | `unpack_android.py:400` | `extraction_dir/` (not rootfs/) | orphan `.img` files |
| payload-dumper-go output | `unpack_android.py:381-388` | `extraction_dir/partitions/` | orphan after mount-filter |
| Scatter zip version subdir | `unpack_android.py:416-418` | `extraction_dir/<basename>/` | **exact DPCS10 case** |
| Boot.img extraction (fast path) | `unpack.py:560-569` | `extraction_dir/boot/` | extracted_path pointed at ramdisk, `/boot/` ignored |
| UEFI `.dump/` output | `unpack.py:159-168` | `extraction_dir/<name>.dump/` | only one dir seen by UEFI analysis |
| Binwalk3 extract dir | fallback chain, `_find_binwalk_output_dir` | nested under extracted_path | `extraction_dir` set to parent via line 139 — sometimes |
| Unblob `_extract` chunks | `unpack.py:682-686` | `extraction_dir/*_extract/` | cleaned, but content under `_extract` survives only in rootfs-discovery |

The pattern: `extracted_path` is a SINGLE string column, set to the best rootfs guess. Detection downstream walks only that path. Any partition image or chunk sibling to the rootfs is invisible.

## File-Filter Thresholds Applied

| File | Line | Filter |
|------|------|--------|
| `unpack_android.py` | 429-430 | `.img < 1 MB` dropped from OTA partition processing |
| `unpack_android.py` | 323-324 | partitions `< 1 MB` in super.img scan skipped |
| `unpack_android.py` | 296-297, 300-301 | super.img magic scan stride = 1 MB (misaligned partitions missed) |
| `unpack_android.py` | 296 | super.img scan capped at 10 GB |
| `unpack_common.py` | 118-120 | `max_extraction_size_mb=10240`, `max_extraction_files=500000`, `max_compression_ratio=200` |
| `unpack.py` | 706 | standalone binary fallback capped at `10 MB` |
| `unpack_linux.py` | 137 | kernel candidate size `< 500 KB` silently dropped |
| `_firmware_tar_filter` | `unpack_linux.py:248-249` | filters out tar members that are not reg/dir/sym/hard — device nodes, FIFOs, sockets dropped silently |

## Silent-Failure Modes

| Mode | File:line | Impact |
|------|-----------|--------|
| simg2img output unchecked | `unpack_android.py:451-456` | truncated `.raw` treated as success |
| fsck.erofs timeout | `unpack_android.py:72-74` | partial extraction left on disk, returns False only if dir empty |
| debugfs timeout | `unpack_android.py:92-94` | same partial-extraction risk |
| payload-dumper-go timeout | `unpack_android.py:391-394` | kill; log but no indication which partitions were partial |
| Boot-img parse silently reads 1648 bytes | `unpack_android.py:117-120` | header v0 has different offset for dtbo_size/dtb_size reads; hardcoded 1632/1636 from v2+ used on v1 → wrong sizes |
| Ramdisk extraction exception swallowed | `unpack_android.py:186-187` | ramdisk.img preserved but `ramdisk/` empty, no error propagated |
| cleanup_unblob_artifacts errors swallowed | `unpack_common.py:89-91, 100-102` | orphan chunks can accumulate |
| Fallback chain `except Exception as e` | `unpack.py:699-701` | unblob/binwalk crashes logged at INFO only, rotates to next extractor |
| arq_worker 30min timeout | `arq_worker.py:371` | stuck extractions marked error, partial `extraction_dir` survives on disk with no cleanup |
| Tar filter drops device/FIFO/socket members | `unpack_linux.py:248` | xattrs + special files silently lost |
| No xattr/ACL preservation on tar extract | `unpack_linux.py:235-258` | SELinux contexts, capabilities lost — affects subsequent security audits |

Notable design choice: **the 30-min job timeout (`arq_worker.py:371`) doesn't distinguish successful partial extraction from real failure.** On timeout the job sets `project.status = "error"` (arq_worker.py:149) but `firmware.extracted_path` stays NULL; the half-extracted tree on disk is ORPHANED — never cleaned, never surfaced.

## Concrete File-References List

Jump targets for the reviewer:

- `backend/app/workers/unpack.py:270` — extraction_dir seed (`os.path.join(output_base_dir, "extracted")`)
- `backend/app/workers/unpack.py:52-68` — `_pick_detection_root` (only existing partial mitigation; parent walk, BUT only applies when parent contains Android partition siblings OR 2+ `partition_*` dirs; DPCS10's raw `.img` siblings don't qualify)
- `backend/app/workers/unpack.py:119-146` — `_analyze_filesystem` sets `extracted_path` to the rootfs guess, the root of the problem
- `backend/app/workers/unpack_android.py:365-485` — `_extract_android_ota` — the extraction routine that creates the sibling-dir layout
- `backend/app/workers/unpack_android.py:410-411` — `rootfs_dir = os.path.join(extraction_dir, "rootfs")` creates the split
- `backend/app/workers/unpack_android.py:413-418` — search_dirs initialization that documents the multi-dir layout but never consolidates it
- `backend/app/workers/unpack_android.py:429-430` — `1 MB` filter
- `backend/app/workers/unpack_android.py:446-457` — simg2img conversion with no output validation
- `backend/app/workers/unpack_android.py:457` — `os.remove(img_path)` deletes source sparse after conversion (no backup)
- `backend/app/workers/unpack_android.py:462-476` — super.img magic check and partition scan trigger
- `backend/app/workers/unpack_android.py:474-476` — `_scan_super_partitions` call + `os.remove(raw_path)` — original super.img deleted after scan
- `backend/app/workers/unpack_android.py:482-483` — `os.remove(raw_path)` for plain partitions, same data-loss risk if `_try_extract_partition` partially succeeds
- `backend/app/workers/unpack_android.py:279-362` — `_scan_super_partitions` with 1 MiB stride limitation
- `backend/app/workers/unpack_android.py:45-100` — `_try_extract_partition` — EROFS then ext4, no fallback to raw-copy, dest dir removed on double-failure
- `backend/app/workers/unpack_android.py:155-157` — boot.img page-aligned offsets (works, but no validation of computed offsets vs file size)
- `backend/app/workers/unpack_android.py:198-226` — boot.img v1/v2 recovery_dtbo/dtb — hard-coded offsets 1632/1636 without version guard (header v0 doesn't have these fields, but code only checks `header_version >= 1` for dtbo)
- `backend/app/workers/unpack_common.py:172-186` — binwalk3 invocation; output dir = extraction_dir (same as OTA extraction target — CAN collide)
- `backend/app/workers/unpack_common.py:189-213` — unblob invocation; `--extract-dir` = extraction_dir
- `backend/app/workers/unpack_common.py:65-104` — cleanup_unblob_artifacts (aggressive; see Gap 12)
- `backend/app/workers/unpack_common.py:315-350` — find_filesystem_root; prefers rootfs-like dirs, ignores raw partition siblings
- `backend/app/workers/unpack_common.py:107-169` — check_extraction_limits (bomb prevention, but triggers shutil.rmtree of extraction_dir on line 676 in unpack.py — wipes ALL extracted content if limits exceeded)
- `backend/app/workers/unpack_linux.py:235-258` — `_firmware_tar_filter` drops device/FIFO/socket members
- `backend/app/workers/arq_worker.py:149-170` — timeout cleanup; sets project status to error but leaves extraction_dir on disk

## Confidence

**HIGH** for gaps 1–4, 10–12 (code-confirmed with exact line numbers). **MEDIUM** for gaps 5, 7, 8, 9 (logic clearly missing guards, but live firmware needed to prove impact). The DPCS10 case is a concrete reproducer for gap 1+10; the others follow the same pattern and have identical code-paths. Overall confidence **HIGH** that Dustin's "holy shit this was a huge gap" instinct is correct — this is a systematic extraction-vs-detection boundary bug with ~dozen distinct symptoms, not a single hot-spot.
