# Stream C Handoff — Android OTA/ZIP Extraction Hardening

**Campaign:** wairz-intake-sweep-2026-04-19  
**Stream:** C  
**Date:** 2026-04-19  
**Branch:** clean-history

---

## Commits

Two logical units shipped in one commit (helper + migration):

1. `backend/app/workers/safe_extract.py` — NEW module
2. Migration of 3 call sites + `firmware_service.py`

---

## Files Touched

| File | Change |
|------|--------|
| `backend/app/workers/safe_extract.py` | NEW — `safe_extract_zip()` with all 3 defences |
| `backend/app/workers/unpack_android.py` | Lines 498–526: replaced two `zf.extract()` calls |
| `backend/app/workers/unpack_common.py` | Lines 249–267: replaced `_extract_zip_safe` body |
| `backend/app/services/firmware_service.py` | Lines 224–254: replaced inline bomb+extractall block |
| `backend/tests/test_safe_extract.py` | NEW — 16 tests covering all 7 battery items |

---

## Verification Battery

| # | Test | Result |
|---|------|--------|
| 1 | Normal zip (3-file) extracts, files present | **PASS** |
| 2 | Zipslip `../../../etc/passwd` → ValueError with "path escape" | **PASS** |
| 3 | Bomb rejected (declared total > max_size) pre-flight, no file written | **PASS** |
| 4 | Symlink external_attr → ValueError with "symlink" in message | **PASS** |
| 5 | Migration completeness grep: 0 bare `zf.extract`/`extractall` in workers + firmware_service | **PASS** |
| 6 | Android OTA-style synthetic ZIP (5 files + 1 subdir) extracts all 6 files | **PASS** |
| 7 | Rule 16 regression: no `.extracted_path` reads in unpack_android.py or unpack_common.py | **PASS** (0 hits) |

All 16 pytest tests passed in 0.08s on Python 3.12.13.

---

## Design Notes

- `safe_extract_zip(zip_path, dest, *, max_size, entry_filter)` — entry_filter lets Android OTA caller extract only payload.bin or .img/.bin files while security checks (symlink, zipslip) still run on ALL entries regardless of filter.
- Streaming bomb detection: pre-flight rejects falsely-declared honest archives fast; the per-entry streaming check catches bombs that declare small size but expand large.
- `_extract_zip_safe` in `unpack_common.py` is kept as a thin wrapper (3 lines) to preserve the existing call site in `_extract_single_archive` without touching that function signature.
- `firmware_service.py` `_extract_archive` zip branch reduced from 30 lines to 3: `safe_extract_zip` now owns all containment, bomb, and symlink logic; max_size is derived from `settings.max_extraction_size_mb` for backwards compatibility.

---

## Rule-1/8/16 Gotchas

- **Rule 1 (path traversal):** All three call sites now use `safe_extract_zip`, which applies `os.path.realpath()` + prefix check per-entry. No duplication.
- **Rule 8 (rebuild worker+backend):** This change touches `unpack_android.py` and `unpack_common.py` which are shared by both backend and worker images. A full `docker compose up -d --build backend worker` is required before trusting in production. The `docker cp` + test run performed here is for validation speed only.
- **Rule 16 (get_detection_roots):** No `firmware.extracted_path` reads were added or modified in the worker files touched. The per-binary OTA extraction (`_extract_android_ota`) is a pre-detection step that operates on the raw upload path, not the firmware ORM object — not in scope for rule 16.

---

## Synthetic Fixture Note

No pre-existing OTA ZIP fixture existed under `backend/tests/fixtures/`. Test 6 uses a synthetic 6-entry ZIP created programmatically in the test itself (boot.img, system.img, vendor.img, userdata.bin, META-INF/MANIFEST.MF, META-INF/subdir/info.txt). No disk fixture file was created; all fixture construction happens in-memory via `zipfile.ZipFile` + `zf.writestr()`.
