# Anti-patterns: Session 39 — Standalone APK Upload

> Extracted: 2026-04-16
> Source: Session 39 work

## Failed Patterns

### 1. Testing New Backend Logic Without Rebuilding Containers
- **What was done:** Added APK classifier to `unpack_common.py` and tested by uploading an APK through the UI.
- **Failure mode:** The APK was classified as `linux_blob` and extracted by unblob (798 files). The new classifier code wasn't running because the container had the old image.
- **Evidence:** `unpack_log` in database showed "Firmware classified as: linux_blob" despite the new `android_apk` path being present in the source code on disk.
- **How to avoid:** After any change to `backend/app/` or `backend/app/workers/`, always run `docker compose up -d --build backend worker` before testing. This is CLAUDE.md rule #1 and #8 — it has now been hit in sessions 4, 10, 19, 33, and 39.

### 2. APK Files Misclassified as Generic ZIPs
- **What was done:** Before the fix, uploading a standalone `.apk` fell through all classifier checks because APKs are valid ZIP files but don't match Android OTA markers.
- **Failure mode:** `classify_firmware()` had no APK-specific detection, so it fell through to the generic `linux_blob` fallback. The unpack pipeline then ran binwalk/unblob, which extracted the APK's internal structure — destroying the file the APK scanner needs.
- **Evidence:** Database showed `linux_blob` classification, extracted path pointed to unblob output with 798 extracted files.
- **How to avoid:** When adding any new analysis capability that requires a specific file format (APK scan, IPA scan, etc.), also add the corresponding classifier entry in `classify_firmware()` and a fast-path in the unpack pipeline. The analysis tool and the upload pipeline must agree on how the file is stored.
