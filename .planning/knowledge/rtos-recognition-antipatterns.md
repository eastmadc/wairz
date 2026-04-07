# Anti-patterns: RTOS/Bare-Metal Firmware Recognition

> Extracted: 2026-04-06
> Campaign: `.planning/campaigns/rtos-recognition.md`

## Failed Patterns

### 1. ZIP Extraction to Same Directory as Source
- **What was done:** `_extract_firmware_from_zip()` extracted the largest file from a ZIP into the same directory where the ZIP was stored, using `os.path.basename(best.filename)` as the target name.
- **Failure mode:** When the inner file had the same name as the ZIP itself (e.g., `update.zip` containing `update.zip`), `open(target_path, "wb")` truncated the source ZIP to 0 bytes before the read from `zf.open(best)` could complete. Result: EOFError, all data lost, 0-byte files on disk with 967MB recorded in the database.
- **Evidence:** 5 consecutive upload attempts all produced 0-byte files. Database showed correct file_size but disk had empty files. Root cause confirmed by tracing `os.path.realpath()` collision.
- **How to avoid:** Always compare source and target paths with `os.path.realpath()` before extraction. Use a temp suffix or temp directory when paths could collide. This is especially common with ZIP-inside-ZIP firmware packaging (Android OTA, vendor update packages).

### 2. Catching Exception Symptoms Instead of Root Causes
- **What was done:** Initial fix for the 500 error was to wrap `_extract_firmware_from_zip()` in try/except for `EOFError` and fall through to raw firmware mode.
- **Failure mode:** The catch hid the real bug (path collision destroying data). Upload "succeeded" but produced a useless 0-byte firmware entry. The user had to discover the deeper issue through further testing.
- **Evidence:** "ZIP extraction failed (), treating as raw firmware" in logs, followed by classify_firmware returning "linux_blob" and all extractors failing.
- **How to avoid:** When an exception occurs during file I/O, always verify the file's state (size, existence) before and after the operation. An EOFError during ZIP read should trigger investigation of why the ZIP became unreadable, not just silence the error.

### 3. Trusting Seed Assumptions Without Verification
- **What was done:** The seed file listed "Wittenstein" as a high-confidence SafeRTOS string marker and "Micrium"/"Jean J. Labrosse" as uC/OS markers.
- **Failure mode:** Research revealed these strings only appear in source code comments, NOT in compiled binaries. Using them would produce zero detections in real firmware.
- **Evidence:** Scout 2 confirmed from actual source code analysis: "No evidence that 'WITTENSTEIN' or 'Wittenstein' appears as a string literal in compiled SafeRTOS binaries" and "Micrium and Silicon Laboratories strings appear only in source code comments."
- **How to avoid:** For any detection signature, verify it survives compilation. Research from the actual source code repositories, not from documentation or marketing materials. The definitive markers were task name strings passed to `OSTaskCreate()` — these are string literals that persist in .rodata.
