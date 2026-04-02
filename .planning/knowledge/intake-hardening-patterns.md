# Patterns: Firmware Intake Hardening

> Extracted: 2026-04-02
> Source: GL-RM10 Rockchip RKFW failure → adaptive fallback + retry fix + robustness audit
> Commits: b0a54ce, 93cb3db, 2bca07b

## Successful Patterns

### 1. Fallback chain > rigid classification
- **Description:** Replace classify→extract with classify→fast-path→fallback-chain. Unknown formats try binwalk (600s), then unblob (1200s). Fast paths still work for known formats.
- **Evidence:** GL-RM10 Rockchip RKFW: classified as "linux_blob", binwalk timed out, BUT succeeded on fresh project when unblob handled it. The architecture was proven correct.
- **Applies when:** Any pipeline that routes to format-specific handlers. Always have a generic fallback that handles "everything else" rather than erroring.

### 2. Test with a fresh instance before debugging the tool
- **Description:** The GL-RM10 failure was diagnosed as "binwalk/unblob can't handle RKFW" — but a fresh project upload succeeded immediately. The real bug was retry state pollution, not tool capability.
- **Evidence:** Same firmware, same tools: failed on retry (polluted dir), succeeded on fresh project (clean dir).
- **Applies when:** Any extraction/processing failure. Before adding format-specific tooling, test with a clean state to isolate whether the tool or the environment is the problem.

### 3. finally block for status management in background tasks
- **Description:** Background tasks that set status to "unpacking" must guarantee reset in a finally block, not just catch blocks. Nested try/except can silently fail, leaving status stuck forever.
- **Evidence:** The GL-RM10 project was stuck at "unpacking" for 10+ hours. The outer exception handler's nested try/except both failed silently.
- **Applies when:** Any async background task that sets a "processing" status. Use finally to guarantee cleanup.

### 4. Robustness audit after a real failure
- **Description:** After fixing the immediate bug (retry cleanup), launched a comprehensive audit that found 16 issues (3 CRITICAL, 4 HIGH, 5 MEDIUM, 4 LOW). Fixed all 3 CRITICALs immediately.
- **Evidence:** The audit found the status-stuck bug, missing file detection, and ZIP exception handling — none of which were visible from the original failure.
- **Applies when:** After any production failure. Fix the immediate cause, then audit the surrounding code for related weaknesses.

## Anti-patterns

### 1. os.makedirs(exist_ok=True) is not idempotent for extraction
- **What was done:** `os.makedirs(extraction_dir, exist_ok=True)` before extraction
- **Failure mode:** On retry, the directory exists with 7.6GB of leftover data. Binwalk creates collision-numbered subdirs (-0.extracted, -1.extracted) in the polluted dir. find_filesystem_root() can't find a valid rootfs.
- **Evidence:** GL-RM10 retry: 3 duplicate extraction directories, no rootfs found. Fresh project: succeeded immediately.
- **How to avoid:** Always `shutil.rmtree()` before `os.makedirs()` when the operation is meant to produce a fresh result. exist_ok=True is for "create if missing", not "clean and recreate".

### 2. Assuming extraction failure = tool limitation
- **What was done:** When GL-RM10 failed, we spent time researching RKFW-specific tools (afptool, Python parsers) and reverse-engineering the header format.
- **Failure mode:** Wasted 30+ minutes of research and implementation before discovering the real cause was directory pollution, not tool capability.
- **Evidence:** RKFW header parsing was unnecessary — binwalk/unblob handled the format fine on a clean directory.
- **How to avoid:** Always test with a clean state before adding format-specific tooling. The simplest hypothesis (environment issue) should be tested first.

### 3. Bare except blocks that swallow errors
- **What was done:** Exception handler for background task status update used nested try/except with bare except
- **Failure mode:** If the status update fails (DB connection lost, transaction conflict), the error is silently logged and the project stays stuck at "unpacking" forever
- **Evidence:** Project c5d129f2 was stuck at "unpacking" for 10+ hours with no error visible
- **How to avoid:** Use finally blocks for guaranteed cleanup. Never nest try/except for critical state management — use a single finally.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Add unblob as fallback, not replace binwalk | Binwalk is faster for known formats; unblob handles the long tail | Correct — binwalk succeeded on GL-RM10, unblob was backup |
| Clean extraction dir before every attempt | Prevents state pollution from prior failures | Correct — fixes the actual root cause |
| finally block instead of nested try/except | Guarantees status reset even if cleanup code fails | Correct — simpler, more reliable |
| Wrap ZIP detection in try/except | Corrupted ZIPs shouldn't crash upload flow | Correct — defense in depth |
| Write pure Python RKFW parser | RKFW format is simple (~80 lines) | Unnecessary — existing tools handle it fine |
| Keep Android fast path alongside fallback | Android extraction is optimized (partition naming, etc.) | Correct — fast paths for known, fallback for unknown |
