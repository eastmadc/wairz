# Anti-patterns: Session 27 — Generic Binary Version Detection

> Extracted: 2026-04-10
> Commit: cbad4ee on clean-history

## Failed Patterns

### 1. MAX_BINARIES_SCAN too low for real firmware
- **What was done:** Kept the existing `MAX_BINARIES_SCAN = 200` limit unchanged during initial implementation.
- **Failure mode:** rssh at `/usr/bin/rssh` was never scanned because the limit exhausted at `psplash-default` (alphabetically before "r"). The generic detector code was correct but the binary was never processed.
- **Evidence:** Unit test on rssh directly → detected. Full pipeline → not detected. Position counting showed rssh was binary #201+.
- **How to avoid:** When adding new detection capabilities, verify the scan window covers the target. For firmware with 300+ binaries, 200 is too low. Consider dynamic limits or priority-based scanning (high-risk service binaries first).

### 2. Assuming unit test success means pipeline success
- **What was done:** Validated the generic detector by calling `_try_generic_binary_detection()` directly on the rssh binary. It worked. Assumed the full pipeline would also work.
- **Failure mode:** The full pipeline's scanning loop never reached rssh due to MAX_BINARIES_SCAN. The unit test bypassed the loop entirely.
- **Evidence:** Direct call → `rssh 2.3.4` detected. API force_rescan → `rssh None` (from service risk annotation only).
- **How to avoid:** Always test via the actual API endpoint (end-to-end), not just unit-level method calls. The integration gap between "method works" and "pipeline works" is where scanning limits, ordering, and dedup interact.

### 3. False positive from NVD fuzzy matching (shutdown → psshutdown)
- **What was done:** Generic detector found `shutdown 2.86` and NVD fuzzy matching mapped it to `cpe:2.3:a:microsoft:psshutdown:2.86` (Microsoft PsShutdown tool).
- **Failure mode:** The firmware's `shutdown` binary is sysvinit's shutdown, not Microsoft's PsShutdown. NVD fuzzy matching found a close-enough match with confidence 0.89.
- **Evidence:** `shutdown 2.86` promoted to medium confidence with incorrect Microsoft CPE.
- **How to avoid:** Consider adding a "known Linux utilities" exclusion list for generic detections — standard sysvinit/coreutils binaries like shutdown, init, mount should not get generic CPE enrichment unless the match is exact. Or require higher confidence threshold (>0.95) for promoting generic detections.
