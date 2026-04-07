# Patterns: RTOS/Bare-Metal Firmware Recognition

> Extracted: 2026-04-06
> Campaign: `.planning/campaigns/rtos-recognition.md`
> Postmortem: none

## Successful Patterns

### 1. Parallel Research Scouts Before Build
- **Description:** Launched 3 parallel research agents (VxWorks/QNX, FreeRTOS/Zephyr/ThreadX/uC/OS, Companion components/tools) to deeply research detection signatures from source code repos, reverse engineering blogs, and existing tool implementations before writing any code.
- **Evidence:** 253+ web searches across 3 scouts. Discovered critical findings not in the seed: uC/OS task name strings are DEFINITIVE markers (not "Micrium"/"Labrosse" as assumed), SafeRTOS "Wittenstein" string is NOT in compiled binaries, ThreadX `_tx_version_id` is always present. These findings directly shaped the detection tiers.
- **Applies when:** Building detection/classification systems where false positive/negative rates matter. Research the actual binary artifacts from source code, not just documentation.

### 2. Tiered Detection with Confidence Escalation
- **Description:** 5-tier detection where each tier adds confidence: magic bytes (instant) → strings (fast) → symbols (LIEF) → ELF sections → heuristic scanning. Cross-tier corroboration upgrades medium to high confidence.
- **Evidence:** All 8 RTOS targets detectable. Tiers are ordered by speed and reliability — fast reject before expensive analysis. Synthetic test binaries detected correctly.
- **Applies when:** Building any multi-signal classification system. Order checks cheapest-first, let expensive checks only run when cheap ones are inconclusive.

### 3. Standalone Service Module with No Internal Dependencies
- **Description:** `rtos_detection_service.py` imports nothing from other Wairz services. Pure standalone Python with only LIEF as external dep. Called via `run_in_executor()` from async code.
- **Evidence:** 611 lines, clean module boundary. Can be tested independently, no circular imports, easy to mock. Reusable across classify_firmware, SBOM, and MCP tool.
- **Applies when:** Adding a new analysis capability that will be called from multiple integration points. Keep the core logic in a standalone synchronous module.

### 4. Research Codebase Integration Points Before Build
- **Description:** Before launching the build agent, thoroughly read all integration targets: `unpack_common.py` (classify_firmware), `unpack.py` (pipeline), `sbom_service.py` (IdentifiedComponent), `binary.py` (MCP tool registration), `firmware.py` (model). Documented exact line numbers and patterns.
- **Evidence:** Integration was clean — no trial-and-error on where to insert code. The MCP tool, classify_firmware extension, and pipeline wiring all worked on first deployment.
- **Applies when:** Any campaign that wires new functionality into existing systems. Map every integration point before writing code.

### 5. Bug Fix During Campaign Reveals Deeper Issue
- **Description:** User reported 500 error on firmware upload. Initial fix (catch EOFError) was incomplete — deeper investigation revealed the real bug: ZIP path collision where extracted file overwrites source ZIP.
- **Evidence:** First fix (EOFError catch) made upload succeed but produced 0-byte files. Root cause investigation found `_extract_firmware_from_zip` writing to same path as source when inner file has same name (update.zip containing update.zip). Fixed by detecting path collision and using temp suffix.
- **Applies when:** Always investigate WHY an error occurs before patching the symptom. The EOFError was the symptom; the path collision was the disease.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Deep research before build | User requested; detection quality depends on signature accuracy | Discovered 5+ corrections to seed assumptions (Wittenstein unreliable, uC/OS task names definitive, etc.) |
| Component-level detection (per-binary) | Firmware can contain multiple RTOS binaries (coprocessor blobs in /lib/firmware/) | Clean architecture — detect_rtos takes a single file path |
| No Ghidra in hot path | LIEF + strings is 100x faster than Ghidra for batch scanning | Correct — detection runs in seconds, not minutes |
| LIEF lazy-loaded with try/except ImportError | Matches existing binary_analysis_service.py pattern | Works in all environments, graceful degradation |
| Store RTOS metadata as JSON in firmware.os_info Text field | Existing field, no migration needed; JSON serialized to text | Works, though JSONB would be cleaner for queries |
| ZIP path collision fix with .extracted suffix | Simple fix that avoids complex temp directory management | Correct — upload works, file preserved |
