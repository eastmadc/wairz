# Anti-patterns: Security Hardening Campaign

> Extracted: 2026-04-10
> Campaign: .planning/campaigns/security-hardening.md

## Failed Patterns

### 1. Deferring Dockerfile Changes Blocks Dependent Phases
- **What was done:** Phase 1 (YARA scanning) required yara-python, which has C dependencies needing Dockerfile changes. Phase 1 was deferred because Dockerfile modifications were out of scope for the session.
- **Failure mode:** YARA scanning was blocked until a later session (session 5) when Dockerfile work was naturally in scope. The campaign shipped as "completed (YARA deferred)" — a partial completion that required tracking.
- **Evidence:** Campaign status: "completed (YARA deferred)." Phase 1 status: "deferred (needs yara-python dep + Dockerfile change)."
- **How to avoid:** When planning a campaign, check if any phase requires Dockerfile/container changes. If so, either: (a) include Dockerfile work in the campaign scope upfront, or (b) structure phases so container-dependent work is Phase 1, not a later phase that blocks integration testing.

### 2. Embedding Rules as Code Constants at Scale
- **What was done:** YARA rules were embedded as Python string constants rather than external .yar files.
- **Failure mode:** Worked well at 26 rules, but later sessions added YARA Forge community rules (thousands of rules) via external files. The embedded approach wouldn't have scaled.
- **Evidence:** Decision Log: "simpler deployment, no file management." But session 20 added extra_rules_dir support for YARA Forge with 10K+ rules.
- **How to avoid:** Embedding is fine for <50 hand-written rules that ship with the tool. But always build the external-file loading path too (extra_rules_dir parameter), because community rule packs will follow. Both patterns coexist well.

### 3. Testing Without the Deferred Dependency
- **What was done:** Phase 4 (verify) ran unit tests but skipped YARA compilation tests because yara-python wasn't installed (Phase 1 deferred).
- **Failure mode:** No immediate failure, but the test suite had a gap. When YARA was added in session 5, compilation issues were caught late.
- **Evidence:** Phase 4 status: "done (24 tests, YARA compile skipped — Phase 1 deferred)."
- **How to avoid:** When deferring a phase, add a clearly-marked skipped test with a TODO referencing the deferred phase. This ensures the gap is visible and gets addressed when the phase is completed.
