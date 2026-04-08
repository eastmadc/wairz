# Patterns: Session 20 (Research + Build)

> Extracted: 2026-04-08
> Session: S20 — cwe_checker, binwalk3, YARA Forge, hardcoded IPs, fuzzy daemons
> Campaign: none (research+build session)
> Postmortem: none

## Successful Patterns

### 1. Parallel Research Before Build
- **Description:** Launched 3 research agents (competitive landscape, codebase health, user workflow) + Ouroboros interview + Citadel fleet simultaneously, then synthesized findings into a prioritized build plan before writing any code.
- **Evidence:** Research completed in ~10 min while session plan was being drafted. All 5 session deliverables were informed by research findings (CRA timeline clarification, Binwalk v3 stability, PyGhidra deferral).
- **Applies when:** Starting a new phase of work with multiple possible directions. Research parallelism is free — spawn scouts while you orient.

### 2. Quick Win First, Then Heavy Lift
- **Description:** Started with Binwalk v3 swap (2h, near-zero risk) and YARA Forge (1h), then moved to cwe_checker sidecar (6h). Early wins built confidence and deployed immediately.
- **Evidence:** Binwalk3 swap verified with real firmware extraction before cwe_checker started. YARA Forge delivered 4,958 rules in <1 hour.
- **Applies when:** Session has multiple items of varying size. Start with the smallest to build momentum and catch blockers early.

### 3. Docker SDK Instead of Docker CLI in Containers
- **Description:** Initial cwe_checker implementation used `asyncio.create_subprocess_exec("docker", ...)` which fails inside the backend container (no `docker` binary). Fixed by switching to the Python Docker SDK (`docker.from_env()`), matching the pattern used by emulation/fuzzing services.
- **Evidence:** `cwe_check_status` returned "Docker check failed: FileNotFoundError" until switched to SDK. Emulation and fuzzing services at `emulation_service.py:253`, `fuzzing_service.py:386` use `client.containers.run()`.
- **Applies when:** Any new Docker integration in the backend. Always use the Python docker SDK, never subprocess calls to the docker CLI.

### 4. Validate External Tool CLI Compatibility Before Swapping
- **Description:** Binwalk v3 removed the `--csv` flag that `firmware_metadata_service.py` relied on. Caught by testing `binwalk3 --csv` which returned "unexpected argument". Fixed by switching to default scan output with whitespace parser.
- **Evidence:** `binwalk3 --csv` returned error code, `binwalk3 --help` showed no `--csv` option. Parser rewritten to handle whitespace-separated + multi-line descriptions + separator lines.
- **Applies when:** Swapping any external tool version (binwalk, Ghidra, radare2, etc.). Always test the exact CLI flags used in the codebase against the new version.

### 5. Rapidfuzz for Variant Name Matching
- **Description:** Used rapidfuzz `token_sort_ratio` to match daemon name variants (version-suffixed, init-script-prefixed) in attack surface scoring. Cleaned names first (strip S50/K20 prefixes, version suffixes), then fuzzy match at 0.80 threshold.
- **Evidence:** 9/9 test cases passed including `lighttpd-1.4.45`, `S50dropbear`, `dropbear_ssh`, `mosquitto_pub`. False positive rate zero for `busybox`, `ls`.
- **Applies when:** Any name-matching against a known set where variants exist. Clean the input first (strip prefixes/suffixes), then fuzzy match. 0.80 threshold is good for binary names.

### 6. Ouroboros Interview for Strategic Scoping
- **Description:** Used Ouroboros MCP interview (7 rounds) to narrow 6+ possible directions into 5 clearly scoped sessions with explicit scope boundaries and deferral list. Ambiguity dropped from initial to 0.20.
- **Evidence:** Interview crystallized: cwe_checker=feature (not compliance), CRA report=full Annex I checklist, firmware update=static detection only, stabilize last. Each session has a named deliverable.
- **Applies when:** Planning multi-session work with competing priorities. Ouroboros forces explicit scope decisions that prevent scope creep.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Stabilize last (S24) not first | Build all features first so stabilization covers tests for ALL new code, README reflects everything | Correct — allows comprehensive integration tests |
| cwe_checker counts as feature, not compliance | It closes the EMBA gap (technical) even though it feeds CRA (compliance). Keeps budget categories honest | Good — compliance sessions stay focused on reporting |
| Static detection only for firmware updates | Full security property analysis too ambitious for 1 session. Catalog first, analyze later | TBD — plan file written, execution in S22 |
| Full CRA Annex I data model (not auto-subset only) | Pentester needs complete checklist even for manual requirements | TBD — plan file written, execution in S23 |
| Use --platform linux/amd64 for cwe_checker | Official image is x86_64-only. QEMU emulation on ARM64 is slow but functional | Works, but analysis is very slow on RPi |
| Defer PyGhidra | Existing GhidraAnalysisCache eliminates repeat latency. PyGhidra only helps first-time-per-binary | Correct — not worth 2-3 sessions when cache works |
