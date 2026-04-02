# Patterns: Device Acquisition v1

> Extracted: 2026-04-02
> Campaign: .planning/campaigns/device-acquisition.md
> Postmortem: none

## Successful Patterns

### 1. Clone existing bridge architecture for new hardware interfaces
- **Description:** The device bridge (wairz-device-bridge.py) was built by cloning the UART bridge pattern exactly: standalone Python script, asyncio TCP server, newline-delimited JSON protocol, id-matched request/response. This made the backend service (device_service.py) nearly identical to uart_service.py.
- **Evidence:** 683-line bridge script completed in one agent pass. Backend service followed uart_service.py pattern with minimal adaptation. All 7 bridge commands worked on first integration test.
- **Applies when:** Adding any new hardware interface to Wairz (Qualcomm EDL, JTAG, SWD, etc.). The bridge pattern is proven and reusable.

### 2. Ouroboros interview + parallel research agents for requirement crystallization
- **Description:** Used Ouroboros Socratic interview to surface ambiguity, then dispatched 8 parallel research agents (2 waves of 4) to debate and converge on answers. Research agents argued options with evidence, producing well-reasoned decisions without requiring the user to manually evaluate every tradeoff.
- **Evidence:** Ambiguity score dropped from 0.47 to 0.15 across 4 interview rounds. Research covered getprop field tiers, dump types, wizard UX, metadata storage, acceptance criteria, security model, and concurrency — all converged within the session.
- **Applies when:** A feature touches multiple domains (backend, frontend, host scripts, database) and has non-obvious design decisions. The "debate, blow up, refine, converge" pattern works especially well when the user wants research-backed decisions rather than picking from menus.

### 3. JSONB column for optional structured metadata
- **Description:** Added a single nullable JSONB column (`device_metadata`) to the existing Firmware table rather than creating a separate table or adding multiple nullable columns. Stored acquisition_method, partition_list, and security_posture as nested JSON.
- **Evidence:** Migration was a single `op.add_column`. No breaking changes. Existing non-Android firmware rows get NULL. Queryable with PostgreSQL JSONB operators.
- **Applies when:** Adding metadata that applies to a subset of records in an existing table. JSONB is ideal when the schema varies by record type (Android vs embedded Linux) and queries on the data are infrequent.

### 4. Parallel phase execution for independent build phases
- **Description:** Phases 1 (DB + parser) and 2 (bridge script) had no dependencies and were delegated to parallel agents in isolated worktrees. Both completed successfully and merged cleanly.
- **Evidence:** Phase 1 completed in 94s, Phase 2 in 175s. No merge conflicts. Combined wall-clock time ~3 minutes vs ~4.5 minutes sequential.
- **Applies when:** Campaign phases have explicit `Deps: none` and touch completely different files. Use worktree isolation to prevent conflicts.

### 5. Mock mode for hardware-dependent features
- **Description:** The bridge script includes a `--mock` flag that returns canned device data, fake getprop output, and writes small test files instead of requiring a real ADB device. This enabled CI testing and development without hardware.
- **Evidence:** All smoke tests and integration verification ran against mock mode. No real Android device needed during development.
- **Applies when:** Any feature that depends on external hardware (devices, serial ports, network equipment). Always build mock mode into the bridge from day one.

### 6. Seed-first, then campaign — structured handoff from interview to execution
- **Description:** Ran Ouroboros interview → generated seed spec → created archon campaign from the seed. The seed captured all decisions with rationale, the campaign decomposed them into executable phases. This prevented the common failure of starting to code before requirements stabilize.
- **Evidence:** All 7 campaign phases completed without rework or direction changes. No phase needed to be rewritten because of missed requirements.
- **Applies when:** Multi-phase features where requirements span multiple system layers. The interview → seed → campaign pipeline catches ambiguity before it becomes wasted code.

### 7. Tiered property parsing with security posture derivation
- **Description:** Instead of parsing only identification fields (model, version), the getprop parser extracts a security posture from properties that most tools ignore: ro.secure, ro.debuggable, ro.adb.secure, verified boot state, SELinux enforcement. These directly inform security assessment.
- **Evidence:** Research agent identified 14 must-have fields (vs the original 5). Security posture fields like ro.secure=0 and ro.boot.selinux=permissive are critical findings in firmware assessment that would have been missed.
- **Applies when:** Parsing any device metadata. Always check for security-relevant properties, not just identification fields.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| ADB root only for v1 | MTKClient requires specific MediaTek hardware in BROM mode — can't gate release on hardware availability | Correct — campaign completed without hardware dependency |
| JSONB column vs separate table | Single nullable column, no breaking migration, queryable; device metadata is 1:1 with firmware | Correct — clean migration, no rework |
| No auth on bridge | Matches UART precedent; local attacker already has Docker socket, STORAGE_ROOT, PostgreSQL access | Correct — consistent with threat model |
| Single connection, multi-device aware | list_devices wraps adb devices (nearly free); device_id on dump commands enables device selection without multi-session complexity | Correct — simple protocol, device selection works |
| Streaming to disk, no buffering | Partitions can be 4-8GB; double-storage would exhaust Pi 5 SD cards | Correct — matches UART bridge's no-buffering pattern |
| Parse all getprop, surface tiered | Full data via API, 14 must-have fields in UI; research showed security posture fields are the biggest gap in existing parsing | Correct — transforms parser from identification to assessment tool |
| 4-step wizard | Research showed 3 too cramped, 5 too granular; no prior art in open-source firmware platforms | Correct — clear step boundaries, natural progression |
| Mock bridge for CI | Can't require real hardware for automated tests; mock mode in bridge script itself | Correct — enabled full development cycle without device |
