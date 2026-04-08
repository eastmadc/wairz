# Patterns: Session 17 — Dependency Hygiene & Campaign Verification

> Extracted: 2026-04-07
> Campaigns: UEFI Firmware Support (completed), Network Protocol Analysis (created)
> Postmortem: none (session-level extraction)

## Successful Patterns

### 1. Dependency Audit via Import Scanning
- **Description:** When one missing dependency was found (androguard), systematically scanned ALL backend Python files for `try/except ImportError` patterns to find other missing deps. Found lz4 and setools.
- **Evidence:** Session 17 — androguard fix led to discovery of 2 more missing packages
- **Applies when:** Fixing a missing dependency. Always check for similar gaps across the codebase.

### 2. Graceful Degradation Pattern Reveals Missing Deps
- **Description:** Code using `try: import X; except ImportError: return error_message` is a signal that the dependency may not be declared in pyproject.toml. These patterns work at runtime but hide missing declarations.
- **Evidence:** androguard, lz4, setools all used this pattern — tools "worked" (returned helpful errors) but the features were silently disabled.
- **Applies when:** Adding new optional dependencies to Python projects. The try/except is good for runtime resilience but the dep must still be declared.

### 3. Docker Rebuild + Recreate (Not Just Restart)
- **Description:** `docker compose restart` does NOT pick up new images. Must use `docker compose up -d` after `docker compose build` to recreate containers with new images.
- **Evidence:** Session 17 — androguard showed as missing after `restart`, only worked after `up -d` which recreated the container.
- **Applies when:** Any backend dependency change requires build + up, not build + restart.

### 4. System vs Venv Python Version Mismatch
- **Description:** apt-installed Python packages (e.g., python3-setools) install for the system Python (3.13 on Debian Trixie), but the app runs in a uv venv using Python 3.12. System packages are invisible to the venv.
- **Evidence:** python3-setools installed via apt but import failed in venv — different Python versions.
- **Applies when:** Adding Python dependencies via apt in the Dockerfile. If the app runs in a venv, apt packages won't be visible unless they're pure Python and symlinked.

### 5. Real Firmware Verification Completes Campaigns
- **Description:** UEFI campaign had 3 build phases complete but was blocked for weeks on Phase 4 (real firmware test). User uploading actual D3633-S1.ROM and running tools verified the entire pipeline end-to-end in minutes.
- **Evidence:** 18 firmware volumes, 550 UEFI modules, VulHunt scan on 684 binaries — all worked first try.
- **Applies when:** Build campaigns with a "verify with real data" phase should flag what test data is needed early, so it doesn't become a long-term blocker.

### 6. Fix Data at the Source, Not the Frontend
- **Description:** Dropdown white-on-white bug was caused by `bg-transparent` on a native `<select>` element in dark theme. Fixed with `bg-background text-foreground` on both select and option elements.
- **Evidence:** ToolForm.tsx select dropdown — browser renders native options with OS default colors, conflicting with dark theme inherited text color.
- **Applies when:** Using native HTML select/option elements in dark-themed apps. Always set explicit background + text colors on both the select AND option elements.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Add androguard to pyproject.toml (not Dockerfile pip) | It's a regular Python dep used by the app, belongs in the dependency list | Worked — installed in venv via uv sync |
| Add lz4 to pyproject.toml | Pure Python, pip-installable, used by unpack_android.py | Worked |
| Keep setools as apt install, accept graceful degradation | setools not on PyPI (only 1.2.3), built for system Python, code has CLI fallback | Acceptable — CIL parsing fallback works |
| Scapy over pyshark for network analysis | Pure Python, no tshark binary needed, 200+ protocols including IoT (MQTT, CoAP) | Campaign decision, not yet validated |
| PcapReader iterator over rdpcap | Memory safety — rdpcap loads entire pcap, PcapReader streams | Campaign decision |
| Network Protocol Analysis as 3-phase Archon campaign | Large scope (~13h), cross-cutting (backend + frontend + Docker), needs persistence | Correct routing — too large for marshal |
