# Anti-patterns: UEFI Firmware Support Campaign

> Extracted: 2026-04-04
> Campaign: .planning/campaigns/uefi-firmware-support.md

## Failed Patterns

### 1. Assuming Binary Names Match Project Names
- **What was done:** Dockerfile used `cp UEFIExtract/UEFIExtract` (uppercase) but cmake built `UEFIExtract/uefiextract` (lowercase).
- **Failure mode:** Binary silently missing from /usr/local/bin. Container starts fine but tool not found at runtime.
- **Evidence:** 3 Docker rebuild cycles wasted. `find -name "UEFIExtract" -type f -executable` matched the directory, not the binary.
- **How to avoid:** After building from source, always `ls` the build output directory to verify actual binary names. Use `file` command to confirm it's an executable, not a directory.

### 2. Purging Build Dependencies in Same Docker Layer
- **What was done:** `apt-get purge -y cmake qt6-base-dev && apt-get autoremove -y` after building UEFIExtract.
- **Failure mode:** `autoremove` cascaded removal of shared libraries (libQt6Core, etc.) that UEFIExtract dynamically links against. Binary exists but segfaults or is missing.
- **Evidence:** Binary present in image but not executable. Discovered only after 2nd full rebuild.
- **How to avoid:** Either (a) build statically, (b) use multi-stage Docker build with only runtime libs in final stage, or (c) keep build deps if the image size penalty is acceptable. For tools built from source, always verify the binary runs (`tool --version`) AFTER the purge step.

### 3. Indentation Error in Inline Endpoint Code
- **What was done:** Section-scanning loop in the UEFI modules REST endpoint was accidentally dedented, running outside the main module loop.
- **Failure mode:** Endpoint returned only 1 module instead of 546. No error, just silently wrong data.
- **Evidence:** Frontend showed 1 module. API returned `total=1`. Root cause: Python indentation sensitivity + large inline function.
- **How to avoid:** For complex endpoint logic, extract into a separate service function (testable independently). Always verify endpoint output matches expected count before shipping.

### 4. Assuming Docker Images Have Basic Shell Utilities
- **What was done:** Used `sleep infinity` then `tail -f /dev/null` as container entrypoints for VulHunt.
- **Failure mode:** Minimal Rust-based container image has no `sleep`, `tail`, `ls`, `sh` — only the `vulhunt-ce` binary.
- **Evidence:** 3 entrypoint attempts failed before using `vulhunt-ce mcp` as a long-running process.
- **How to avoid:** For third-party minimal images, check what binaries exist before assuming POSIX utilities. Use the tool's own long-running mode (server, daemon, mcp) as the entrypoint.

### 5. Docker Exec From Inside Another Container
- **What was done:** `vulhunt.py` used `docker exec -i wairz-vulhunt-1 vulhunt-ce scan ...` to run scans.
- **Failure mode:** Backend container doesn't have `docker` CLI installed. Error: `[Errno 2] No such file or directory`.
- **Evidence:** REST endpoint returned error immediately. Only caught when testing from the UI (MCP testing was done from the host).
- **How to avoid:** Never use `docker exec` from within a container unless docker CLI is explicitly installed AND the docker socket is mounted. Prefer HTTP/gRPC/MCP network communication between containers.

### 6. Testing Only From Host, Not From Container
- **What was done:** VulHunt CLI tested via `docker exec` from the host terminal. Assumed it would also work from the backend container.
- **Failure mode:** Host has docker CLI, backend container doesn't. Same command, different environments.
- **Evidence:** All manual tests passed on host. First real UI request failed.
- **How to avoid:** Always test the full path: UI → frontend → backend → sidecar. A passing host test does NOT validate the containerized path.

### 7. Stale Master Plan After Implementation
- **What was done:** Master plan listed Phase 1-3 as "not started" but they were all implemented in a previous commit (24b6555).
- **Failure mode:** Almost started a campaign to implement already-completed work. Wasted investigation time.
- **Evidence:** User asked to "run Phase 1 as a campaign" — research revealed all items already shipped.
- **How to avoid:** After any implementation session, update the master plan status. Check git log before starting any campaign from a plan document.
