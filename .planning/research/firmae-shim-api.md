# FirmAE Flask API Shim Design

> Companion to: `firmae-integration-brief.md`
> Purpose: Detailed API specification for the Flask shim that wraps FirmAE inside the sidecar container.

---

## Overview

The shim is a lightweight Flask application running inside the FirmAE sidecar container. It translates REST/WebSocket requests from the Wairz backend into FirmAE pipeline operations, manages the QEMU subprocess lifecycle, and streams progress events back to the caller.

```
Wairz Backend                FirmAE Sidecar Container
+----------------+          +-----------------------------------+
| emulation_svc  | ---HTTP-->| Flask Shim (:5000)               |
|                | <--JSON---|                                   |
|                |          | FirmAE scripts (run.sh pipeline)  |
|                | ---WS--->| QEMU serial console (socat)       |
+----------------+          +-----------------------------------+
```

The shim runs on port 5000 inside the sidecar. The Wairz backend communicates with it via the Docker network.

---

## 1. Endpoint Specifications

### POST /start

Initiates a full FirmAE emulation pipeline for a firmware blob.

**Request:**
```json
{
  "firmware_path": "/firmwares/abc123.bin",
  "brand": "dlink",
  "mode": "run",
  "arbitration": {
    "boot": true,
    "network": true,
    "nvram": true,
    "kernel": true,
    "etc": true
  },
  "timeout": 240,
  "check_timeout": 360,
  "session_id": "uuid-from-wairz"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `firmware_path` | string | yes | Path to firmware blob inside the container (mounted volume) |
| `brand` | string | yes | Vendor name (used by FirmAE for brand-specific heuristics) |
| `mode` | string | no | `"run"` (default), `"check"`, `"analyze"`, `"debug"` |
| `arbitration` | object | no | Override individual FIRMAE_* flags. Defaults: all true. |
| `timeout` | int | no | Boot timeout in seconds. Default: 240 |
| `check_timeout` | int | no | Service check timeout in seconds. Default: 360 |
| `session_id` | string | no | Wairz-assigned ID for correlation. Auto-generated if omitted. |

**Response (202 Accepted):**
```json
{
  "session_id": "uuid",
  "iid": null,
  "status": "queued",
  "message": "Pipeline started"
}
```

The pipeline runs asynchronously. Poll `/status` or subscribe to `/events` for progress.

**Behavior:**
1. Validates firmware_path exists and is readable
2. Writes arbitration flags to a temp `firmae.config` override
3. Spawns `run.sh -r <brand> <firmware_path>` as a subprocess
4. Returns immediately with 202

---

### GET /status

Returns current pipeline state and discovered information.

**Response (200 OK):**
```json
{
  "session_id": "uuid",
  "iid": 1,
  "status": "running",
  "phase": "emulation",
  "phase_detail": "QEMU booted, waiting for network",
  "arch": "mipseb",
  "kernel_version": "2.6",
  "guest_ips": ["192.168.0.1"],
  "network_reachable": true,
  "web_reachable": false,
  "uptime_seconds": 45,
  "qemu_pid": 12345,
  "serial_socket": "/tmp/qemu.1.S1",
  "monitor_socket": "/tmp/qemu.1",
  "error": null,
  "timestamps": {
    "started": "2026-04-05T12:00:00Z",
    "extraction_done": "2026-04-05T12:01:30Z",
    "image_ready": "2026-04-05T12:02:15Z",
    "boot_started": "2026-04-05T12:02:16Z",
    "network_up": "2026-04-05T12:03:30Z"
  }
}
```

**Status values:**

| Status | Description |
|--------|-------------|
| `queued` | Request received, not yet started |
| `extracting` | binwalk extraction in progress |
| `detecting_arch` | Architecture detection running |
| `preparing_image` | Disk image creation + fixups |
| `booting` | QEMU launched, waiting for boot |
| `checking_network` | Ping/web reachability tests |
| `running` | Emulation up and services accessible |
| `partial` | Booted but no web service detected |
| `failed` | Pipeline failed (see `error` field) |
| `stopped` | Cleanly shut down |

---

### GET /ports

Discovers open TCP ports on the emulated firmware.

**Response (200 OK):**
```json
{
  "session_id": "uuid",
  "guest_ips": ["192.168.0.1"],
  "scan_method": "nmap",
  "ports": [
    {
      "ip": "192.168.0.1",
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "banner": "GoAhead-Webs"
    },
    {
      "ip": "192.168.0.1",
      "port": 23,
      "protocol": "tcp",
      "state": "open",
      "service": "telnet",
      "banner": ""
    },
    {
      "ip": "192.168.0.1",
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "https",
      "banner": ""
    }
  ],
  "scan_time_ms": 3200
}
```

**Behavior:**
1. Requires status == `running` or `partial`
2. Runs `nmap -sV -T4 --top-ports 1000 <guest_ip>` against each discovered IP
3. Parses nmap XML output for port/service/banner info
4. Caches result for 30 seconds (port state unlikely to change rapidly)

---

### POST /stop

Gracefully shuts down the emulation and cleans up all resources.

**Request:**
```json
{
  "force": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `force` | bool | If true, sends SIGKILL immediately. If false, tries SIGTERM first with 10s grace period. |

**Response (200 OK):**
```json
{
  "session_id": "uuid",
  "status": "stopped",
  "cleanup": {
    "qemu_killed": true,
    "tap_interfaces_removed": 4,
    "image_deleted": true,
    "scratch_deleted": true
  }
}
```

**Cleanup sequence:**
1. Kill QEMU process (SIGTERM, wait 10s, then SIGKILL)
2. Kill any child processes in the process group
3. Remove TAP interfaces: `tunctl -d tap${IID}_N` for N in 0..3
4. Unmount disk image: run `scripts/umount.sh`
5. Delete scratch directory: `rm -rf scratch/${IID}/`
6. Delete disk image: `rm -f images/${IID}.tar.gz images/${IID}.kernel`
7. Remove database entry: `DELETE FROM image WHERE id=${IID}`
8. Remove temp files: `rm -f /tmp/qemu.${IID}*`

---

### WebSocket /console

Provides interactive serial console access to the emulated firmware.

**Connection:** `ws://<sidecar>:5000/console?session_id=<uuid>`

**Protocol:**
```
Client -> Server (text frame):  { "type": "input", "data": "ls -la\n" }
Client -> Server (text frame):  { "type": "resize", "cols": 120, "rows": 40 }
Server -> Client (text frame):  { "type": "output", "data": "drwxr-xr-x ..." }
Server -> Client (text frame):  { "type": "disconnect", "reason": "QEMU exited" }
```

**Implementation:**
- The shim uses `socat` to bridge the QEMU serial unix socket (`/tmp/qemu.${IID}.S1`) to the WebSocket
- Input is written to the socket; output is read and forwarded
- A background asyncio task reads from the serial socket and pushes to all connected WebSocket clients
- On QEMU exit, sends `disconnect` frame and closes the WebSocket

**Fallback:** If serial socket is not available (QEMU hasn't booted yet), the shim queues input and delivers it when the socket becomes available, or returns an error frame:
```json
{ "type": "error", "message": "Serial console not yet available, QEMU is still booting" }
```

---

### GET /nvram

Retrieves the current NVRAM key-value state from the emulated firmware.

**Query Parameters:**
- `key` (optional): Return only this specific key
- `prefix` (optional): Return keys matching this prefix

**Response (200 OK):**
```json
{
  "session_id": "uuid",
  "nvram_path": "/firmadyne/libnvram",
  "entries": {
    "lan_ipaddr": "192.168.0.1",
    "lan_netmask": "255.255.255.0",
    "wan_proto": "dhcp",
    "http_passwd": "admin",
    "wl0_ssid": "MyRouter"
  },
  "override_count": 12,
  "total_count": 87
}
```

**Implementation:**
1. Mount the QEMU disk image (or access via serial console)
2. Read files from `/firmadyne/libnvram/` directory (each file is one key-value pair: filename = key, content = value)
3. Read overrides from `/firmadyne/libnvram.override/`
4. Merge and return

**Alternative approach:** Execute `ls /firmadyne/libnvram/ && cat /firmadyne/libnvram/*` via the serial console if the emulation is running.

---

### POST /capture

Starts or stops network traffic capture (pcap) on the emulated firmware's TAP interface.

**Request:**
```json
{
  "action": "start",
  "interface": "tap1_0",
  "filter": "tcp port 80",
  "max_packets": 10000,
  "max_duration_seconds": 300
}
```

**Response (200 OK, action=start):**
```json
{
  "session_id": "uuid",
  "capture_id": "cap-uuid",
  "status": "capturing",
  "interface": "tap1_0",
  "pcap_path": "/captures/cap-uuid.pcap"
}
```

**Request (stop):**
```json
{
  "action": "stop",
  "capture_id": "cap-uuid"
}
```

**Response (200 OK, action=stop):**
```json
{
  "capture_id": "cap-uuid",
  "status": "complete",
  "pcap_path": "/captures/cap-uuid.pcap",
  "packets_captured": 1523,
  "file_size_bytes": 245760
}
```

**Implementation:**
- Uses `tcpdump -i <interface> -w <pcap_path> <filter>` as a subprocess
- Tracks capture PIDs for stop/cleanup
- Pcap files stored in a mounted volume accessible to the Wairz backend
- Automatic cleanup on `/stop` or container shutdown

---

### GET /events (Server-Sent Events)

Streams real-time pipeline progress events.

**Connection:** `GET /events?session_id=<uuid>`

**Response:** `text/event-stream`

```
event: phase_change
data: {"phase": "extracting", "timestamp": "2026-04-05T12:00:01Z"}

event: phase_change
data: {"phase": "detecting_arch", "timestamp": "2026-04-05T12:01:31Z", "detail": "Found mipseb from /bin/busybox"}

event: arch_detected
data: {"arch": "mipseb", "endian": "big", "kernel": "vmlinux.mipseb.2"}

event: phase_change
data: {"phase": "preparing_image", "timestamp": "2026-04-05T12:01:35Z"}

event: phase_change
data: {"phase": "booting", "timestamp": "2026-04-05T12:02:16Z", "qemu_pid": 12345}

event: network_up
data: {"ip": "192.168.0.1", "ping_ms": 2.3}

event: service_detected
data: {"ip": "192.168.0.1", "port": 80, "service": "http"}

event: phase_change
data: {"phase": "running", "timestamp": "2026-04-05T12:03:45Z"}

event: error
data: {"phase": "extracting", "message": "binwalk failed: unsupported format", "fatal": true}
```

---

## 2. Pipeline Stage Events

### Event Schema

All events follow this base structure:

```json
{
  "session_id": "uuid",
  "timestamp": "ISO-8601",
  "event_type": "string",
  "phase": "string",
  "data": {}
}
```

### Event Types

| Event Type | Phase | Data Fields | Description |
|-----------|-------|-------------|-------------|
| `pipeline_started` | `queued` | `firmware_path`, `brand`, `mode` | Pipeline accepted and queued |
| `phase_change` | any | `phase`, `detail` | Phase transition |
| `extraction_progress` | `extracting` | `files_found`, `rootfs_found`, `kernel_found` | Extraction progress |
| `extraction_complete` | `extracting` | `iid`, `rootfs_extracted`, `kernel_extracted`, `tarball_size_bytes` | Extraction finished |
| `arch_detected` | `detecting_arch` | `arch`, `endian`, `source_binary`, `kernel_version` | Architecture identified |
| `image_ready` | `preparing_image` | `image_path`, `image_size_bytes`, `injected_tools` | QEMU disk image created |
| `qemu_started` | `booting` | `qemu_pid`, `qemu_cmd`, `serial_socket`, `monitor_socket` | QEMU process launched |
| `serial_output` | `booting` | `line` | Serial console output line (opt-in, high volume) |
| `network_up` | `checking_network` | `ip`, `ping_ms` | Guest responds to ping |
| `service_detected` | `checking_network` | `ip`, `port`, `service` | TCP service found |
| `emulation_ready` | `running` | `guest_ips`, `services` | Emulation fully up |
| `emulation_partial` | `partial` | `guest_ips`, `reason` | Boot succeeded, no web service |
| `error` | any | `message`, `fatal`, `stderr_tail` | Error occurred |
| `stopped` | `stopped` | `reason`, `cleanup_summary` | Emulation shut down |

### Phase Transition Diagram

```
queued -> extracting -> detecting_arch -> preparing_image -> booting -> checking_network -> running
                                                                                       \-> partial
     \-> failed (from any phase)                                                        \-> failed
```

---

## 3. Error Handling

### Failure Modes by Phase

#### Extraction Phase
| Error | Cause | HTTP | Recovery |
|-------|-------|------|----------|
| `extraction_failed` | binwalk cannot parse firmware format | 422 | None -- firmware not supported |
| `no_rootfs` | Extraction succeeded but no Linux rootfs found (< 4 standard dirs) | 422 | Try different firmware |
| `no_kernel` | Rootfs found but no kernel image | Warning | FirmAE uses pre-built kernel |
| `extraction_timeout` | binwalk hung (> 300s) | 504 | Retry with simpler firmware |

#### Architecture Detection
| Error | Cause | HTTP | Recovery |
|-------|-------|------|----------|
| `arch_unsupported` | Detected arch not in {armel, mipseb, mipsel} | 422 | None for FirmAE; use Wairz user-mode for aarch64/x86 |
| `no_elf_binaries` | No ELF executables found in rootfs | 422 | Firmware may be encrypted or non-Linux |
| `arch_detection_failed` | `file` command returned no usable output | 500 | Bug -- investigate |

#### Image Preparation
| Error | Cause | HTTP | Recovery |
|-------|-------|------|----------|
| `image_creation_failed` | `qemu-img` or `fdisk` failed | 500 | Disk full or QEMU not installed |
| `mount_failed` | `kpartx` or `mount` failed (permissions) | 500 | Container not privileged enough |
| `fix_image_failed` | `fixImage.sh` error | 500 | Investigate specific error |

#### Emulation
| Error | Cause | HTTP | Recovery |
|-------|-------|------|----------|
| `qemu_crash` | QEMU process exited with non-zero code | 500 | Check serial log for kernel panic |
| `boot_timeout` | No network after TIMEOUT seconds | 504 | Increase timeout; try different kernel version |
| `no_web_service` | Ping works but no HTTP | 200 (partial) | Not fatal -- firmware may not have web UI |
| `network_collision` | TAP interface conflict | 500 | IID collision -- restart with unique IID |

### Error Response Format

All error responses use a consistent structure:

```json
{
  "session_id": "uuid",
  "status": "failed",
  "error": {
    "code": "extraction_failed",
    "message": "binwalk could not extract rootfs from firmware",
    "phase": "extracting",
    "fatal": true,
    "detail": "No valid Linux root filesystem found (0/4 standard directories)",
    "stderr_tail": "Last 20 lines of stderr...",
    "serial_tail": "Last 50 lines of serial output (if available)..."
  }
}
```

### Timeout Strategy

| Phase | Default Timeout | Configurable | Action on Timeout |
|-------|----------------|--------------|-------------------|
| Extraction | 300s | No (hardcoded in binwalk) | Kill binwalk, report error |
| Arch detection | 30s | No | Kill, report error |
| Image prep | 120s | No | Kill, report error |
| QEMU boot | 60-240s | Yes (`timeout` param) | Kill QEMU, report timeout |
| Service check | 60-360s | Yes (`check_timeout` param) | Mark as partial, keep running |

---

## 4. Port Discovery

### Primary Method: nmap

After emulation reaches `running` or `partial` status, the shim can scan for open ports.

```bash
nmap -sV -T4 --top-ports 1000 -oX /tmp/scan.xml <guest_ip>
```

**Why nmap over alternatives:**
- Already installed by FirmAE's `install.sh`
- Service version detection (`-sV`) identifies what's running
- Banner grabbing provides useful context
- XML output (`-oX`) is easy to parse programmatically

### Fallback Method: Direct TCP Connect

If nmap is unavailable or too slow, use a Python-native scan:

```python
import socket

def scan_port(ip, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0
```

Scan common IoT ports: 21, 22, 23, 25, 53, 80, 443, 554, 8080, 8443, 8888, 49152.

### Scan Trigger Points

| Trigger | When | Behavior |
|---------|------|----------|
| Automatic | `running` status reached | Scan top 100 ports, cache result |
| On-demand | `GET /ports` called | Full 1000-port scan (or cached) |
| Periodic | Every 60s while running | Quick re-scan of known-open ports |

### Port Mapping to Wairz Frontend

The Wairz backend maps discovered ports to forwarded ports via Docker network:

```
Guest 192.168.0.1:80  ->  TAP bridge  ->  Sidecar container  ->  Docker network  ->  Wairz backend
```

Since the sidecar container shares a Docker network with the Wairz backend, the guest IPs are reachable directly from the backend (the sidecar's network stack has the TAP routes). The backend can proxy or provide direct URLs.

---

## 5. Process Management

### Architecture

The Flask shim manages a tree of processes:

```
Flask shim (PID 1 or gunicorn)
  |
  +-- Postgres (managed by pg_ctl)
  |
  +-- Pipeline subprocess (run.sh)
       |
       +-- binwalk (extraction)
       +-- getArch.py
       +-- makeImage.sh
       |    +-- qemu-img, fdisk, mount, kpartx
       +-- QEMU (long-running)
       +-- check_emulation.sh
            +-- ping, curl/wget
```

### Subprocess Lifecycle

#### Startup Sequence

```python
# 1. Start Postgres (must be ready before FirmAE)
subprocess.Popen(["pg_ctl", "start", "-D", PG_DATA, "-l", PG_LOG])
wait_for_postgres(timeout=10)

# 2. Initialize FirmAE database (idempotent)
subprocess.run(["psql", "-U", "firmadyne", "-d", "firmware", "-f", "database/schema"])

# 3. Write config overrides
write_firmae_config(arbitration_flags, timeouts)

# 4. Launch pipeline
pipeline = subprocess.Popen(
    ["bash", "run.sh", "-r", brand, firmware_path],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    preexec_fn=os.setsid  # New process group for clean kill
)
```

#### Progress Monitoring

The shim monitors pipeline progress by:

1. **Parsing stdout/stderr** of `run.sh` for phase markers:
   - `"Tag: <iid>"` -- extraction assigned IID
   - `"getArch.py"` output -- architecture detected
   - `"qemu-system-"` in process list -- QEMU started
   - `"Network reachable"` -- ping success
   - `"Web service on"` -- HTTP detected

2. **Polling filesystem** for state files:
   - `scratch/${IID}/` exists -- extraction started
   - `images/${IID}.tar.gz` exists -- extraction complete
   - `scratch/${IID}/image.raw` exists -- image created
   - `scratch/${IID}/qemu.initial.serial.log` exists -- QEMU booted
   - `scratch/${IID}/ip.0` exists -- network configured
   - `scratch/${IID}/emulation.log` exists -- check complete

3. **Polling processes** for QEMU PID:
   - `pgrep -f "qemu-system.*${IID}"` -- QEMU running
   - Check `/tmp/qemu.${IID}.S1` socket exists -- serial ready
   - Check `/tmp/qemu.${IID}` socket exists -- monitor ready

#### Graceful Shutdown

```python
def stop_emulation(force=False):
    cleanup = {}

    # 1. Kill QEMU process group
    if pipeline and pipeline.poll() is None:
        if force:
            os.killpg(os.getpgid(pipeline.pid), signal.SIGKILL)
        else:
            os.killpg(os.getpgid(pipeline.pid), signal.SIGTERM)
            try:
                pipeline.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(pipeline.pid), signal.SIGKILL)
        cleanup["qemu_killed"] = True

    # 2. Kill any remaining QEMU processes (belt and suspenders)
    subprocess.run(["pkill", "-f", f"qemu-system.*{iid}"])

    # 3. Run FirmAE cleanup
    subprocess.run(["bash", "scripts/delete.sh", str(iid)])
    cleanup["tap_interfaces_removed"] = 4
    cleanup["image_deleted"] = True
    cleanup["scratch_deleted"] = True

    # 4. Clean database
    subprocess.run(["psql", "-U", "firmadyne", "-d", "firmware",
                     "-c", f"DELETE FROM image WHERE id={iid}"])

    return cleanup
```

#### Crash Recovery

If the Flask shim receives SIGTERM (container stop):

```python
import atexit, signal

def cleanup_on_exit(signum=None, frame=None):
    """Kill all child processes and clean up resources."""
    # Kill entire process group
    try:
        os.killpg(os.getpgid(0), signal.SIGTERM)
    except ProcessLookupError:
        pass

    # Clean up TAP interfaces
    for i in range(4):
        subprocess.run(["tunctl", "-d", f"tap{iid}_{i}"], capture_output=True)

    # Stop Postgres
    subprocess.run(["pg_ctl", "stop", "-D", PG_DATA, "-m", "fast"])

atexit.register(cleanup_on_exit)
signal.signal(signal.SIGTERM, cleanup_on_exit)
signal.signal(signal.SIGINT, cleanup_on_exit)
```

### Concurrency Model

The shim supports **one emulation session per container**. This simplifies:
- Resource management (one QEMU, one set of TAP interfaces)
- Process tracking (single pipeline subprocess)
- Cleanup (kill everything on stop)

For parallel emulation, Wairz spins up multiple sidecar containers, each with its own session. This matches FirmAE's own `docker-helper.py` pattern of one-container-per-firmware.

### Health Check

The shim exposes a simple health endpoint:

```
GET /health

Response: { "status": "healthy", "postgres": "up", "session_active": true, "uptime_seconds": 300 }
```

Docker health check:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1
```

---

## Appendix A: Complete Endpoint Summary

| Method | Path | Description | Status When Valid |
|--------|------|-------------|-------------------|
| POST | `/start` | Start FirmAE pipeline | No active session |
| GET | `/status` | Get current state | Any |
| GET | `/ports` | Scan for open ports | running, partial |
| POST | `/stop` | Stop and clean up | Any active session |
| WS | `/console` | Serial console | booting, running, partial |
| GET | `/nvram` | Read NVRAM state | running, partial |
| POST | `/capture` | Start/stop pcap | running, partial |
| GET | `/events` | SSE progress stream | Any active session |
| GET | `/health` | Container health | Always |

## Appendix B: Sidecar Container Outline

```dockerfile
FROM ubuntu:20.04

# Install FirmAE dependencies (from install.sh)
RUN apt-get update && apt-get install -y \
    python3 python3-pip postgresql postgresql-client \
    qemu-system-arm qemu-system-mips qemu-utils \
    busybox-static bash-static binwalk nmap socat tcpdump \
    kpartx uml-utilities util-linux net-tools iproute2 iptables \
    ...

# Install Flask shim
RUN pip3 install flask flask-sock gunicorn

# Copy FirmAE
COPY FirmAE/ /work/FirmAE/

# Copy pre-built kernels and binaries
COPY binaries/ /work/FirmAE/binaries/

# Copy shim
COPY shim/ /work/shim/

# Init Postgres data directory
RUN pg_ctl init -D /var/lib/postgresql/data

EXPOSE 5000
HEALTHCHECK --interval=30s CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/work/shim/entrypoint.sh"]
```

Entrypoint:
```bash
#!/bin/bash
# Start Postgres
pg_ctl start -D /var/lib/postgresql/data -l /var/log/postgresql.log
sleep 2

# Init FirmAE database (idempotent)
psql -U firmadyne -d firmware -f /work/FirmAE/database/schema 2>/dev/null || true

# Start Flask shim
exec gunicorn -w 1 -b 0.0.0.0:5000 --timeout 600 shim:app
```

## Appendix C: Wairz Backend Integration Points

The Wairz backend's `emulation_service.py` will gain a new method:

```python
async def start_firmae_session(self, firmware: Firmware, brand: str, ...):
    # 1. Create sidecar container via Docker SDK
    container = docker_client.containers.run(
        image="wairz-firmae:latest",
        detach=True,
        privileged=True,  # or use cap_add for minimum caps
        network="emulation_net",
        volumes={
            firmware_dir: {"bind": "/firmwares", "mode": "ro"},
            capture_dir: {"bind": "/captures", "mode": "rw"},
        },
    )

    # 2. Wait for health check
    await wait_for_healthy(container, timeout=15)

    # 3. POST /start to the shim
    shim_url = f"http://{container.name}:5000"
    resp = await httpx.post(f"{shim_url}/start", json={...})

    # 4. Store session in DB with container_id and shim_url
    # 5. Frontend polls /status via backend proxy
```

The existing `EmulationSession` model gains:
- `emulation_type`: `"user"` | `"system"` | `"firmae"`
- `shim_url`: URL of the Flask shim inside the sidecar
- `guest_ips`: List of discovered IPs
- `discovered_ports`: JSON list of port scan results
