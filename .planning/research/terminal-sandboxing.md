# Research: Terminal Shell Sandboxing (S1)

> Question: What is the best approach to sandbox the Wairz terminal WebSocket shell so it's confined to the firmware extraction directory?
> Date: 2026-04-03
> Confidence: overall HIGH

## Context

The terminal WebSocket (`routers/terminal.py`) spawns `/bin/bash` via PTY fork + execve. It `os.chdir()` to the firmware root but the shell has full host filesystem access — `cd /` escapes immediately. The backend runs inside Docker on an ARM64 RPi5 (kernel 6.12).

## Options Evaluated

### 1. Bubblewrap (bwrap)
**Confidence:** HIGH on ARM64, MEDIUM inside Docker
- Works natively on aarch64
- `apt-get install bubblewrap` in Dockerfile
- Sub-millisecond startup, strong namespace isolation
- **BLOCKER:** Requires `CLONE_NEWUSER` → Docker needs `--cap-add SYS_ADMIN` + `--security-opt seccomp=unconfined`. This significantly weakens the backend container's own isolation.
- Sources: [containers/bubblewrap#505](https://github.com/containers/bubblewrap/issues/505), [ArchWiki](https://wiki.archlinux.org/title/Bubblewrap)

### 2. unshare + chroot
**Confidence:** HIGH feasibility, LOW recommendation
- Same `SYS_ADMIN` requirement as bubblewrap
- Must provide shell binaries inside chroot (firmware has BusyBox ARM, not host bash)
- Reimplements what bubblewrap already does, without safety checks
- **Not recommended** — strictly worse than bubblewrap

### 3. Docker Container Spawn ← RECOMMENDED
**Confidence:** VERY HIGH
- Pattern already proven in `emulation_service.py` lines 874-1044
- `_resolve_host_path()` and volume mount patterns already exist
- Zero new capabilities needed — backend already has Docker socket
- Full isolation: PID, mount, network namespaces + cgroup limits
- 500ms-2s startup latency (acceptable for interactive terminal)
- `network_mode="none"` prevents network escape
- Read-only mount via `{"bind": "/workspace", "mode": "ro"}`
- Alpine image (~3.4MB) keeps overhead minimal
- Sources: existing codebase, [Docker startup study](https://arxiv.org/html/2602.15214v1)

### 4. clone() + pivot_root
**Confidence:** HIGH feasibility, NOT recommended
- Requires ctypes to call Linux syscalls from Python
- Same `SYS_ADMIN` Docker restrictions
- Maintenance nightmare — writing a mini container runtime
- No benefit over bubblewrap

### 5. Landlock + seccomp
**Confidence:** HIGH in theory, BLOCKED on this host
- Zero startup latency, no capabilities needed, works inside Docker
- **BLOCKER:** RPi5 kernel 6.12 has `CONFIG_SECURITY_LANDLOCK is not set`
- Would require custom kernel build or waiting for RPi kernel team to enable it
- Even if available, only restricts filesystem — no PID/mount namespace isolation
- Sources: [landlock.io](https://landlock.io/), [Edward-Knight/landlock](https://github.com/Edward-Knight/landlock)

## Comparison Matrix

| Criterion | Bubblewrap | Docker spawn | Landlock |
|---|---|---|---|
| Security | Strong | **Strong** | Medium-Strong |
| Complexity | Medium | **Low** | Low-Medium |
| Works in Docker | Needs SYS_ADMIN | **Yes (native)** | **Yes** but not on RPi5 |
| Startup latency | <1ms | 500ms-2s | <1ms |
| Codebase precedent | None | **emulation_service** | None |
| New capabilities | SYS_ADMIN | **None** | **None** (if kernel supports) |

## Recommendation

**Docker container spawn** is the clear winner:
1. Zero new capabilities or security posture changes
2. Pattern already battle-tested in emulation_service.py
3. Full namespace isolation (PID, mount, network, cgroup)
4. Works on ARM64 inside Docker without changes
5. The only downside (500ms-2s startup) is acceptable for "user clicks terminal"

### Implementation sketch
```python
# In terminal.py, replace the fork+execve with:
container = client.containers.run(
    image="alpine:3.19",
    command=["sleep", "infinity"],
    detach=True,
    volumes={host_firmware_path: {"bind": "/workspace", "mode": "ro"}},
    working_dir="/workspace",
    mem_limit="256m",
    nano_cpus=int(1e9),
    pids_limit=128,
    network_mode="none",
    labels={"wairz.terminal": str(project_id)},
    remove=True,
)
exec_id = client.api.exec_create(container.id, ["/bin/sh"], tty=True, stdin=True)
sock = client.api.exec_start(exec_id, socket=True, tty=True)
# Proxy sock ↔ WebSocket (same pattern as emulation terminal)
```

## Open Questions

- Should the firmware mount be read-only or read-write? Read-only is safer but prevents users from modifying files for testing.
- Should we use `alpine:3.19` (has standard tools) or `debian:bookworm-slim` (matches emulation base)?
- Container cleanup: use `remove=True` or explicit cleanup in the finally block?
- Should the terminal container image be pre-pulled at backend startup to reduce first-use latency?
