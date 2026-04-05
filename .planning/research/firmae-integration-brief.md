# FirmAE Integration Research Brief

> Research date: 2026-04-05
> Source: https://github.com/pr0v3rbs/FirmAE
> License: MIT
> Paper: "FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis" (ACSAC 2020)

---

## 1. FirmAE Pipeline Map

FirmAE's execution is orchestrated by the top-level `run.sh` script, which takes three arguments: `[mode] [brand] [firmware_path]`. The pipeline has four major phases:

### Phase 1: Firmware Extraction (~30-300s)

| Step | Script | What it does |
|------|--------|-------------|
| 1a | `sources/extractor/extractor.py` | Runs binwalk (`--run-as=root --preserve-symlinks`) recursively on the firmware blob. Detects uImage, TP-Link/TRX compound formats, and standard archives. Extracts rootfs and kernel separately. |
| 1b | `sources/extractor/extractor.py` (2nd pass) | Re-runs extraction targeting kernel image specifically. |
| 1c | Database insert | Stores image metadata (filename, brand, MD5 hash, rootfs_extracted, kernel_extracted) into PostgreSQL `image` table. Returns an Image ID (IID) used throughout the pipeline. |

### Phase 2: Architecture Detection (~5-15s)

| Step | Script | What it does |
|------|--------|-------------|
| 2a | `scripts/getArch.py` | Opens the extracted tarball, prioritizes common binaries (busybox, httpd, boa, binaries in `/sbin/`, `/bin/`). Runs `file` command on each, parses ELF headers for architecture + endianness. |
| 2b | Architecture validation | Checks detected arch is one of: `armel`, `mipseb`, `mipsel`. Rejects unsupported architectures. |
| 2c | `scripts/inferKernel.py` | Extracts kernel version string and init parameters from the kernel binary using `strings`. Used for kernel version selection (2.6 vs 4.1). |

### Phase 3: Image Preparation (~30-60s)

| Step | Script | What it does |
|------|--------|-------------|
| 3a | `scripts/tar2db.py` | Converts extracted tarball contents into the `object` and `object_to_image` database tables (file hashes, permissions, UIDs). |
| 3b | `scripts/makeImage.sh` | Creates a 1GB raw QEMU disk image (`qemu-img create -f raw`). Partitions with `fdisk`, formats as ext2, extracts firmware tarball into it. |
| 3c | Injection (in makeImage.sh) | Copies architecture-specific binaries into `/firmadyne/` inside the image: busybox, bash-static, console, strace, gdb, gdbserver, libnvram.so, libnvram_ioctl.so. |
| 3d | `scripts/fixImage.sh` | Creates missing directories (`/proc`, `/dev/pts`, `/tmp`, `/var`, `/sys`). Generates device nodes (mem, zero, random, tty, console, ttyS*, mtd*, mtdblock*). Creates `/etc/passwd`, `/etc/hosts`, `/etc/TZ`. Removes reboot binaries to prevent shutdown. |
| 3e | `scripts/inferFile.sh` | Discovers init system by: (1) extracting init path from kernel strings, (2) checking `/init`, (3) searching for preinitMT/preinit/rcS. Creates `/firmadyne/init` boot chain. Injects `preInit.sh` hook. Detects web server binary (uhttpd, httpd, goahead, boa, lighttpd) and records it in `/firmadyne/service`. |
| 3f | `scripts/makeNetwork.py` | Parses QEMU serial logs from a brief pre-boot. Infers network topology (normal, bridge, reload, default). Generates TAP interface setup commands. Assigns host-side IPs by decrementing guest IP's last octet. |

### Phase 4: Emulation + Mode-Specific Operations

| Step | Script | What it does |
|------|--------|-------------|
| 4a | `scripts/run.{armel,mipseb,mipsel}.sh` | Launches QEMU with architecture-specific parameters (see Section 2). Boots headless (`-display none`). Serial output to unix socket + log file. |
| 4b | `scripts/preInit.sh` (inside guest) | Mounts sysfs, proc, devpts, tmpfs. Creates `/etc/mtab` symlink. |
| 4c | `scripts/network.sh` (inside guest) | Configures br0 bridge with static IP (default 192.168.0.1). Flushes iptables every 5 seconds to maintain open firewall. |
| 4d | `scripts/run_service.sh` (inside guest) | Waits 120 seconds, then starts the detected web server binary. Monitors every 10 seconds and respawns if it dies. |
| 4e | `scripts/check_emulation.sh` | Tests emulation success via ping reachability + HTTP service detection against inferred IPs. Uses `TIMEOUT` (60-240s) and `CHECK_TIMEOUT` (60-360s). |

### Mode-Specific Behavior

| Mode | Flag | Behavior after boot |
|------|------|-------------------|
| Check (`-c`) | Verify only | Runs ping + web check, logs result, kills QEMU |
| Analyze (`-a`) | Full scan | Runs check, then `analyses/analyses_all.sh` (routersploit, custom scanners) |
| Run (`-r`) | Interactive | Boots and stays running indefinitely |
| Debug (`-d`) | User debug | Boots with debug tools available, stays running |
| Boot (`-b`) | Kernel debug | Boots with GDB stub for kernel debugging |

### Typical End-to-End Timing

| Phase | Without FIRMAE_ETC | With FIRMAE_ETC |
|-------|-------------------|-----------------|
| Extraction | 30-300s | 30-300s |
| Arch detection | 5-15s | 5-15s |
| Image prep | 30-60s | 30-60s |
| Boot + check | 60s timeout | 240s timeout |
| Web service wait | 60s timeout | 360s timeout |
| **Total** | **~3-8 min** | **~5-15 min** |

---

## 2. Docker Requirements

### Privileges

FirmAE's `docker-helper.py` launches containers with `--privileged=true`. This is required for:

| Requirement | Why |
|-------------|-----|
| TAP interface creation | `tunctl -t tapN -u USER` requires `CAP_NET_ADMIN` + `/dev/net/tun` |
| Bridge management | `ip link add ... type bridge` requires `CAP_NET_ADMIN` |
| iptables manipulation | Flushing/adding rules requires `CAP_NET_ADMIN` + `CAP_NET_RAW` |
| Loop device management | `kpartx`, `losetup`, `mount` require device access |
| QEMU networking | Needs `/dev/net/tun` for TAP-based guest networking |
| Device node creation | `mknod` in fixImage.sh requires `CAP_MKNOD` |

### Minimum Capabilities (if not using --privileged)

```
--cap-add=NET_ADMIN      # TAP, bridge, iptables
--cap-add=NET_RAW         # Raw socket access for ping checks
--cap-add=SYS_ADMIN       # Loop device mount, kpartx
--cap-add=MKNOD           # Device node creation
--device=/dev/net/tun     # QEMU TAP networking
--device=/dev/kvm         # KVM acceleration (if available)
```

### Required Device Access

- `/dev/net/tun` -- QEMU TAP networking
- `/dev/kvm` -- optional, KVM acceleration (host arch only)
- Loop devices are created dynamically via `losetup`/`kpartx`

### Kernel Modules (host)

- `tun` -- TAP interface support
- `bridge` -- Linux bridge support
- `loop` -- Loop device for disk images
- `dm-mod` -- Device mapper for kpartx
- `8021q` -- VLAN support (optional, for VLAN-tagged firmware)

### Volume Mounts (from docker-helper.py)

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `/dev` | `/dev` | Device access |
| FirmAE root dir | `/work/FirmAE` | Framework code + binaries |
| Firmware directory | `/work/firmwares` | Input firmware images |

---

## 3. Pre-built Kernels

FirmAE ships pre-built kernels from two separate repositories:

### Kernel v2.6 (pr0v3rbs/FirmAE_kernel-v2.6)

Modified Linux 2.6 kernel originally from Firmadyne. MIPS only (Malta target, 24kf CPU).

| File | Architecture | Format |
|------|-------------|--------|
| `vmlinux.mipseb.2` | MIPS big-endian | vmlinux (ELF) |
| `vmlinux.mipsel.2` | MIPS little-endian | vmlinux (ELF) |

### Kernel v4.1 (pr0v3rbs/FirmAE_kernel-v4.1)

Newer Linux 4.1 kernel. MIPS (Malta) + ARM (virt).

| File | Architecture | Format |
|------|-------------|--------|
| `vmlinux.mipseb.4` | MIPS big-endian | vmlinux (ELF) |
| `vmlinux.mipsel.4` | MIPS little-endian | vmlinux (ELF) |
| `zImage.armel` | ARM little-endian | zImage (compressed) |

### Kernel Modifications

Both kernel trees include an in-tree `firmadyne` module that provides:

- **LD_PRELOAD injection**: Patches `init/main.c` to force `LD_PRELOAD=/firmadyne/libnvram.so` for all processes
- **Syscall interception**: Uses kprobes to hook and log system calls (`firmadyne.syscall=1` boot param)
- **Device stubs**: Creates virtual entries in devfs/procfs for missing hardware
- **Reboot interception**: Re-executes `/sbin/init` instead of actual reboot
- **Console execution**: Can trigger `/firmadyne/console` after N syscalls

### Kernel Selection Logic

The `firmae.config` helper functions select kernels:
- ARM always uses `zImage.armel` (only v4.1 available)
- MIPS defaults to v2.6 (`vmlinux.mips{eb,el}.2`); switches to v4.1 when `FIRMAE_KERNEL` arbitration is enabled and v2.6 fails

### Storage Location

Downloaded to `./binaries/` by `download.sh`. Referenced at runtime via `${BINARY_DIR}` in `firmae.config`.

---

## 4. PostgreSQL Usage

### Connection

- User: `firmadyne`, Password: `firmadyne`
- Database: `firmware`
- Host: `172.17.0.1` (Docker mode) or `127.0.0.1` (host mode)

### Schema (5 tables)

```sql
CREATE TABLE brand (
    id SERIAL PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL
);

CREATE TABLE image (
    id SERIAL PRIMARY KEY,
    filename VARCHAR NOT NULL,
    description VARCHAR,
    brand_id INTEGER DEFAULT 1 REFERENCES brand(id),
    hash VARCHAR UNIQUE,
    rootfs_extracted BOOLEAN DEFAULT FALSE,
    kernel_extracted BOOLEAN DEFAULT FALSE,
    arch VARCHAR,
    kernel_version VARCHAR
);

CREATE TABLE object (
    id SERIAL PRIMARY KEY,
    hash VARCHAR UNIQUE
);

CREATE TABLE object_to_image (
    id SERIAL PRIMARY KEY,
    oid INTEGER NOT NULL REFERENCES object(id),
    iid INTEGER NOT NULL REFERENCES image(id),
    filename VARCHAR NOT NULL,
    regular_file BOOLEAN DEFAULT TRUE,
    permissions INTEGER,
    uid INTEGER,
    gid INTEGER
);

CREATE TABLE product (
    id SERIAL PRIMARY KEY,
    iid INTEGER NOT NULL REFERENCES image(id),
    url VARCHAR NOT NULL,
    mib_hash VARCHAR, mib_url VARCHAR,
    sdk_hash VARCHAR, sdk_url VARCHAR,
    product VARCHAR, version VARCHAR, build VARCHAR,
    date TIMESTAMP,
    mib_filename VARCHAR, sdk_filename VARCHAR
);
```

### Usage Pattern

- `brand` + `image`: Core metadata, populated during extraction. The auto-increment `image.id` becomes the IID used everywhere.
- `object` + `object_to_image`: File-level inventory with permissions. Populated by `tar2db.py`. Used for filesystem analysis but **not required for emulation**.
- `product`: Vendor metadata. Populated manually or by scrapers. **Not used during emulation**.

### Can We Use SQLite Instead?

**No, not easily.** FirmAE's codebase uses `psycopg2` directly with PostgreSQL-specific features:
- `SERIAL` auto-increment columns
- `psql` command-line tool for schema loading and queries in shell scripts
- Connection string format `host=X user=Y dbname=Z` throughout

However, for the sidecar use case, we can run an ephemeral Postgres inside the container (see risk assessment). The database is small (< 1MB for a single firmware) and only needed during the pipeline run.

---

## 5. Network Setup

### Host-Side (makeNetwork.py + run.{arch}.sh)

1. **TAP creation**: `tunctl -t tap${IID}_${i} -u ${USER}` creates one TAP interface per emulated NIC (up to 4).

2. **IP assignment**: Host-side IP derived from guest IP by decrementing last octet. Example: guest `192.168.0.1` -> host `192.168.0.0/24` on the TAP.

3. **VLAN support** (optional): `ip link add link tap${IID}_0 name tap${IID}_0.X type vlan id X` when firmware uses VLANs.

4. **QEMU NIC connection**:
   - With `FIRMAE_NET=true`: User-mode networking (`-netdev user,id=netN`)
   - Without: Socket-based (`-netdev socket,id=netN,listen=:200N`)
   - NIC model: `virtio-net-device` (ARM) or `e1000` (MIPS)

### Guest-Side (network.sh, inside firmware)

1. Creates bridge `br0` with static IP `192.168.0.1`
2. Adds `eth0` to bridge
3. Runs persistent loop flushing iptables every 5 seconds (keeps firewall open for analysis)

### Network Modes (inferred from serial logs)

| Mode | Description |
|------|------------|
| `normal` | Standard bridge with detected IP |
| `bridge` | Resolves conflicting bridge configs |
| `reload` | Re-assigns static 192.168.0.1 |
| `default` | Fallback: br0 + 192.168.0.1 |

### Connectivity Verification

`check_emulation.sh` tests:
1. `ping` to each inferred guest IP
2. HTTP request to each IP (web service detection)
3. Results logged to `emulation.log`

---

## 6. NVRAM Emulation

### Mechanism

FirmAE uses an **LD_PRELOAD-based NVRAM emulator** (`libnvram.so`) that intercepts NVRAM API calls at the shared library level.

### How It Works

1. **Kernel-level injection**: The modified kernel patches `init/main.c` to set `LD_PRELOAD=/firmadyne/libnvram.so` globally, ensuring every process loads the library.

2. **Function interception**: `libnvram.so` intercepts standard NVRAM functions:
   - `nvram_get(key)` -- returns emulated value
   - `nvram_set(key, val)` -- stores in emulated storage
   - `nvram_getall()`, `nvram_commit()`, etc.

3. **Storage backend**: Key-value pairs stored as individual files in a tmpfs at `/firmadyne/libnvram/`. Override values in `/firmadyne/libnvram.override/`.

4. **Default value discovery**: On first access, the library searches firmware filesystem for default NVRAM files:
   - `/var/etc/nvram.default`
   - `/etc/nvram.default`, `/etc/nvram.conf`, `/etc/nvram.deft`
   - `/etc/wlan/nvram_params`
   - `/etc/system_nvram_defaults`
   - Various vendor-specific paths

5. **FirmAE enhancement** (FIRMAE_NVRAM arbitration): During a pre-emulation pass, FirmAE logs all `nvram_get()` calls. For keys with unknown values, it scans the firmware filesystem for files containing those key names and extracts matching key-value pairs. These are injected as overrides for the real emulation run.

### Additional NVRAM Library

`libnvram_ioctl.so` handles NVRAM access via `ioctl()` calls (some vendors use ioctl instead of function calls).

---

## 7. Architecture Detection

### Method: `scripts/getArch.py`

1. Opens the extracted firmware tarball
2. Prioritizes common ELF binaries: busybox, boa, httpd, and binaries in `/sbin/`, `/bin/`
3. Runs the `file` command on each binary
4. Parses output for architecture markers:

| `file` output contains | Detected arch |
|------------------------|--------------|
| `ARM` + `LSB` | `armel` |
| `MIPS` + `MSB` | `mipseb` |
| `MIPS` + `LSB` | `mipsel` |
| `ARM64` / `aarch64` | Not supported in v1 |
| `Intel 80386` | Not supported |
| `x86-64` | Not supported |

5. Stops at first successful match
6. Stores result in PostgreSQL `image.arch` column

### Limitations

- No AArch64 support (no pre-built kernel)
- No x86 firmware emulation (not the target use case)
- Detection depends on at least one recognizable ELF binary in the firmware

---

## 8. Success/Failure Detection

### Method: `scripts/check_emulation.sh`

FirmAE uses a two-stage network reachability check:

**Stage 1: Ping test**
- Waits up to `TIMEOUT` seconds (60 or 240) for QEMU boot
- Pings each inferred guest IP
- If no response after timeout: **FAIL -- boot did not complete**

**Stage 2: Web service test**
- Waits up to `CHECK_TIMEOUT` seconds (60 or 360) for HTTP service
- Attempts HTTP connection to each reachable IP
- If web service responds: **PASS**
- If ping succeeds but no web service: **PARTIAL -- booted but no web**

### IP Discovery

IPs are read from files written during the image preparation phase:
- `${WORK_DIR}/ip.0`, `ip.1`, etc.
- If DHCP detected, tests against `127.0.0.1`

### Result Storage

Results logged to `${WORK_DIR}/emulation.log` with:
- Ping success/failure per IP
- Web service availability per IP
- Response times

### After Check

QEMU process is killed via `sudo kill` targeting the IID-specific process. TAP interfaces cleaned up by `delete.sh`.

---

## 9. License

**MIT License**

FirmAE is released under the MIT license, which permits:
- Commercial use
- Modification
- Distribution
- Private use

No license file was found at the expected path (`LICENSE`), but the README and GitHub metadata both indicate MIT. The Firmadyne upstream project (which FirmAE extends) is also MIT-licensed.

---

## 10. Risk Assessment

### High Risk

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Privileged container** | FirmAE needs `--privileged` for TAP/bridge/kpartx. This gives root-equivalent access to the host. | Use minimum capabilities (`NET_ADMIN`, `SYS_ADMIN`, `MKNOD`) + specific device mounts instead. Run on isolated Docker network. |
| **Ephemeral Postgres complexity** | Running Postgres inside the sidecar adds startup time (~3-5s) and memory (~50-100MB). | Use a lightweight Postgres (Alpine-based) with minimal config. Or investigate replacing psycopg2 calls with a thin DB abstraction. |
| **Shell script fragility** | FirmAE is 70% Python + 16% shell. The shell scripts use hardcoded paths, `sudo`, and assume Ubuntu host tools. Breaking changes are likely when wrapping in a different base image. | Pin base image to Ubuntu 20.04. Run integration tests against known-good firmware. |
| **QEMU process management** | FirmAE manages QEMU via `kill` signals and PID files. No graceful shutdown protocol. If the shim crashes, orphan QEMU processes persist. | Implement PID tracking in the shim. Use process groups. Add a watchdog that kills all QEMU on shim exit. |

### Medium Risk

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Network collision** | Each emulated firmware gets TAP interfaces named `tap${IID}_N`. Parallel instances need unique IIDs. | Assign unique IIDs per Wairz session. Use Docker network isolation so TAP names don't collide across containers. |
| **Disk space** | Each firmware creates a 1GB raw disk image + extracted tarball. | Clean up after emulation. Set container tmpfs limits. Monitor disk usage. |
| **No AArch64 support** | Many modern IoT devices use AArch64. FirmAE has no pre-built AArch64 kernel. | Document limitation. Build custom AArch64 kernel as future work. Use Wairz's existing user-mode emulation for AArch64 binaries. |
| **Stale upstream** | FirmAE's last significant update was 2020-2021. Dependencies (binwalk 2.3.4, Ubuntu 20.04) are aging. | Fork and maintain. Pin known-working versions. |
| **Port discovery** | FirmAE only checks HTTP. Firmware may expose SSH, Telnet, SNMP, UPnP on other ports. | Add nmap scan after boot success. |

### Low Risk

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **License compatibility** | MIT license is permissive. Compatible with Wairz's license. | No action needed. |
| **Kernel module availability** | `tun`, `bridge`, `loop`, `dm-mod` are standard. Should be available on any Linux host. | Check at container startup. Fail fast with clear error. |
| **Memory usage** | QEMU uses 256MB per emulated instance. | Set container memory limits. Limit concurrent instances. |
