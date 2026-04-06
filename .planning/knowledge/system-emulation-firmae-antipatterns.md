# Anti-patterns: Automated System Emulation (FirmAE)

> Extracted: 2026-04-05
> Campaign: .planning/campaigns/system-emulation-firmae.md

## Failed Patterns

### 1. Assuming Ubuntu 22.04 pip Supports --break-system-packages
- **What was done:** Dockerfile used `pip3 install --no-cache-dir --break-system-packages flask gunicorn psycopg2-binary`
- **Failure mode:** pip on Ubuntu 22.04 (Python 3.10) doesn't support `--break-system-packages` flag — that's Python 3.11+ / pip 23+. Build failed with "Usage: pip3 install [options]" error.
- **Evidence:** First Docker build failure. Fixed by removing the flag.
- **How to avoid:** On Ubuntu 22.04 base images, `pip3 install` works without `--break-system-packages`. Only needed on newer distros (24.04+) where PEP 668 is enforced.

### 2. Hardcoded Credentials Assumed to Match Container Defaults
- **What was done:** Entrypoint set PostgreSQL password to "firmae" and created the default "postgres" role. FirmAE's scripts connect as user "firmadyne" with password "firmadyne".
- **Failure mode:** `psycopg2.OperationalError: FATAL: role "firmadyne" does not exist`. Extractor ran silently without DB connection, produced no output, causing the pipeline to fail with "extractor.py failed!" and empty IID.
- **Evidence:** Required debugging with direct `python3 -c "import psycopg2; psycopg2.connect(...)"` inside the container. The error only appeared with the `-d` (debug) flag on the extractor.
- **How to avoid:** When wrapping a third-party tool, always grep for hardcoded credentials: `grep -r 'password\|connect.*database' sources/ scripts/`. FirmAE hardcodes "firmadyne"/"firmadyne" in both `extractor.py` and `scripts/util.py`.

### 3. Docker Loop Device Partition Assumption
- **What was done:** FirmAE's `makeImage.sh` uses `losetup -Pf` + `kpartx` to create partitioned loop devices (`/dev/loopXp1`).
- **Failure mode:** Inside Docker containers (even with `--privileged`), partition device nodes don't propagate through devtmpfs because udev events aren't forwarded. The script enters an infinite retry loop waiting for `/dev/loop2p1` that never appears.
- **Evidence:** Pipeline stuck at "extracting" phase with repeated `ls: cannot access '/dev/loop2p1': No such file or directory` in output. Consumed the full 10-minute timeout.
- **How to avoid:** When containerizing tools that use loop devices with partitions, always patch to use raw images (no partition table) with `mount -o loop`. Override any `*_ROOTFS` kernel parameters to use `/dev/sda` instead of `/dev/sda1`. This is a fundamental Docker limitation, not fixable with capabilities.

### 4. Inline Sed Commands in Dockerfile RUN Blocks
- **What was done:** Attempted to patch FirmAE's scripts with complex sed commands directly in a Dockerfile `RUN` block, including patterns with `${DEVICE}`, pipe characters, and nested quotes.
- **Failure mode:** Shell escaping conflicts between Docker's shell processing, sed's regex engine, and bash variable expansion. Patterns like `e2fsck -y ${DEVICE}` couldn't be reliably matched because `$` was interpreted by the shell before reaching sed.
- **Evidence:** Build error `exit code: 1` on the sed line. Required 3 iterations to get right.
- **How to avoid:** For non-trivial file patches in Dockerfiles, always use a separate `.sh` script (COPY + RUN). The script runs in its own shell context where escaping is predictable. Pattern: `COPY patches/fix.sh /tmp/` → `RUN chmod +x /tmp/fix.sh && /tmp/fix.sh`.

### 5. Unbound Variable from Commented-Out Assignment
- **What was done:** Commented out `DEVICE=\`add_partition ${IMAGE}\`` but left `e2fsck -y ${DEVICE}` referencing the variable. FirmAE's scripts use `set -u` (error on unbound variables).
- **Failure mode:** `./scripts/makeImage.sh: line 143: DEVICE: unbound variable` — pipeline crashed after successfully creating the disk image and extracting the filesystem.
- **Evidence:** Pipeline output showed successful `mke2fs`, `mount -o loop`, filesystem extraction, and chroot operations — then crashed on the cleanup `e2fsck` line.
- **How to avoid:** When patching scripts that use `set -u`, trace ALL references to variables whose assignments you're commenting out. Use `grep -n 'VARIABLE_NAME' script.sh` to find every reference before patching.

### 6. Testing Pipeline Timeout Too Short for Cross-Architecture Emulation
- **What was done:** Set pipeline timeout to 10 minutes (600s), matching FirmAE's typical timing on x86 hardware.
- **Failure mode:** On ARM64 host (Raspberry Pi), cross-architecture QEMU emulation (MIPS on ARM64) takes significantly longer. FirmAE's disk image creation alone takes ~5 minutes, and QEMU boot + network inference takes another ~5 minutes. The 10-minute timeout fired during the network inference phase.
- **Evidence:** Pipeline reached `[*] infer network start!!!` before timeout at 600.6s. Firmware IP (192.168.1.2) was detected but not returned before cleanup.
- **How to avoid:** When testing on non-x86 hardware, multiply expected timeouts by 3-5x. For QEMU system emulation (not just user-mode), cross-arch overhead is especially significant because the entire OS boots under emulation. Default to 30 minutes on ARM64.
