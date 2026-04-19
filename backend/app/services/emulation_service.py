"""Service for managing QEMU-based firmware emulation sessions.

Uses the Docker SDK to spawn isolated containers running QEMU in user-mode
(single binary chroot) or system-mode (full OS boot).
"""

import asyncio
import io
import logging
import os
import shlex
import tarfile

from datetime import datetime, timezone
from uuid import UUID

import docker
import docker.errors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.services.emulation_constants import (
    ARCH_ALIASES,
    BINFMT_ENTRIES,
    QEMU_USER_BIN_MAP,
    _ANSI_RE,
    _HOST_ARCH,
    _MARKER_RE,
    _validate_kernel_file,
)
from app.services.emulation_preset_service import EmulationPresetService
from app.services.kernel_service import KernelService
from app.utils.docker_client import get_docker_client
from app.utils.sandbox import validate_path

logger = logging.getLogger(__name__)


class EmulationService:
    """Manages QEMU emulation session lifecycle via Docker containers."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._settings = get_settings()

    def _get_docker_client(self) -> docker.DockerClient:
        """Create a Docker client (created per-call, not cached)."""
        return get_docker_client()

    def _normalize_arch(self, arch: str | None) -> str | None:
        if not arch:
            return None
        return ARCH_ALIASES.get(arch, arch.lower())

    def _ensure_binfmt_misc(self, arch: str) -> None:
        """Register binfmt_misc for the target architecture if not already present.

        Uses a short-lived privileged Docker container to register the QEMU
        user-mode interpreter with the kernel's binfmt_misc subsystem.  The
        ``F`` (fix binary) flag causes the kernel to cache the interpreter's
        file descriptor at registration time, so it works transparently inside
        chroots and containers — any execve() of a foreign-arch ELF is handled
        by the kernel without the binary needing to be accessible from the
        process's mount namespace.

        Docker containers see an empty ``/proc/sys/fs/binfmt_misc`` by default
        (it's not the host's mount), so the privileged container must first
        ``mount -t binfmt_misc`` to access the real kernel entries.

        This is a host-level operation (binfmt_misc is kernel-wide) and
        persists until the host reboots or the entry is explicitly removed.
        A flag file in ``/tmp`` avoids re-running the privileged container
        on every emulation start within the same backend container lifetime.

        Failures are logged as warnings but never raised — user-mode
        emulation still works for the initial shell; only child processes
        would fail with "Exec format error".
        """
        # Skip for the host's native architecture — the kernel handles it
        if arch == _HOST_ARCH:
            logger.debug("Skipping binfmt_misc for native architecture: %s", arch)
            return

        entry = BINFMT_ENTRIES.get(arch)
        if not entry:
            logger.debug("No binfmt_misc entry defined for architecture: %s", arch)
            return

        binfmt_name, registration = entry

        # Check local flag file — avoids running a privileged container on
        # every emulation start.  The flag persists within this backend
        # container's lifetime (cleared on container restart).
        flag_file = f"/tmp/.binfmt_registered_{binfmt_name}"
        if os.path.exists(flag_file):
            logger.debug("binfmt_misc already registered (cached): %s", binfmt_name)
            return

        logger.info(
            "Registering binfmt_misc for %s (requires privileged container)...",
            binfmt_name,
        )

        client = self._get_docker_client()
        try:
            # Run a short-lived privileged container that:
            # 1. Mounts binfmt_misc (Docker containers don't see the host's mount)
            # 2. Checks if the entry already exists (idempotent)
            # 3. Registers if needed
            # Must be privileged because Docker's default seccomp profile blocks
            # writes to /proc/sys even with the SYS_ADMIN capability.
            # The F flag causes the kernel to open /usr/bin/qemu-{arch}-static
            # from within this container's filesystem and cache the fd.
            result = client.containers.run(
                image=self._settings.emulation_image,
                command=[
                    "sh", "-c",
                    "mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null; "
                    f"if [ -f /proc/sys/fs/binfmt_misc/{binfmt_name} ]; then "
                    "echo ALREADY_REGISTERED; "
                    "else "
                    f"echo '{registration}' > /proc/sys/fs/binfmt_misc/register 2>&1 "
                    "&& echo REGISTERED || echo FAILED; "
                    "fi",
                ],
                remove=True,
                privileged=True,
            )

            output = result.decode("utf-8", errors="replace").strip()

            if "REGISTERED" in output or "ALREADY_REGISTERED" in output:
                # Create flag file so subsequent calls skip the privileged container
                try:
                    with open(flag_file, "w") as f:
                        f.write("1")
                except OSError:
                    pass  # Non-critical — just means we'll check again next time
                logger.info("binfmt_misc for %s: %s", binfmt_name, output)
            else:
                logger.warning(
                    "binfmt_misc registration for %s returned unexpected output: %s",
                    binfmt_name,
                    output,
                )
        except Exception as exc:
            logger.warning(
                "Could not register binfmt_misc for %s: %s. "
                "Child processes in user-mode emulation may fail with 'Exec format error'. "
                "To fix manually: docker run --rm --privileged multiarch/qemu-user-static --reset -p yes",
                binfmt_name,
                exc,
            )

    async def _count_active_sessions(self, project_id: UUID) -> int:
        result = await self.db.scalar(
            select(func.count(EmulationSession.id)).where(
                EmulationSession.project_id == project_id,
                EmulationSession.status.in_(["created", "starting", "running"]),
            )
        )
        return result or 0

    async def start_session(
        self,
        firmware: Firmware,
        mode: str,
        binary_path: str | None = None,
        arguments: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationSession:
        """Start a new emulation session.

        Args:
            firmware: The firmware record (must have extracted_path).
            mode: "user" or "system".
            binary_path: For user mode — path to the binary within the extracted FS.
            arguments: Optional CLI arguments for user mode.
            port_forwards: List of {"host": int, "guest": int} dicts.
            kernel_name: Specific kernel to use for system mode.
            init_path: Override init binary for system mode (e.g., "/bin/sh").
            pre_init_script: Shell script to run before firmware init (system mode).
            stub_profile: Stub library profile ("none", "generic", "tenda").
        """
        if mode not in ("user", "system"):
            raise ValueError("mode must be 'user' or 'system'")

        if not firmware.extracted_path:
            raise ValueError("Firmware has not been unpacked")

        if mode == "user" and not binary_path:
            raise ValueError("binary_path is required for user-mode emulation")

        # Validate binary_path against extracted root
        if binary_path:
            validate_path(firmware.extracted_path, binary_path)

        # Check concurrent session limit
        active = await self._count_active_sessions(firmware.project_id)
        if active >= self._settings.emulation_max_sessions:
            raise ValueError(
                f"Maximum concurrent sessions ({self._settings.emulation_max_sessions}) reached. "
                "Stop an existing session first."
            )

        arch = self._normalize_arch(firmware.architecture)
        if not arch:
            raise ValueError(
                "Cannot determine firmware architecture. "
                "Architecture detection must complete before emulation."
            )

        # Create DB record
        session = EmulationSession(
            project_id=firmware.project_id,
            firmware_id=firmware.id,
            mode=mode,
            status="starting",
            binary_path=binary_path,
            arguments=arguments,
            architecture=arch,
            port_forwards=port_forwards or [],
        )
        self.db.add(session)
        await self.db.flush()

        # Detect standalone binary mode: binary_info is only set for standalone
        # binaries (direct ELF/PE upload or extraction fallback), never for
        # firmware with a proper rootfs.
        is_standalone = firmware.binary_info is not None

        # Check if this binary should use Qiling instead of QEMU/Docker.
        # Qiling handles PE (Windows) and Mach-O (macOS) binaries that QEMU
        # user-mode can't emulate. Qiling runs in-process (no Docker needed).
        binary_format = (firmware.binary_info or {}).get("format")
        use_qiling = (
            is_standalone
            and binary_format in ("pe", "macho")
            and mode == "user"
        )

        if use_qiling:
            try:
                from app.services.qiling_service import run_binary_async, get_rootfs_path

                # Resolve absolute binary path
                abs_binary = os.path.join(
                    firmware.extracted_path,
                    binary_path.lstrip("/") if binary_path else "",
                )

                # Parse arguments
                args = shlex.split(arguments) if arguments else None

                # Resolve rootfs
                rootfs = get_rootfs_path(binary_format, arch)

                session.mode = "qiling"
                session.started_at = datetime.now(timezone.utc)
                await self.db.flush()

                # Run Qiling emulation (batch, not interactive)
                qresult = await run_binary_async(
                    binary_path=abs_binary,
                    rootfs=rootfs,
                    args=args,
                    timeout=60,
                    trace_syscalls=True,
                    binary_format=binary_format,
                    architecture=arch,
                )

                # Store results in session
                output_parts = []
                if qresult.stdout:
                    output_parts.append(f"=== STDOUT ===\n{qresult.stdout}")
                if qresult.stderr:
                    output_parts.append(f"=== STDERR ===\n{qresult.stderr}")
                if qresult.error:
                    output_parts.append(f"=== ERROR ===\n{qresult.error}")
                if qresult.memory_errors:
                    output_parts.append(
                        f"=== MEMORY ERRORS ===\n" +
                        "\n".join(qresult.memory_errors)
                    )
                if qresult.syscall_trace:
                    trace = qresult.syscall_trace[:100]  # Cap for storage
                    output_parts.append(
                        f"=== SYSCALL TRACE ({qresult.syscall_count} total) ===\n" +
                        "\n".join(trace)
                    )

                summary = (
                    f"Qiling emulation completed in {qresult.duration_ms}ms. "
                    f"Exit code: {qresult.exit_code}. "
                    f"Syscalls: {qresult.syscall_count}."
                )
                if qresult.timed_out:
                    summary += " (TIMED OUT)"

                session.logs = "\n\n".join(output_parts) if output_parts else "(no output)"
                session.error_message = qresult.error
                session.status = "stopped"
                session.stopped_at = datetime.now(timezone.utc)

            except Exception as exc:
                logger.exception("Qiling emulation failed")
                session.status = "error"
                session.error_message = str(exc)

            await self.db.flush()
            return session

        # Start Docker container (QEMU path — for ELF binaries and system mode)
        try:
            container_id = await self._start_container(
                session=session,
                extracted_path=firmware.extracted_path,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware.kernel_path,
                init_path=init_path,
                pre_init_script=pre_init_script,
                stub_profile=stub_profile,
                is_standalone=is_standalone,
                binary_info=firmware.binary_info,
            )
            session.container_id = container_id
            session.status = "running"
            session.started_at = datetime.now(timezone.utc)
        except Exception as exc:
            logger.exception("Failed to start emulation container")
            session.status = "error"
            session.error_message = str(exc)

        await self.db.flush()
        return session

    def _resolve_host_path(self, container_path: str) -> str | None:
        """Resolve a path inside this container to a host path for Docker mounts.

        When the backend runs inside Docker and uses the Docker socket, volume
        mounts reference HOST paths, not container paths. This method inspects
        our own container's mounts to translate paths.

        If not running in Docker, returns the path as-is.
        Returns None if the path is not on any mount (baked into image).
        """
        real_path = os.path.realpath(container_path)

        # Not running in Docker — path is already a host path
        if not os.path.exists("/.dockerenv"):
            return real_path

        client = self._get_docker_client()

        # Find our own container by hostname (Docker sets HOSTNAME to container ID)
        hostname = os.environ.get("HOSTNAME", "")
        if not hostname:
            return real_path

        try:
            our_container = client.containers.get(hostname)
            mounts = our_container.attrs.get("Mounts", [])

            for mount in mounts:
                dest = mount.get("Destination", "")
                source = mount.get("Source", "")
                if not dest or not source:
                    continue

                # Check if our path falls under this mount
                if real_path.startswith(dest + os.sep) or real_path == dest:
                    relative = os.path.relpath(real_path, dest)
                    host_path = os.path.join(source, relative)
                    logger.info(
                        "Path translation: %s -> %s (via mount %s -> %s)",
                        real_path, host_path, source, dest,
                    )
                    return host_path

        except Exception:
            logger.warning(
                "Could not inspect own container for path translation: %s",
                real_path, exc_info=True,
            )

        # Path is not on any Docker mount — baked into the container image
        return None

    @staticmethod
    def _copy_dir_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a directory tree into a running container using put_archive.

        Creates a tar archive of src_path contents and streams it into
        dst_path inside the container.
        """
        import io
        import tarfile

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            # Add all files from src_path, with arcname="" so they land
            # directly in dst_path (not in a subdirectory)
            for entry in os.scandir(src_path):
                tar.add(entry.path, arcname=entry.name)
        tar_stream.seek(0)

        container.put_archive(dst_path, tar_stream)

    @staticmethod
    def _copy_file_to_container(
        container: "docker.models.containers.Container",
        src_path: str,
        dst_path: str,
    ) -> None:
        """Copy a single file into a running container using put_archive."""
        import io
        import tarfile

        dst_dir = os.path.dirname(dst_path)
        dst_name = os.path.basename(dst_path)

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(src_path, arcname=dst_name)
        tar_stream.seek(0)

        container.put_archive(dst_dir, tar_stream)

    @staticmethod
    def _fix_firmware_permissions(
        container: "docker.models.containers.Container",
    ) -> None:
        """Fix execute permissions and broken symlinks in firmware.

        Binwalk extraction often loses execute bits and corrupts symlinks
        (replacing them with small files containing the original symlink
        target as text, or just null bytes). This method:
        1. Makes files in common binary/library directories executable.
        2. Restores corrupted symlinks across the entire firmware tree by
           reading small file contents to recover the original target path.
        3. Falls back to heuristics for .so versioned libraries and busybox.
        """
        bin_dirs = [
            "/firmware/bin", "/firmware/sbin",
            "/firmware/usr/bin", "/firmware/usr/sbin",
            "/firmware/lib", "/firmware/usr/lib",
            "/firmware/lib32", "/firmware/usr/lib32",
        ]
        for d in bin_dirs:
            # Use argv-list form with test + chmod to avoid any shell
            # interpolation. The test command returns 0 only when d exists;
            # non-zero exit from exec_run is intentionally ignored here.
            test_result = container.exec_run(["test", "-d", d])
            if test_result.exit_code == 0:
                container.exec_run(["chmod", "-R", "+x", d])

        # Generic symlink restoration script.
        # Binwalk corruption patterns:
        #   a) Small file whose content IS the symlink target (as text, possibly null-padded)
        #   b) Small file of pure null bytes (target lost — need heuristics)
        #
        # Strategy:
        #   Pass 1: Scan entire tree for small files (<256 bytes). Read content.
        #           If content looks like a path, restore symlink.
        #   Pass 2: Fix remaining .so stubs using versioned-name matching.
        #   Pass 3: Fix remaining null stubs in bin/sbin using busybox (if present).
        fix_symlinks_script = r"""
FIXED=0
PASS1=0
PASS2=0
PASS3=0

# --- Pass 1: Content-based symlink recovery (most reliable) ---
# Scan the entire firmware tree for small regular files whose content
# looks like a symlink target path (e.g., "busybox", "../lib/libc.so.6",
# "/usr/bin/python3").
find /firmware -type f -size -256c 2>/dev/null | while read stub; do
    # Read file content, strip null bytes and whitespace
    target=$(tr -d '\000' < "$stub" 2>/dev/null | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Skip empty content
    [ -z "$target" ] && continue

    # Validate: target must look like a path (relative or absolute)
    # and contain only valid path characters
    case "$target" in
        /*|./*|../*)
            # Absolute or explicit relative path — good
            ;;
        *)
            # Bare name — only accept if it contains no spaces/specials
            # and is short (likely "busybox", "bash", etc.)
            case "$target" in
                *[[:space:]]*|*[^a-zA-Z0-9._-]*) continue ;;
            esac
            [ ${#target} -gt 64 ] && continue
            ;;
    esac

    # Don't create circular symlinks
    stubname=$(basename "$stub")
    targetname=$(basename "$target")
    [ "$stubname" = "$targetname" ] && [ "$target" = "$targetname" ] && continue

    # Replace the stub with a symlink
    rm -f "$stub"
    ln -s "$target" "$stub"
    PASS1=$((PASS1 + 1))
done

# --- Pass 2: Versioned .so heuristic for remaining stubs ---
# Some corrupted .so stubs may have been pure null (no readable target).
# Match libfoo.so -> libfoo.so.X.Y.Z by name pattern.
for dir in /firmware/lib /firmware/usr/lib /firmware/lib32 /firmware/usr/lib32; do
    [ -d "$dir" ] || continue
    for stub in $(find "$dir" -maxdepth 1 \( -name '*.so' -o -name '*.so.[0-9]*' \) 2>/dev/null); do
        # Skip if already a symlink (fixed in pass 1)
        [ -L "$stub" ] && continue
        [ -f "$stub" ] || continue
        size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
        [ "$size" -lt 256 ] || continue
        base=$(basename "$stub")
        best=""
        best_len=0
        for candidate in "$dir"/${base}*; do
            [ -f "$candidate" ] || [ -L "$candidate" ] || continue
            cand_name=$(basename "$candidate")
            [ "$cand_name" = "$base" ] && continue
            cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
            [ "$cand_size" -gt 256 ] || [ -L "$candidate" ] || continue
            cand_len=${#cand_name}
            if [ "$cand_len" -gt "$best_len" ]; then
                best="$cand_name"
                best_len=$cand_len
            fi
        done
        if [ -n "$best" ]; then
            rm -f "$stub"
            ln -s "$best" "$stub"
            PASS2=$((PASS2 + 1))
        fi
    done
done

# --- Pass 3: Busybox fallback for remaining null stubs ---
# Only applies to files in bin/sbin dirs that are still tiny and not
# yet symlinks. This is the last resort for pure-null stubs.
bb=""
for candidate in /firmware/bin/busybox /firmware/usr/bin/busybox; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        cand_size=$(stat -c%s "$candidate" 2>/dev/null || echo 0)
        if [ "$cand_size" -gt 1000 ]; then
            # Strip /firmware prefix so symlinks work as both chroot
            # and ext4 root paths
            bb="${candidate#/firmware}"
            break
        fi
    fi
done
if [ -n "$bb" ]; then
    for dir in /firmware/bin /firmware/sbin /firmware/usr/bin /firmware/usr/sbin; do
        [ -d "$dir" ] || continue
        for stub in "$dir"/*; do
            # Skip symlinks (already fixed) and directories
            [ -L "$stub" ] && continue
            [ -f "$stub" ] || continue
            size=$(stat -c%s "$stub" 2>/dev/null || echo 999999)
            [ "$size" -lt 64 ] || continue
            name=$(basename "$stub")
            [ "$name" = "busybox" ] && continue
            # Verify it's actually null/empty content (not a real tiny script)
            content=$(tr -d '\000' < "$stub" 2>/dev/null)
            [ -z "$content" ] || continue
            rm -f "$stub"
            ln -s "$bb" "$stub"
            PASS3=$((PASS3 + 1))
        done
    done
fi

echo "Symlink repair: pass1=$PASS1 pass2=$PASS2 pass3=$PASS3"
"""
        result = container.exec_run(["sh", "-c", fix_symlinks_script])
        output = result.output.decode("utf-8", errors="replace").strip()
        if output:
            logger.info("Firmware symlink repair: %s", output)

    @staticmethod
    def _put_file_in_container(
        container: "docker.models.containers.Container",
        path: str,
        content: str,
        mode: int = 0o755,
    ) -> None:
        """Write a file into a Docker container using put_archive.

        This avoids heredoc/shell escaping issues that can corrupt file content
        when using container.exec_run with 'cat << EOF'.
        """
        filename = os.path.basename(path)
        directory = os.path.dirname(path)

        data = content.encode("utf-8")
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)
        container.put_archive(directory, tar_stream)

    # Map stub profile + architecture → list of .so filenames to inject
    STUB_PROFILE_MAP: dict[str, dict[str, list[str]]] = {
        "none": {},
        "generic": {
            "mipsel": ["stubs_generic_mipsel.so"],
            "mips": ["stubs_generic_mips.so"],
            "arm": ["stubs_generic_arm.so"],
            "aarch64": ["stubs_generic_aarch64.so"],
        },
        "tenda": {
            "mipsel": ["stubs_generic_mipsel.so", "stubs_tenda_mipsel.so"],
            "mips": ["stubs_generic_mips.so", "stubs_tenda_mips.so"],
            "arm": ["stubs_generic_arm.so", "stubs_tenda_arm.so"],
            "aarch64": ["stubs_generic_aarch64.so", "stubs_tenda_aarch64.so"],
        },
    }

    @staticmethod
    def _inject_stub_libraries(
        container: "docker.models.containers.Container",
        architecture: str | None,
        stub_profile: str = "none",
    ) -> None:
        """Copy arch-matched LD_PRELOAD stub libraries into the firmware rootfs.

        Pre-compiled stubs live in /opt/stubs/ inside the emulation container.
        Based on the stub_profile, copies the appropriate .so files into
        /firmware/opt/stubs/ so they're available inside the emulated firmware.

        Profiles:
          - "none": no stubs injected
          - "generic": MTD flash + wireless ioctl stubs
          - "tenda": generic + Tenda-specific function stubs
        """
        if stub_profile == "none" or not architecture:
            if stub_profile != "none":
                logger.debug("No architecture for stub injection, skipping")
            return

        arch_map = EmulationService.STUB_PROFILE_MAP.get(stub_profile, {})
        stub_files = arch_map.get(architecture, [])
        if not stub_files:
            logger.debug(
                "No stub libraries for profile=%s arch=%s", stub_profile, architecture
            )
            return

        # Build shell command to copy all stubs
        copy_cmds = ["mkdir -p /firmware/opt/stubs"]
        for stub_file in stub_files:
            copy_cmds.append(
                f"if [ -f /opt/stubs/{stub_file} ]; then "
                f"cp /opt/stubs/{stub_file} /firmware/opt/stubs/{stub_file} && "
                f"chmod 755 /firmware/opt/stubs/{stub_file} && "
                f"echo 'OK: {stub_file}'; else echo 'MISSING: {stub_file}'; fi"
            )

        result = container.exec_run(["sh", "-c", " && ".join(copy_cmds)])
        output = result.output.decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            if line.startswith("OK:"):
                logger.info("Injected stub: %s", line[4:].strip())
            elif line.startswith("MISSING:"):
                logger.warning("Stub not found in container: %s", line[9:].strip())

    def _find_initrd(
        self,
        kernel_path: str | None,
        kernel_name: str | None = None,
    ) -> str | None:
        """Find the initrd/initramfs companion for a kernel.

        Checks the kernel service sidecar metadata and convention-based
        naming (<kernel>.initrd).
        """
        if not kernel_path:
            return None

        svc = KernelService()

        # If kernel_name was specified, check sidecar directly
        if kernel_name:
            initrd = svc._initrd_path(kernel_name)
            if initrd:
                return initrd

        # Try convention: look for <kernel_basename>.initrd in the kernel dir
        kernel_basename = os.path.basename(kernel_path)
        initrd = svc._initrd_path(kernel_basename)
        if initrd:
            return initrd

        return None

    @staticmethod
    def _generate_init_wrapper(
        original_init: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> str:
        """Generate a wairz init wrapper script for system-mode emulation.

        The wrapper runs before the firmware's own init and handles:
        - Mounting proc, sysfs, devtmpfs, tmpfs
        - Configuring networking (QEMU user-mode always uses 10.0.2.0/24)
        - Setting LD_PRELOAD for stub libraries (based on stub_profile)
        - Sourcing an optional pre-init script for firmware-specific setup
        - Executing the firmware's original init or an interactive shell
        """
        if original_init:
            exec_line = f'exec {original_init}'
        else:
            exec_line = (
                '# Auto-detect init\n'
                'for candidate in /sbin/init /etc/preinit /sbin/procd /init /linuxrc; do\n'
                '    if [ -x "$candidate" ] || [ -L "$candidate" ]; then\n'
                '        exec "$candidate"\n'
                '    fi\n'
                'done\n'
                '# Fallback to shell\n'
                'echo "[wairz] No init found, dropping to shell"\n'
                'exec /bin/sh'
            )

        pre_init_block = ""
        if pre_init_script:
            pre_init_block = (
                '\n# --- User pre-init script ---\n'
                'if [ -f /wairz_pre_init.sh ]; then\n'
                '    echo "[wairz] Running pre-init script..."\n'
                '    chmod +x /wairz_pre_init.sh\n'
                '    . /wairz_pre_init.sh\n'
                '    echo "[wairz] Pre-init script finished (exit=$?)"\n'
                'fi'
            )

        stub_block = ""
        if stub_profile != "none":
            stub_block = (
                '# Export LD_PRELOAD for stub libraries based on stub_profile setting.\n'
                '# This ensures ALL processes started by the firmware\'s init inherit the stubs.\n'
                '# /etc/ld.so.preload is NOT supported by musl libc -- only the env var works.\n'
                'STUBS=""\n'
                'for f in /opt/stubs/stubs_*.so; do\n'
                '    [ -f "$f" ] && STUBS="$STUBS $f"\n'
                'done\n'
                'STUBS=$(echo "$STUBS" | sed \'s/^ //\')\n'
                'if [ -n "$STUBS" ]; then\n'
                '    export LD_PRELOAD="$STUBS"\n'
                '    echo "[wairz] LD_PRELOAD set: $LD_PRELOAD"\n'
                'else\n'
                '    echo "[wairz] No stub libraries found in /opt/stubs/"\n'
                'fi'
            )

        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "templates", "wairz_init_wrapper.sh",
        )
        with open(template_path) as f:
            template = f.read()

        return (
            template
            .replace("@@PRE_INIT_BLOCK@@", pre_init_block)
            .replace("@@STUB_BLOCK@@", stub_block)
            .replace("@@EXEC_LINE@@", exec_line)
        )

    @staticmethod
    def _inject_init_wrapper(
        container: "docker.models.containers.Container",
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> str:
        """Inject the wairz init wrapper into the firmware rootfs.

        Writes /firmware/wairz_init.sh (and optionally /firmware/wairz_pre_init.sh)
        into the container's firmware directory. These files will be included
        in the ext4 rootfs image created by start-system-mode.sh.

        Returns the init_path to pass to start-system-mode.sh ("/wairz_init.sh").
        """
        wrapper = EmulationService._generate_init_wrapper(
            init_path, pre_init_script, stub_profile=stub_profile
        )

        # Write scripts into the container using put_archive (avoids heredoc/escaping issues)
        EmulationService._put_file_in_container(container, "/firmware/wairz_init.sh", wrapper)

        # Write the pre-init script if provided
        if pre_init_script:
            EmulationService._put_file_in_container(container, "/firmware/wairz_pre_init.sh", pre_init_script)
            logger.info("Injected pre-init script (%d bytes)", len(pre_init_script))

        logger.info(
            "Injected init wrapper (original_init=%s, has_pre_init=%s)",
            init_path or "auto-detect",
            bool(pre_init_script),
        )
        return "/wairz_init.sh"

    async def _start_container(
        self,
        session: EmulationSession,
        extracted_path: str,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
        is_standalone: bool = False,
        binary_info: dict | None = None,
    ) -> str:
        """Spawn a Docker container for this emulation session."""
        client = self._get_docker_client()
        settings = self._settings

        # Resolve the extracted path to a host path for Docker volume mounts.
        # If None, the data is baked into the backend image (not on a volume),
        # so we'll use docker cp instead of a bind mount.
        real_path = os.path.realpath(extracted_path)
        host_path = self._resolve_host_path(real_path)
        use_docker_cp = host_path is None

        volumes = {}
        if not use_docker_cp:
            volumes[host_path] = {"bind": "/firmware", "mode": "rw"}

        # Build port bindings for system mode
        port_bindings = {}
        if session.port_forwards:
            for pf in session.port_forwards:
                host_ = pf.get("host", 0)
                if host_:
                    # QEMU listens on the host port INSIDE the container
                    # (hostfwd=tcp::HOST_PORT-:GUEST_PORT), so Docker must
                    # map the same port on both sides: host:PORT → container:PORT
                    port_bindings[f"{host_}/tcp"] = [{"HostPort": str(host_)}]

        # Resolve kernel path for system mode (backend-side path)
        kernel_backend_path = None
        initrd_backend_path = None
        if session.mode == "system":
            kernel_backend_path = self._find_kernel(
                session.architecture,
                kernel_name=kernel_name,
                firmware_kernel_path=firmware_kernel_path,
            )
            # Look for companion initrd
            initrd_backend_path = self._find_initrd(
                kernel_backend_path, kernel_name
            )
            if initrd_backend_path:
                logger.info("Found initrd: %s", initrd_backend_path)

        # Container-internal path where the kernel will be placed
        CONTAINER_KERNEL_PATH = "/tmp/kernel"

        common_labels = {
            "wairz.session_id": str(session.id),
            "wairz.project_id": str(session.project_id),
            "wairz.mode": session.mode,
        }

        if use_docker_cp:
            # Create container with "sleep infinity" so we can copy files via SDK.
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                cap_add=["SYS_ADMIN"],
                network_mode="bridge",
                labels=common_labels,
            )

            # Create /firmware dir, then copy the extracted filesystem into it
            # using the Docker SDK's put_archive (accepts a tar stream).
            container.exec_run(["mkdir", "-p", "/firmware"])

            logger.info("Copying firmware to emulation container via tar stream: %s", real_path)
            try:
                self._copy_dir_to_container(container, real_path, "/firmware")
            except Exception as exc:
                container.remove(force=True)
                raise RuntimeError(f"Failed to copy firmware to emulation container: {exc}")

            # Fix permissions — binwalk extraction may lose execute bits.
            self._fix_firmware_permissions(container)

        else:
            # Standard bind mount — host path is available
            container = client.containers.run(
                image=settings.emulation_image,
                command=["sleep", "infinity"],
                detach=True,
                volumes=volumes or None,
                ports=port_bindings or None,
                mem_limit=f"{settings.emulation_memory_limit_mb}m",
                nano_cpus=int(settings.emulation_cpu_limit * 1e9),
                privileged=False,
                cap_add=["SYS_ADMIN"],
                network_mode="bridge",
                labels=common_labels,
            )

            # Fix permissions — binwalk extraction may lose execute bits.
            self._fix_firmware_permissions(container)

        # Inject LD_PRELOAD stub libraries into the firmware rootfs.
        # Based on stub_profile, copies the appropriate .so files into
        # /firmware/opt/stubs/ so they end up in the ext4 rootfs for system mode
        # and in the chroot for user mode. The init wrapper handles LD_PRELOAD.
        self._inject_stub_libraries(container, session.architecture, stub_profile)

        # For user mode, ensure binfmt_misc is registered for the target
        # architecture so child processes (spawned by the QEMU-emulated shell)
        # are automatically handled by the kernel via the cached qemu-static fd.
        # Then copy qemu-static into the firmware rootfs for the explicit chroot.
        if session.mode == "user":
            self._ensure_binfmt_misc(session.architecture or "arm")
            arch = session.architecture or "arm"
            qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

            if is_standalone:
                # Standalone binary mode: no chroot, use QEMU directly with
                # -L pointing to the sysroot for library resolution.
                is_static = binary_info.get("is_static", False) if binary_info else False
                from app.services.sysroot_service import get_sysroot_path

                sysroot_path = get_sysroot_path(arch) if not is_static else None

                # Mark the container as standalone mode via a flag file
                # so exec_command and the WebSocket terminal know to use
                # the non-chroot execution path.
                container.exec_run([
                    "sh", "-c",
                    "touch /tmp/.standalone_mode && "
                    f"echo '{arch}' > /tmp/.standalone_arch && "
                    f"echo '{1 if is_static else 0}' > /tmp/.standalone_static"
                ])

                # Make the binary executable (must run as root since firmware
                # files are owned by root from the bind mount)
                container.exec_run(
                    ["sh", "-c", "chmod +x /firmware/* 2>/dev/null || true"],
                    user="root",
                )

                if sysroot_path and not is_static:
                    logger.info(
                        "Standalone binary mode (dynamic): arch=%s sysroot=%s",
                        arch, sysroot_path,
                    )
                else:
                    logger.info(
                        "Standalone binary mode (static): arch=%s", arch,
                    )
            else:
                # Standard firmware rootfs mode: chroot-based
                container.exec_run([
                    "sh", "-c",
                    f"cp $(which {qemu_bin}) /firmware/{qemu_bin} && "
                    f"chmod +x /firmware/{qemu_bin}"
                ])
                # Ensure /proc and /dev exist for binaries that need them
                container.exec_run([
                    "sh", "-c",
                    "mkdir -p /firmware/proc /firmware/dev /firmware/tmp /firmware/sys && "
                    "mount -t proc proc /firmware/proc 2>/dev/null || true && "
                    "mount --bind /dev /firmware/dev 2>/dev/null || true"
                ])
                logger.info(
                    "User-mode chroot prepared: copied %s into /firmware/",
                    qemu_bin,
                )

        # For system mode, copy the kernel into the container and launch QEMU
        if session.mode == "system":
            if not kernel_backend_path:
                # No valid kernel available — clean up the container
                container.remove(force=True)
                raise ValueError(
                    "System-mode emulation requires a valid kernel, but none was found. "
                    "The firmware-extracted kernel (if any) failed validation and no "
                    "pre-built kernels are available. Upload a QEMU-compatible kernel "
                    "via the Kernel Manager."
                )

            self._copy_file_to_container(
                container, kernel_backend_path, CONTAINER_KERNEL_PATH,
            )

            # Copy initrd if available
            CONTAINER_INITRD_PATH = "/tmp/initrd"
            initrd_arg = ""
            if initrd_backend_path and os.path.isfile(initrd_backend_path):
                self._copy_file_to_container(
                    container, initrd_backend_path, CONTAINER_INITRD_PATH,
                )
                initrd_arg = CONTAINER_INITRD_PATH
                logger.info("Copied initrd to container: %s", initrd_backend_path)

            # Inject init wrapper into the firmware rootfs. The wrapper
            # auto-mounts proc/sysfs, configures networking, sets LD_PRELOAD
            # based on stub_profile, sources the optional pre-init script,
            # then execs the original init.
            # This must happen before ext4 image creation in start-system-mode.sh.
            wrapper_init = self._inject_init_wrapper(
                container,
                init_path=init_path,
                pre_init_script=pre_init_script,
                stub_profile=stub_profile,
            )

            pf_str = ""
            if session.port_forwards:
                pf_str = ",".join(
                    f"{pf['host']}:{pf['guest']}" for pf in session.port_forwards
                )
            cmd = [
                "/opt/scripts/start-system-mode.sh",
                session.architecture or "arm",
                "/firmware",
                CONTAINER_KERNEL_PATH,
                pf_str,
                initrd_arg,
                wrapper_init,
            ]
            container.exec_run(cmd, detach=True)

            # Health check: wait briefly to catch early QEMU failures
            await self._await_system_startup(container)

        return container.id

    async def _await_system_startup(
        self,
        container: "docker.models.containers.Container",
        timeout: int = 30,
    ) -> None:
        """Wait briefly after QEMU launch and check for early failures.

        The startup script creates an ext4 rootfs image (takes a few seconds),
        decompresses the kernel if needed, then exec's to QEMU. We need to
        account for this preparation phase where the QEMU process doesn't
        exist yet but the startup script is still running.

        Checks each second whether the startup script or QEMU is still alive.
        If both are gone, reads /tmp/qemu-system.log and raises with the log
        content so the caller can set error status.
        """
        qemu_was_seen = False

        for i in range(timeout):
            await asyncio.sleep(1)

            # Check if the container itself is still running
            try:
                container.reload()
                if container.status not in ("running", "created"):
                    log = self._read_container_qemu_log(container, quiet=True)
                    raise RuntimeError(
                        f"Emulation container exited during startup.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
            except docker.errors.NotFound:
                raise RuntimeError("Emulation container disappeared during startup")

            # Check if either the startup script or QEMU process is alive.
            # During ext4 creation, only the script runs. After exec, only
            # QEMU runs. If neither is found, something failed.
            try:
                result = container.exec_run(
                    ["sh", "-c",
                     "pgrep -f 'qemu-system' >/dev/null 2>&1 && echo qemu || "
                     "(pgrep -f 'start-system-mode' >/dev/null 2>&1 && echo script || echo none)"],
                )
                output = result.output.decode("utf-8", errors="replace").strip()

                if output == "qemu":
                    qemu_was_seen = True
                elif output == "none":
                    if qemu_was_seen:
                        # QEMU was running but now it's gone — it crashed
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"QEMU process exited during startup.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    elif i > 15:
                        # Neither script nor QEMU found after 15s — something is wrong
                        log = self._read_container_qemu_log(container)
                        raise RuntimeError(
                            f"Neither startup script nor QEMU found after {i}s.\n\n"
                            f"--- QEMU log ---\n{log}"
                        )
                    # else: still early, script may not have started yet
            except docker.errors.APIError:
                pass  # Container may be in a transient state

            # Check if the serial socket appeared (means QEMU is up and listening)
            try:
                result = container.exec_run(["test", "-S", "/tmp/qemu-serial.sock"])
                if result.exit_code == 0:
                    logger.info("QEMU serial socket ready after %ds", i + 1)
                    return  # QEMU is healthy
            except docker.errors.APIError:
                pass

        # Timeout without socket, but QEMU is still running — that's OK,
        # it may just be slow (ext4 creation, kernel boot). Let it continue.
        logger.info(
            "QEMU still starting after %ds (no serial socket yet), "
            "continuing in background",
            timeout,
        )

    @staticmethod
    def _read_container_qemu_log(
        container: "docker.models.containers.Container",
        max_bytes: int = 4000,
        quiet: bool = False,
    ) -> str:
        """Read /tmp/qemu-system.log from inside a container.

        Returns the log content (truncated to max_bytes) or a fallback
        message if the log is not available.
        """
        try:
            result = container.exec_run(["cat", "/tmp/qemu-system.log"])
            log = result.output.decode("utf-8", errors="replace")
            if len(log) > max_bytes:
                log = log[-max_bytes:] + "\n... [truncated]"
            return log.strip() if log.strip() else "(log file is empty)"
        except Exception:
            if not quiet:
                logger.debug("Could not read QEMU log from container", exc_info=True)
            # Fall back to container logs
            try:
                log = container.logs(tail=50).decode("utf-8", errors="replace")
                return log.strip() if log.strip() else "(no log available)"
            except Exception:
                logger.debug("Failed to read container logs", exc_info=True)
                return "(no log available)"

    def _find_kernel(
        self,
        arch: str | None,
        kernel_name: str | None = None,
        firmware_kernel_path: str | None = None,
    ) -> str:
        """Find a kernel for system-mode emulation.

        Priority order:
        1. Explicit kernel_name (user-specified from kernel management)
        2. Kernel extracted from the firmware during unpacking
        3. Pre-built kernels in emulation_kernel_dir (matching architecture)
        """
        kernel_dir = self._settings.emulation_kernel_dir

        # 1) User-specified kernel from the kernel management system
        if kernel_name:
            if "/" in kernel_name or "\\" in kernel_name or ".." in kernel_name:
                raise ValueError(f"Invalid kernel name: {kernel_name}")
            kernel_path = os.path.join(kernel_dir, kernel_name)
            if not os.path.isfile(kernel_path):
                raise ValueError(
                    f"Kernel '{kernel_name}' not found in {kernel_dir}. "
                    "Upload a kernel via the kernel management API."
                )
            return kernel_path

        # 2) Kernel extracted from the firmware itself — validate before using
        if firmware_kernel_path and os.path.isfile(firmware_kernel_path):
            is_valid, reason = _validate_kernel_file(firmware_kernel_path)
            if is_valid:
                logger.info(
                    "Using kernel extracted from firmware: %s (%s)",
                    firmware_kernel_path, reason,
                )
                return firmware_kernel_path
            else:
                logger.warning(
                    "Firmware kernel candidate rejected: %s — %s. "
                    "Falling through to pre-built kernels.",
                    firmware_kernel_path, reason,
                )

        # 3) Pre-built kernel from the kernel management directory
        svc = KernelService()
        match = svc.find_kernel_for_arch(arch or "arm")
        if match:
            return os.path.join(kernel_dir, match["name"])

        raise ValueError(
            f"No kernel available for architecture '{arch or 'arm'}'. "
            "System-mode emulation requires a pre-built Linux kernel. "
            "A kernel was not found in the firmware image. "
            "Upload one via the kernel management page or API "
            "(GET/POST /api/v1/kernels)."
        )

    @staticmethod
    def build_user_shell_cmd(
        arch: str,
        is_standalone: bool = False,
        binary_path: str | None = None,
        is_static: bool = False,
    ) -> list[str]:
        """Return the command list for an interactive QEMU user-mode shell.

        For firmware rootfs mode: uses chroot so all firmware paths work
        naturally (e.g., /bin/foo resolves to /firmware/bin/foo).

        For standalone binary mode: uses QEMU directly with -L for sysroot,
        running the binary without a chroot.
        """
        qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

        if is_standalone and binary_path:
            from app.services.sysroot_service import get_sysroot_path

            # For standalone binaries, run QEMU directly (no chroot)
            # The binary is at /firmware/<binary_name>
            full_binary = f"/firmware/{binary_path.lstrip('/')}"
            qemu_path = f"/usr/bin/{qemu_bin}"

            if is_static:
                return [qemu_path, full_binary]
            else:
                sysroot = get_sysroot_path(arch) or "/opt/sysroots/arm"
                return [qemu_path, "-L", sysroot, full_binary]

        # Standard firmware rootfs mode
        return ["chroot", "/firmware", f"/{qemu_bin}", "/bin/sh"]

    async def stop_session(self, session_id: UUID) -> EmulationSession:
        """Stop an emulation session and remove its container."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status in ("stopped", "error"):
            return session

        # Stop the Docker container
        if session.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(session.container_id)
                session.logs = self._read_container_qemu_log(container, max_bytes=8000)
                container.stop(timeout=5)
                container.remove(force=True)
            except docker.errors.NotFound:
                logger.info("Container already removed: %s", session.container_id)
            except Exception:
                logger.exception("Error stopping container: %s", session.container_id)

        session.status = "stopped"
        session.stopped_at = datetime.now(timezone.utc)
        await self.db.flush()
        return session

    async def delete_session(self, session_id: UUID) -> None:
        """Delete a stopped or errored emulation session record."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")
        if session.status in ("running", "starting"):
            raise ValueError("Cannot delete an active session — stop it first")
        await self.db.delete(session)
        await self.db.flush()

    async def exec_command(
        self,
        session_id: UUID,
        command: str,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
    ) -> dict:
        """Execute a command inside a running emulation session."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")

        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = self._get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError("Container not found — session may have been terminated")

        # Build exec command.
        # User mode: chroot into /firmware so all firmware paths work naturally.
        # The qemu-static binary was copied into /firmware/ during session start.
        # System mode: send command through QEMU's serial console socket.
        #
        # Environment variables are prepended as shell exports so they're
        # available to the command inside the chroot/emulated system.
        env_prefix = ""
        if environment:
            exports = " ".join(
                f"export {shlex.quote(k)}={shlex.quote(v)};"
                for k, v in environment.items()
            )
            env_prefix = exports + " "

        if session.mode == "user":
            arch = session.architecture or "arm"
            qemu_bin = QEMU_USER_BIN_MAP.get(arch, "qemu-arm-static")

            # Check if this is a standalone binary session (marker set in _start_container)
            standalone_check = container.exec_run(
                ["test", "-f", "/tmp/.standalone_mode"], demux=True,
            )
            is_standalone = standalone_check.exit_code == 0

            if is_standalone:
                # Standalone binary mode: run QEMU directly with sysroot
                from app.services.sysroot_service import get_sysroot_path

                static_check = container.exec_run(
                    ["cat", "/tmp/.standalone_static"], demux=True,
                )
                is_static = False
                if static_check.exit_code == 0:
                    stdout = static_check.output[0] if isinstance(static_check.output, tuple) else static_check.output
                    is_static = stdout and stdout.strip() == b"1"

                sysroot = get_sysroot_path(arch)
                ld_prefix = f"QEMU_LD_PREFIX={sysroot} " if sysroot and not is_static else ""

                # Apply shlex.quote to the binary path so filenames with
                # spaces, quotes, or other shell metacharacters don't break
                # the single-shell expansion here.  `command` is user-
                # supplied exec intent (by design) and is kept as-is.
                quoted_binary = shlex.quote((session.binary_path or "").lstrip("/"))
                exec_cmd = [
                    "timeout", str(timeout),
                    "sh", "-c",
                    f"{ld_prefix}{env_prefix}/usr/bin/{qemu_bin} /firmware/{quoted_binary} {command}",
                ]
            else:
                # Standard firmware rootfs mode: chroot
                exec_cmd = [
                    "timeout", str(timeout),
                    "chroot", "/firmware",
                    f"/{qemu_bin}", "/bin/sh", "-c", env_prefix + command,
                ]
        else:
            # System mode: use serial-exec.sh to send commands through the
            # QEMU serial console socket with proper output capture.
            # The script wraps the command in unique markers, keeps the socat
            # connection alive until output is captured, and extracts the
            # guest command's stdout and exit code.
            full_cmd = env_prefix + command if env_prefix else command
            exec_cmd = [
                "/opt/scripts/serial-exec.sh",
                full_cmd,
                str(timeout),
            ]

        try:
            exec_result = container.exec_run(exec_cmd, demux=True)

            stdout_bytes = exec_result.output[0] if exec_result.output[0] else b""
            stderr_bytes = exec_result.output[1] if exec_result.output[1] else b""
            exit_code = exec_result.exit_code

            # `timeout` and serial-exec.sh return exit code 124 for timeouts
            timed_out = exit_code == 124

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            # Strip ANSI escape codes and residual markers (safety net for
            # anything serial-exec.sh misses or user-mode terminal output)
            if session.mode == "system":
                stdout_str = _ANSI_RE.sub("", stdout_str)
                stdout_str = _MARKER_RE.sub("", stdout_str)
                stderr_str = _ANSI_RE.sub("", stderr_str)

            # For system mode, the serial-exec.sh script outputs a timeout
            # marker if no response was received from the guest
            if session.mode == "system" and "WAIRZ_SERIAL_TIMEOUT" in stdout_str:
                # Strip the marker and return whatever raw serial output was captured
                stdout_str = stdout_str.replace("WAIRZ_SERIAL_TIMEOUT\n", "").strip()
                if not stderr_str:
                    stderr_str = (
                        "No response from serial console within timeout. "
                        "The guest OS may still be booting or no shell is available."
                    )
                timed_out = True

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": exit_code if not timed_out else -1,
                "timed_out": timed_out,
            }

        except Exception as exc:
            raise ValueError(f"Command execution failed: {exc}")

    async def send_ctrl_c(self, session_id: UUID) -> dict:
        """Send Ctrl-C to a running system-mode emulation session.

        This kills any stuck foreground process on the serial console,
        allowing subsequent commands to execute. Only works for system-mode
        sessions (user-mode sessions don't have a serial console).
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")
        if session.status != "running":
            raise ValueError(f"Session is not running (status: {session.status})")
        if session.mode != "system":
            raise ValueError("send_ctrl_c is only supported for system-mode sessions")
        if not session.container_id:
            raise ValueError("No container associated with this session")

        client = self._get_docker_client()
        try:
            container = client.containers.get(session.container_id)
        except docker.errors.NotFound:
            session.status = "error"
            session.error_message = "Container not found"
            await self.db.flush()
            raise ValueError("Container not found — session may have been terminated")

        # Send Ctrl-C (\x03) followed by a newline to the serial socket
        ctrl_c_cmd = [
            "sh", "-c",
            "printf '\\x03\\n' | socat - UNIX-CONNECT:/tmp/qemu-serial.sock",
        ]
        try:
            exec_result = container.exec_run(ctrl_c_cmd, demux=True)
            stdout = (exec_result.output[0] or b"").decode("utf-8", errors="replace")
            return {
                "success": exec_result.exit_code == 0,
                "message": "Ctrl-C sent to serial console" if exec_result.exit_code == 0 else f"Failed: {stdout}",
            }
        except Exception as exc:
            raise ValueError(f"Failed to send Ctrl-C: {exc}")

    async def get_status(self, session_id: UUID) -> EmulationSession:
        """Get the status of an emulation session, updating from Docker if running."""
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        # If session claims to be running, verify with Docker
        if session.status == "running" and session.container_id:
            try:
                client = self._get_docker_client()
                container = client.containers.get(session.container_id)
                if container.status not in ("running", "created"):
                    # Container died — try to read QEMU log for diagnostics
                    log = self._read_container_qemu_log(container, quiet=True)
                    session.status = "error"
                    session.error_message = (
                        f"Emulation container exited unexpectedly.\n\n"
                        f"--- QEMU log ---\n{log}"
                    )
                    session.stopped_at = datetime.now(timezone.utc)
                    await self.db.flush()
                elif session.mode == "system":
                    # Container is running, but check if QEMU process inside is alive
                    try:
                        check = container.exec_run(
                            ["sh", "-c", "pgrep -f 'qemu-system' >/dev/null 2>&1; echo $?"],
                        )
                        output = check.output.decode("utf-8", errors="replace").strip()
                        if output != "0":
                            log = self._read_container_qemu_log(container)
                            session.status = "error"
                            session.error_message = (
                                f"QEMU process has exited.\n\n"
                                f"--- QEMU log ---\n{log}"
                            )
                            session.stopped_at = datetime.now(timezone.utc)
                            await self.db.flush()
                    except docker.errors.APIError:
                        pass  # transient Docker error, don't update status
            except docker.errors.NotFound:
                session.status = "stopped"
                session.error_message = "Container no longer exists"
                session.stopped_at = datetime.now(timezone.utc)
                await self.db.flush()
            except Exception:
                logger.exception("Error checking container status")

        return session

    async def list_sessions(self, project_id: UUID) -> list[EmulationSession]:
        """List all emulation sessions for a project."""
        result = await self.db.execute(
            select(EmulationSession)
            .where(EmulationSession.project_id == project_id)
            .order_by(EmulationSession.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_session_logs(self, session_id: UUID) -> str:
        """Read QEMU startup logs from a session's container.

        Works for both running and recently-stopped containers.
        Returns the log text or an explanatory message.
        """
        result = await self.db.execute(
            select(EmulationSession).where(EmulationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise ValueError("Session not found")

        if not session.container_id:
            # No container — return stored error_message if available
            if session.error_message:
                return session.error_message
            return "No container associated with this session — no logs available."

        try:
            client = self._get_docker_client()
            container = client.containers.get(session.container_id)
            return self._read_container_qemu_log(container, max_bytes=8000)
        except docker.errors.NotFound:
            # Container removed — return saved logs or error_message
            if session.logs:
                return session.logs
            if session.error_message:
                return session.error_message
            return "Container has been removed — no logs available."
        except Exception as exc:
            return f"Failed to read logs: {exc}"

    async def cleanup_expired(self) -> int:
        """Stop sessions that have exceeded the timeout. Returns count stopped."""
        timeout_minutes = self._settings.emulation_timeout_minutes
        cutoff = datetime.now(timezone.utc).timestamp() - (timeout_minutes * 60)

        result = await self.db.execute(
            select(EmulationSession).where(
                EmulationSession.status == "running",
                EmulationSession.started_at.isnot(None),
            )
        )
        sessions = result.scalars().all()
        count = 0

        for session in sessions:
            if session.started_at and session.started_at.timestamp() < cutoff:
                try:
                    await self.stop_session(session.id)
                    count += 1
                except Exception:
                    logger.exception("Failed to stop expired session: %s", session.id)

        return count

    # ── Emulation Presets (delegated to EmulationPresetService) ──

    async def create_preset(
        self,
        project_id: UUID,
        name: str,
        mode: str,
        description: str | None = None,
        binary_path: str | None = None,
        arguments: str | None = None,
        architecture: str | None = None,
        port_forwards: list[dict] | None = None,
        kernel_name: str | None = None,
        init_path: str | None = None,
        pre_init_script: str | None = None,
        stub_profile: str = "none",
    ) -> EmulationPreset:
        """Create a new emulation preset for a project."""
        return await EmulationPresetService(self.db).create_preset(
            project_id=project_id,
            name=name,
            mode=mode,
            description=description,
            binary_path=binary_path,
            arguments=arguments,
            architecture=architecture,
            port_forwards=port_forwards,
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )

    async def list_presets(self, project_id: UUID) -> list[EmulationPreset]:
        """List all emulation presets for a project."""
        return await EmulationPresetService(self.db).list_presets(project_id)

    async def get_preset(self, preset_id: UUID) -> EmulationPreset:
        """Get a single emulation preset by ID."""
        return await EmulationPresetService(self.db).get_preset(preset_id)

    async def update_preset(
        self, preset_id: UUID, updates: dict
    ) -> EmulationPreset:
        """Update an existing emulation preset."""
        return await EmulationPresetService(self.db).update_preset(preset_id, updates)

    async def delete_preset(self, preset_id: UUID) -> None:
        """Delete an emulation preset."""
        await EmulationPresetService(self.db).delete_preset(preset_id)
