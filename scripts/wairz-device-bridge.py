#!/usr/bin/env python3
"""Wairz Device Bridge — standalone TCP-to-ADB bridge for MCP tool access.

Bridges ADB device access to a TCP server, following the same architecture as
wairz-uart-bridge.py. JSON-over-TCP protocol (newline-delimited) with
request/response matching by ID.

Usage:
    python wairz-device-bridge.py --port 9998 --bind 127.0.0.1
    python wairz-device-bridge.py --port 9998 --mock   # Mock mode (no real device)

Dependencies: None beyond Python stdlib + `adb` on PATH (for real mode).
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("wairz-device-bridge")

# Stall timeout: abort dump if no bytes received for this many seconds
DUMP_STALL_TIMEOUT = 60
# Block size for dd reads
DUMP_BLOCK_SIZE = 4 * 1024 * 1024  # 4 MB
# Progress event interval (bytes)
PROGRESS_INTERVAL = 4 * 1024 * 1024  # Every 4 MB


def _make_progress_event(
    partition: str,
    bytes_written: int,
    total_bytes: int | None,
    elapsed: float,
) -> dict:
    """Build a progress event dict with optional percentage and throughput."""
    event: dict = {
        "event": "progress",
        "partition": partition,
        "bytes_written": bytes_written,
    }
    if total_bytes and total_bytes > 0:
        event["total_bytes"] = total_bytes
        event["progress_percent"] = round(bytes_written / total_bytes * 100, 1)
    if elapsed > 0 and bytes_written > 0:
        event["throughput_mbps"] = round(
            bytes_written / (1024 * 1024) / elapsed, 1
        )
    return event


# ---------------------------------------------------------------------------
# Mock data for --mock mode
# ---------------------------------------------------------------------------

MOCK_DEVICE = {
    "serial": "MOCK001",
    "model": "Mock_Device",
    "device": "mock",
    "transport_id": "1",
    "state": "device",
}

MOCK_GETPROP = """\
[ro.build.display.id]: [RP1A.200720.009]
[ro.build.version.incremental]: [6934943]
[ro.build.version.sdk]: [30]
[ro.build.version.release]: [11]
[ro.build.type]: [userdebug]
[ro.build.flavor]: [mock_device-userdebug]
[ro.product.model]: [Mock_Device]
[ro.product.brand]: [generic]
[ro.product.name]: [mock_device]
[ro.product.device]: [mock]
[ro.product.board]: [mock]
[ro.product.cpu.abi]: [arm64-v8a]
[ro.hardware]: [mock]
[ro.serialno]: [MOCK001]
[ro.bootimage.build.fingerprint]: [generic/mock_device/mock:11/RP1A.200720.009/6934943:userdebug/dev-keys]
[ro.secure]: [1]
[ro.debuggable]: [1]
[persist.sys.usb.config]: [mtp,adb]
[sys.usb.state]: [mtp,adb]
[ro.crypto.state]: [encrypted]
[ro.boot.verifiedbootstate]: [orange]
[ro.boot.flash.locked]: [0]
"""

MOCK_PARTITIONS = [
    "boot", "dtbo", "metadata", "misc", "modem", "recovery",
    "super", "system", "userdata", "vbmeta", "vendor",
]

# Realistic mock partition sizes (bytes)
MOCK_PARTITION_SIZES = {
    "boot": 67108864,       # 64 MB
    "dtbo": 8388608,        # 8 MB
    "metadata": 16777216,   # 16 MB
    "misc": 1048576,        # 1 MB
    "modem": 134217728,     # 128 MB
    "recovery": 67108864,   # 64 MB
    "super": 8589934592,    # 8 GB
    "system": 3221225472,   # 3 GB
    "userdata": 53687091200,  # 50 GB
    "vbmeta": 65536,        # 64 KB
    "vendor": 536870912,    # 512 MB
}


# MediaTek USB identifiers for BROM/preloader mode detection
MTK_BROM_VID_PID = ("0e8d", "0003")
MTK_PRELOADER_VID_PID = ("0e8d", "2000")

MOCK_MTK_DEVICE = {
    "serial": "MTK_MOCK001",
    "mode": "brom",
    "chipset": "MT6765",
    "model": "Mock MediaTek (BROM)",
    "state": "brom",
    "available": True,
}

MOCK_MTK_PARTITIONS = [
    {"name": "boot", "size": 67108864},
    {"name": "recovery", "size": 67108864},
    {"name": "super", "size": 8589934592},
    {"name": "vbmeta", "size": 65536},
    {"name": "md1img", "size": 134217728},
    {"name": "lk", "size": 1048576},
    {"name": "tee", "size": 10485760},
    {"name": "preloader", "size": 262144},
]


# ---------------------------------------------------------------------------
# DeviceManager — manages ADB/MTK interactions and dump state
# ---------------------------------------------------------------------------

class DeviceManager:
    """Manages ADB and MTKClient device interactions and partition dump state."""

    def __init__(self, mock: bool = False) -> None:
        self._mock = mock
        self._current_dump: dict | None = None  # Tracks in-progress dump
        self._cancel_event = asyncio.Event()
        self._completed_partitions: list[dict] = []
        self._mtk_available: bool | None = None  # Cached mtk CLI check

    @property
    def is_dumping(self) -> bool:
        return self._current_dump is not None

    def _check_mtk_available(self) -> bool:
        """Check if mtkclient CLI is installed."""
        if self._mtk_available is None:
            self._mtk_available = shutil.which("mtk") is not None
        return self._mtk_available

    async def list_devices(self) -> list[dict]:
        """List connected ADB and MTKClient devices."""
        if self._mock:
            return [
                {**MOCK_DEVICE.copy(), "mode": "adb"},
                MOCK_MTK_DEVICE.copy(),
            ]

        # Get ADB devices
        adb_devices = await self._list_adb_devices()

        # Get MTK BROM/preloader devices
        mtk_devices = await self._detect_mtk_devices()

        return adb_devices + mtk_devices

    async def _list_adb_devices(self) -> list[dict]:
        """List connected ADB devices."""
        try:
            stdout = await self._run_adb("devices", "-l")
        except RuntimeError:
            return []
        devices = []
        for line in stdout.strip().splitlines()[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            state = parts[1]
            attrs = {}
            for part in parts[2:]:
                if ":" in part:
                    key, _, val = part.partition(":")
                    attrs[key] = val
            devices.append({
                "serial": serial,
                "mode": "adb",
                "model": attrs.get("model", ""),
                "device": attrs.get("device", ""),
                "transport_id": attrs.get("transport_id", ""),
                "state": state,
            })
        return devices

    async def _detect_mtk_devices(self) -> list[dict]:
        """Detect MediaTek devices in BROM or preloader mode via lsusb."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "lsusb",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await proc.communicate()
            stdout = stdout_bytes.decode("utf-8", errors="replace")
        except (FileNotFoundError, OSError):
            return []

        devices = []
        mtk_available = self._check_mtk_available()
        idx = 0

        for line in stdout.strip().splitlines():
            line_lower = line.lower()
            mode = None
            if f"{MTK_BROM_VID_PID[0]}:{MTK_BROM_VID_PID[1]}" in line_lower:
                mode = "brom"
            elif f"{MTK_PRELOADER_VID_PID[0]}:{MTK_PRELOADER_VID_PID[1]}" in line_lower:
                mode = "preloader"

            if mode:
                devices.append({
                    "serial": f"MTK_{mode.upper()}_{idx}",
                    "mode": mode,
                    "chipset": None,
                    "model": f"MediaTek ({mode.upper()})",
                    "state": mode,
                    "available": mtk_available,
                    "error": None if mtk_available else "mtkclient not installed (pip install mtkclient)",
                })
                idx += 1

        return devices

    async def get_device_info(self, device_id: str) -> dict:
        """Get device properties, partition list, and partition sizes."""
        if self._mock:
            # Return mock data based on device_id prefix
            if device_id.startswith("MTK_"):
                return self._mock_mtk_device_info()
            partition_info = [
                {"name": p, "size": MOCK_PARTITION_SIZES.get(p)}
                for p in MOCK_PARTITIONS
            ]
            return {
                "getprop": MOCK_GETPROP,
                "partitions": MOCK_PARTITIONS[:],
                "partition_sizes": partition_info,
                "mode": "adb",
            }

        # Route based on device mode
        if device_id.startswith("MTK_"):
            return await self._mtk_get_device_info()

        return await self._adb_get_device_info(device_id)

    def _mock_mtk_device_info(self) -> dict:
        """Return mock MTK device info."""
        partitions = [p["name"] for p in MOCK_MTK_PARTITIONS]
        return {
            "getprop": "",
            "partitions": partitions,
            "partition_sizes": MOCK_MTK_PARTITIONS[:],
            "mode": "brom",
            "chipset": "MT6765",
        }

    async def _adb_get_device_info(self, device_id: str) -> dict:
        """Get ADB device properties, partition list, and sizes."""
        getprop = await self._run_adb("-s", device_id, "shell", "getprop")
        try:
            partitions_raw = await self._run_adb(
                "-s", device_id, "shell", "ls /dev/block/by-name/"
            )
            partitions = [
                p.strip() for p in partitions_raw.strip().splitlines() if p.strip()
            ]
        except RuntimeError:
            partitions = []

        # Query partition sizes in one batch command
        partition_info = []
        if partitions:
            sizes = await self._get_partition_sizes(device_id, partitions)
            for p in partitions:
                partition_info.append({"name": p, "size": sizes.get(p)})

        return {
            "getprop": getprop,
            "partitions": partitions,
            "partition_sizes": partition_info,
            "mode": "adb",
        }

    async def _mtk_get_device_info(self) -> dict:
        """Get MTK device partition table via mtk printgpt."""
        if not self._check_mtk_available():
            raise RuntimeError("mtkclient not installed (pip install mtkclient)")

        mtk_path = shutil.which("mtk")
        proc = await asyncio.create_subprocess_exec(
            mtk_path, "printgpt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=60,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise RuntimeError("mtk printgpt timed out (60s). Is the device in BROM mode?")

        if proc.returncode != 0:
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            # Check for common errors
            combined = (stderr + stdout).lower()
            if "no device" in combined or "not found" in combined:
                raise RuntimeError("No MediaTek device found. Ensure device is in BROM mode.")
            if "permission" in combined or "access" in combined:
                raise RuntimeError(
                    "USB permission denied. Run: sudo cp mtkclient/Setup/Linux/*.rules "
                    "/etc/udev/rules.d/ && sudo udevadm control --reload-rules"
                )
            raise RuntimeError(f"mtk printgpt failed: {stderr or stdout}")

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        partitions, partition_info = self._parse_printgpt(stdout)

        # Try to detect chipset from mtk output
        chipset = None
        for line in stdout.splitlines():
            line_lower = line.lower()
            if "mt" in line_lower and any(c.isdigit() for c in line):
                import re
                match = re.search(r'(MT\d{4}[A-Za-z]*)', line, re.IGNORECASE)
                if match:
                    chipset = match.group(1).upper()
                    break

        return {
            "getprop": "",
            "partitions": partitions,
            "partition_sizes": partition_info,
            "mode": "brom",
            "chipset": chipset,
        }

    @staticmethod
    def _parse_printgpt(output: str) -> tuple[list[str], list[dict]]:
        """Parse mtk printgpt output to extract partition names and sizes.

        The output format varies but typically contains lines like:
          GPT Table:
          Name            Start LBA       End LBA         Size
          preloader       0x00000000      0x000003ff      512.0 KB
          boot            0x00008000      0x00017fff      64.0 MB
          system          0x00100000      0x006fffff      3.0 GB
          ...

        Or structured lines with partition info containing name, offset, size.
        """
        import re

        partitions: list[str] = []
        partition_info: list[dict] = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith(("GPT", "---", "Name", "===")):
                continue

            # Try to match: name  start_lba  end_lba  size_str
            # Or: name  offset  size
            parts = line.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            # Skip non-partition lines (headers, status messages, chipset IDs)
            if name.lower() in ("gpt", "table", "entry", "name", "start", "end", "partition"):
                continue
            # Skip chipset identifiers (e.g., MTK6765, MT6789)
            if re.match(r'^(MT|MTK)\d', name, re.IGNORECASE):
                continue
            # Skip info/status lines
            if name.startswith("[") or name.startswith("#"):
                continue
            # Partition names are alphanumeric with underscores
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', name):
                continue
            # Must contain at least one hex value or size to be a partition line
            if not re.search(r'0x[0-9a-fA-F]+|\d+\.\d+\s*(KB|MB|GB)', line, re.IGNORECASE):
                continue

            # Try to extract size from the line
            size_bytes = None
            # Look for size pattern like "64.0 MB", "3.0 GB", "512.0 KB"
            size_match = re.search(
                r'(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB|B)\b', line, re.IGNORECASE
            )
            if size_match:
                val = float(size_match.group(1))
                unit = size_match.group(2).upper()
                multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
                size_bytes = int(val * multipliers.get(unit, 1))
            else:
                # Try hex size: look for two hex values that could be start/end LBA
                hex_vals = re.findall(r'0x([0-9a-fA-F]+)', line)
                if len(hex_vals) >= 2:
                    try:
                        start = int(hex_vals[0], 16)
                        end = int(hex_vals[1], 16)
                        if end > start:
                            size_bytes = (end - start + 1) * 512  # LBA sector size
                    except ValueError:
                        pass

            partitions.append(name)
            partition_info.append({"name": name, "size": size_bytes})

        return partitions, partition_info

    async def _get_partition_sizes(
        self, device_id: str, partitions: list[str]
    ) -> dict[str, int | None]:
        """Query partition sizes via blockdev --getsize64 on the device."""
        # Build a single shell command that queries all partitions at once
        cmds = " && ".join(
            f'echo "{p}:$(blockdev --getsize64 /dev/block/by-name/{p} 2>/dev/null || echo -1)"'
            for p in partitions
        )
        try:
            stdout = await self._run_adb(
                "-s", device_id, "shell", f"su -c '{cmds}'"
            )
        except RuntimeError:
            # Fallback: try without su (some devices allow blockdev without root shell)
            try:
                stdout = await self._run_adb(
                    "-s", device_id, "shell", cmds
                )
            except RuntimeError:
                return {}

        sizes: dict[str, int | None] = {}
        for line in stdout.strip().splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            name, _, val = line.partition(":")
            try:
                size = int(val)
                sizes[name] = size if size > 0 else None
            except ValueError:
                sizes[name] = None
        return sizes

    async def _get_partition_size(
        self, device_id: str, partition: str
    ) -> int | None:
        """Query a single partition's size. Returns None if unknown."""
        if self._mock:
            if device_id.startswith("MTK_"):
                for p in MOCK_MTK_PARTITIONS:
                    if p["name"] == partition:
                        return p["size"]
                return None
            return MOCK_PARTITION_SIZES.get(partition)
        if device_id.startswith("MTK_"):
            # For MTK devices, we already got sizes from printgpt
            # The caller should have cached them; return None as fallback
            return None
        sizes = await self._get_partition_sizes(device_id, [partition])
        return sizes.get(partition)

    async def dump_partition(
        self,
        device_id: str,
        partition: str,
        output_dir: str,
        writer: asyncio.StreamWriter,
        req_id: str,
    ) -> dict:
        """Dump a single partition to a file, sending progress events."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        dest = output_path / f"{partition}.img"

        # Pre-query partition size for progress percentage
        total_bytes = await self._get_partition_size(device_id, partition)

        self._current_dump = {
            "device_id": device_id,
            "partition": partition,
            "bytes_written": 0,
            "total_bytes": total_bytes,
            "started_at": time.monotonic(),
            "status": "running",
        }
        self._cancel_event.clear()

        try:
            if self._mock:
                return await self._mock_dump_partition(
                    partition, dest, writer, req_id, total_bytes
                )
            if device_id.startswith("MTK_"):
                return await self._mtk_dump_partition(
                    partition, dest, writer, req_id, total_bytes
                )
            return await self._real_dump_partition(
                device_id, partition, dest, writer, req_id, total_bytes
            )
        finally:
            self._current_dump = None

    async def _real_dump_partition(
        self,
        device_id: str,
        partition: str,
        dest: Path,
        writer: asyncio.StreamWriter,
        req_id: str,
        total_bytes: int | None = None,
    ) -> dict:
        """Dump a real partition via adb exec-out dd."""
        proc = await asyncio.create_subprocess_exec(
            "adb", "-s", device_id, "exec-out",
            "dd", f"if=/dev/block/by-name/{partition}", f"bs={DUMP_BLOCK_SIZE}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        bytes_written = 0
        last_progress_bytes = 0
        last_data_time = time.monotonic()
        start_time = time.monotonic()

        try:
            with open(dest, "wb") as f:
                while True:
                    if self._cancel_event.is_set():
                        proc.kill()
                        return {
                            "status": "cancelled",
                            "partition": partition,
                            "bytes_written": bytes_written,
                        }

                    try:
                        chunk = await asyncio.wait_for(
                            proc.stdout.read(65536), timeout=DUMP_STALL_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        proc.kill()
                        return {
                            "status": "error",
                            "partition": partition,
                            "error": f"Stall timeout: no data received for {DUMP_STALL_TIMEOUT}s",
                            "bytes_written": bytes_written,
                        }

                    if not chunk:
                        break

                    f.write(chunk)
                    bytes_written += len(chunk)
                    last_data_time = time.monotonic()

                    if self._current_dump:
                        self._current_dump["bytes_written"] = bytes_written

                    # Send progress event
                    if bytes_written - last_progress_bytes >= PROGRESS_INTERVAL:
                        last_progress_bytes = bytes_written
                        elapsed = time.monotonic() - start_time
                        progress = _make_progress_event(
                            partition, bytes_written, total_bytes, elapsed
                        )
                        await self._send_event(writer, req_id, progress)

            await proc.wait()
        except Exception as exc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return {
                "status": "error",
                "partition": partition,
                "error": str(exc),
                "bytes_written": bytes_written,
            }

        return {
            "status": "complete",
            "partition": partition,
            "size": bytes_written,
            "total_bytes": total_bytes,
            "path": str(dest),
        }

    async def _mock_dump_partition(
        self,
        partition: str,
        dest: Path,
        writer: asyncio.StreamWriter,
        req_id: str,
        total_bytes: int | None = None,
    ) -> dict:
        """Mock dump: writes 4KB of zeros with simulated progress."""
        mock_size = 4096
        start_time = time.monotonic()
        with open(dest, "wb") as f:
            written = 0
            chunk_size = 1024
            while written < mock_size:
                if self._cancel_event.is_set():
                    return {
                        "status": "cancelled",
                        "partition": partition,
                        "bytes_written": written,
                    }
                chunk = b"\x00" * min(chunk_size, mock_size - written)
                f.write(chunk)
                written += len(chunk)
                if self._current_dump:
                    self._current_dump["bytes_written"] = written
                elapsed = time.monotonic() - start_time
                progress = _make_progress_event(
                    partition, written, total_bytes, elapsed
                )
                await self._send_event(writer, req_id, progress)
                await asyncio.sleep(0.05)  # Simulate transfer time

        return {
            "status": "complete",
            "partition": partition,
            "size": mock_size,
            "total_bytes": total_bytes,
            "path": str(dest),
        }

    async def _mtk_dump_partition(
        self,
        partition: str,
        dest: Path,
        writer: asyncio.StreamWriter,
        req_id: str,
        total_bytes: int | None = None,
    ) -> dict:
        """Dump a partition via mtk r <partition> <output_file>.

        MTKClient writes directly to a file (not stdout), so we track progress
        by polling the output file size.
        """
        if not self._check_mtk_available():
            return {
                "status": "error",
                "partition": partition,
                "error": "mtkclient not installed (pip install mtkclient)",
                "bytes_written": 0,
            }

        mtk_path = shutil.which("mtk")
        proc = await asyncio.create_subprocess_exec(
            mtk_path, "r", partition, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        start_time = time.monotonic()
        bytes_written = 0

        try:
            # Poll file size for progress while process runs
            while proc.returncode is None:
                if self._cancel_event.is_set():
                    proc.kill()
                    return {
                        "status": "cancelled",
                        "partition": partition,
                        "bytes_written": bytes_written,
                    }

                # Check file size for progress
                try:
                    if dest.exists():
                        bytes_written = dest.stat().st_size
                        if self._current_dump:
                            self._current_dump["bytes_written"] = bytes_written

                        elapsed = time.monotonic() - start_time
                        progress = _make_progress_event(
                            partition, bytes_written, total_bytes, elapsed
                        )
                        await self._send_event(writer, req_id, progress)
                except OSError:
                    pass

                # Wait before next poll, but also check if process finished
                try:
                    await asyncio.wait_for(proc.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass

            # Process finished — get final size
            if dest.exists():
                bytes_written = dest.stat().st_size

            if proc.returncode != 0:
                stderr = ""
                if proc.stderr:
                    stderr_bytes = await proc.stderr.read()
                    stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
                stdout_text = ""
                if proc.stdout:
                    stdout_bytes = await proc.stdout.read()
                    stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()

                combined = (stderr + stdout_text).lower()
                if "no device" in combined or "not found" in combined:
                    error = "Device disconnected or not in BROM mode"
                elif "permission" in combined or "access" in combined:
                    error = "USB permission denied — check udev rules"
                else:
                    error = stderr or stdout_text or f"mtk r failed (rc={proc.returncode})"

                return {
                    "status": "error",
                    "partition": partition,
                    "error": error,
                    "bytes_written": bytes_written,
                }

        except Exception as exc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return {
                "status": "error",
                "partition": partition,
                "error": str(exc),
                "bytes_written": bytes_written,
            }

        return {
            "status": "complete",
            "partition": partition,
            "size": bytes_written,
            "total_bytes": total_bytes,
            "path": str(dest),
        }

    async def dump_all(
        self,
        device_id: str,
        partitions: list[str],
        output_dir: str,
        writer: asyncio.StreamWriter,
        req_id: str,
        skip_existing: bool = False,
    ) -> dict:
        """Dump multiple partitions sequentially."""
        results = []
        for partition in partitions:
            if self._cancel_event.is_set():
                results.append({
                    "status": "cancelled",
                    "partition": partition,
                })
                break

            # Skip if already completed and skip_existing is set
            if skip_existing:
                existing = Path(output_dir) / f"{partition}.img"
                if existing.exists() and existing.stat().st_size > 0:
                    logger.info("Skipping already-dumped partition: %s", partition)
                    results.append({
                        "status": "skipped",
                        "partition": partition,
                        "size": existing.stat().st_size,
                        "path": str(existing),
                    })
                    continue

            # Try up to MAX_RETRIES+1 times per partition
            max_retries = 2
            result = None
            for attempt in range(max_retries + 1):
                if self._cancel_event.is_set():
                    break

                # Clean up partial file before retry
                if attempt > 0:
                    partial = Path(output_dir) / f"{partition}.img"
                    if partial.exists():
                        partial.unlink()
                    logger.info(
                        "Retrying partition %s (attempt %d/%d) after %.1fs backoff",
                        partition, attempt + 1, max_retries + 1, attempt * 5,
                    )
                    await asyncio.sleep(attempt * 5)  # 0s, 5s, 10s backoff

                result = await self.dump_partition(
                    device_id, partition, output_dir, writer, req_id
                )

                if result.get("status") != "error":
                    break

                error_msg = result.get("error", "").lower()
                # Don't retry permission or "not installed" errors
                if "permission" in error_msg or "not installed" in error_msg:
                    break

                logger.warning(
                    "Partition %s attempt %d failed: %s",
                    partition, attempt + 1, result.get("error"),
                )

            if result:
                if attempt > 0 and result.get("status") != "error":
                    result["retries"] = attempt
                results.append(result)

            if result and result.get("status") == "error":
                logger.error(
                    "Partition %s failed after %d attempt(s): %s",
                    partition, attempt + 1, result.get("error"),
                )
                # Continue with remaining partitions

        return {
            "status": "complete",
            "results": results,
            "total": len(partitions),
            "completed": sum(
                1 for r in results if r.get("status") in ("complete", "skipped")
            ),
            "failed": sum(1 for r in results if r.get("status") == "error"),
        }

    def get_dump_status(self) -> dict:
        """Return status of current in-progress dump."""
        if self._current_dump is None:
            return {"status": "idle"}
        elapsed = time.monotonic() - self._current_dump["started_at"]
        bytes_written = self._current_dump["bytes_written"]
        total = self._current_dump.get("total_bytes")
        result = {
            "status": "running",
            "device_id": self._current_dump["device_id"],
            "partition": self._current_dump["partition"],
            "bytes_written": bytes_written,
            "total_bytes": total,
            "elapsed_seconds": round(elapsed, 1),
        }
        if total and total > 0:
            result["progress_percent"] = round(bytes_written / total * 100, 1)
        if elapsed > 0 and bytes_written > 0:
            result["throughput_mbps"] = round(
                bytes_written / (1024 * 1024) / elapsed, 1
            )
        return result

    def cancel_dump(self) -> dict:
        """Signal cancellation of current dump."""
        if self._current_dump is None:
            return {"status": "idle", "message": "No dump in progress"}
        self._cancel_event.set()
        return {"status": "cancelling", "partition": self._current_dump["partition"]}

    async def _run_adb(self, *args: str) -> str:
        """Run an adb command and return stdout."""
        adb_path = shutil.which("adb")
        if not adb_path:
            raise RuntimeError("adb not found on PATH")

        proc = await asyncio.create_subprocess_exec(
            adb_path, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"adb {' '.join(args)} failed (rc={proc.returncode}): "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )
        return stdout.decode("utf-8", errors="replace")

    @staticmethod
    async def _send_event(
        writer: asyncio.StreamWriter, req_id: str, event: dict
    ) -> None:
        """Send a progress event to the client."""
        event["id"] = req_id
        try:
            writer.write((json.dumps(event) + "\n").encode("utf-8"))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass


# ---------------------------------------------------------------------------
# BridgeServer — asyncio TCP server
# ---------------------------------------------------------------------------

class BridgeServer:
    """Asyncio TCP server that handles JSON-over-TCP protocol for ADB device bridge."""

    def __init__(self, device_mgr: DeviceManager, bind: str, port: int) -> None:
        self._device_mgr = device_mgr
        self._bind = bind
        self._port = port
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._bind, self._port
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("Device bridge listening on %s", addrs)
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        logger.info("Client connected: %s (at %s)", addr, _now_iso())
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    response = {"ok": False, "error": "Invalid JSON"}
                    writer.write((json.dumps(response) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                req_id = request.get("id")
                command = request.get("command", "")
                logger.info(
                    "Command: %s device_id=%s (at %s)",
                    command,
                    request.get("device_id", "-"),
                    _now_iso(),
                )

                response = await self._dispatch(command, request, writer)
                if req_id is not None:
                    response["id"] = req_id

                writer.write((json.dumps(response) + "\n").encode("utf-8"))
                await writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            logger.error("Client handler error: %s", exc, exc_info=True)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("Client disconnected: %s", addr)

    async def _dispatch(
        self, command: str, request: dict, writer: asyncio.StreamWriter
    ) -> dict:
        """Route a request to the appropriate handler."""
        try:
            if command == "list_devices":
                return await self._handle_list_devices(request)
            elif command == "get_device_info":
                return await self._handle_get_device_info(request)
            elif command == "dump_partition":
                return await self._handle_dump_partition(request, writer)
            elif command == "dump_all":
                return await self._handle_dump_all(request, writer)
            elif command == "get_dump_status":
                return await self._handle_get_dump_status(request)
            elif command == "cancel_dump":
                return await self._handle_cancel_dump(request)
            elif command == "resume_dump":
                return await self._handle_resume_dump(request, writer)
            else:
                return {"ok": False, "error": f"Unknown command: {command}"}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            logger.error("Handler error for %s: %s", command, exc, exc_info=True)
            return {"ok": False, "error": str(exc)}

    async def _handle_list_devices(self, request: dict) -> dict:
        devices = await self._device_mgr.list_devices()
        return {"ok": True, "devices": devices}

    async def _handle_get_device_info(self, request: dict) -> dict:
        device_id = request.get("device_id", "")
        if not device_id:
            return {"ok": False, "error": "device_id is required"}

        info = await self._device_mgr.get_device_info(device_id)
        return {"ok": True, "getprop": info["getprop"], "partitions": info["partitions"]}

    async def _handle_dump_partition(
        self, request: dict, writer: asyncio.StreamWriter
    ) -> dict:
        device_id = request.get("device_id", "")
        partition = request.get("partition", "")
        output_dir = request.get("output_dir", "")
        req_id = request.get("id", "")

        if not device_id:
            return {"ok": False, "error": "device_id is required"}
        if not partition:
            return {"ok": False, "error": "partition is required"}
        if not output_dir:
            return {"ok": False, "error": "output_dir is required"}

        # Validate partition name (prevent path traversal)
        if "/" in partition or ".." in partition:
            return {"ok": False, "error": "Invalid partition name"}

        if self._device_mgr.is_dumping:
            return {"ok": False, "error": "A dump is already in progress"}

        t0 = time.monotonic()
        result = await self._device_mgr.dump_partition(
            device_id, partition, output_dir, writer, req_id
        )
        elapsed = time.monotonic() - t0
        logger.info(
            "Transfer: partition=%s bytes=%s duration=%.1fs outcome=%s",
            partition,
            result.get("size", result.get("bytes_written", 0)),
            elapsed,
            result.get("status"),
        )
        result["ok"] = result.get("status") == "complete"
        return result

    async def _handle_dump_all(
        self, request: dict, writer: asyncio.StreamWriter
    ) -> dict:
        device_id = request.get("device_id", "")
        partitions = request.get("partitions", [])
        output_dir = request.get("output_dir", "")
        req_id = request.get("id", "")

        if not device_id:
            return {"ok": False, "error": "device_id is required"}
        if not partitions:
            return {"ok": False, "error": "partitions list is required"}
        if not output_dir:
            return {"ok": False, "error": "output_dir is required"}

        for p in partitions:
            if "/" in p or ".." in p:
                return {"ok": False, "error": f"Invalid partition name: {p}"}

        if self._device_mgr.is_dumping:
            return {"ok": False, "error": "A dump is already in progress"}

        t0 = time.monotonic()
        result = await self._device_mgr.dump_all(
            device_id, partitions, output_dir, writer, req_id
        )
        elapsed = time.monotonic() - t0
        logger.info(
            "Transfer (all): partitions=%d completed=%d failed=%d duration=%.1fs",
            result["total"],
            result["completed"],
            result["failed"],
            elapsed,
        )
        result["ok"] = True
        return result

    async def _handle_get_dump_status(self, request: dict) -> dict:
        status = self._device_mgr.get_dump_status()
        return {"ok": True, **status}

    async def _handle_cancel_dump(self, request: dict) -> dict:
        result = self._device_mgr.cancel_dump()
        return {"ok": True, **result}

    async def _handle_resume_dump(
        self, request: dict, writer: asyncio.StreamWriter
    ) -> dict:
        device_id = request.get("device_id", "")
        partitions = request.get("partitions", [])
        output_dir = request.get("output_dir", "")
        req_id = request.get("id", "")

        if not device_id:
            return {"ok": False, "error": "device_id is required"}
        if not partitions:
            return {"ok": False, "error": "partitions list is required"}
        if not output_dir:
            return {"ok": False, "error": "output_dir is required"}

        for p in partitions:
            if "/" in p or ".." in p:
                return {"ok": False, "error": f"Invalid partition name: {p}"}

        if self._device_mgr.is_dumping:
            return {"ok": False, "error": "A dump is already in progress"}

        t0 = time.monotonic()
        result = await self._device_mgr.dump_all(
            device_id, partitions, output_dir, writer, req_id,
            skip_existing=True,
        )
        elapsed = time.monotonic() - t0
        logger.info(
            "Transfer (resume): partitions=%d completed=%d failed=%d duration=%.1fs",
            result["total"],
            result["completed"],
            result["failed"],
            elapsed,
        )
        result["ok"] = True
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wairz Device Bridge — TCP-to-ADB bridge for MCP tools"
    )
    parser.add_argument(
        "--port", type=int, default=9998, help="TCP listen port (default: 9998)"
    )
    parser.add_argument(
        "--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--mock", action="store_true", help="Enable mock mode (no real ADB device needed)"
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Log level (default: INFO)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.mock:
        logger.info("Starting in MOCK mode — no real ADB device required")

    device_mgr = DeviceManager(mock=args.mock)
    server = BridgeServer(device_mgr, bind=args.bind, port=args.port)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
