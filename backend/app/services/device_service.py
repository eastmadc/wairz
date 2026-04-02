"""Service for Android device acquisition via the wairz-device-bridge.

Proxies commands to the host-side bridge over TCP (same pattern as uart_service.py)
and manages dump state for the frontend wizard.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.firmware import Firmware
from app.models.project import Project
from app.utils.getprop import extract_device_metadata, parse_getprop_txt
from app.workers.unpack import unpack_firmware

logger = logging.getLogger(__name__)


class DeviceService:
    """Manages device acquisition and communicates with the host-side bridge."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        # In-memory dump state (single dump at a time)
        self._dump_state: dict | None = None

    # ── Public API ──

    async def get_bridge_status(self) -> dict:
        """Check if the device bridge is reachable."""
        settings = get_settings()
        try:
            result = await self._bridge_request({"command": "list_devices"})
            return {
                "connected": True,
                "bridge_host": settings.device_bridge_host,
                "bridge_port": settings.device_bridge_port,
                "error": None,
            }
        except ConnectionError as e:
            return {
                "connected": False,
                "bridge_host": settings.device_bridge_host,
                "bridge_port": settings.device_bridge_port,
                "error": str(e),
            }

    async def list_devices(self) -> list[dict]:
        """List connected ADB devices via the bridge."""
        result = await self._bridge_request({"command": "list_devices"})
        return result.get("devices", [])

    async def get_device_info(self, device_id: str) -> dict:
        """Get device details including getprop and partition list."""
        result = await self._bridge_request({
            "command": "get_device_info",
            "device_id": device_id,
        })

        # Parse getprop and extract structured metadata
        getprop_raw = result.get("getprop", "")
        props = parse_getprop_txt(getprop_raw)
        metadata = extract_device_metadata(props)

        return {
            "getprop": props,
            "partitions": result.get("partitions", []),
            "partition_sizes": result.get("partition_sizes", []),
            "device_metadata": metadata,
        }

    # Shared dump directory — bind-mounted between host and container so the
    # bridge (host-side) can write partition images and the backend (container)
    # can read them for import.
    DUMP_SHARED_DIR = "/tmp/wairz-dumps"

    async def start_dump(
        self,
        project_id: uuid.UUID,
        device_id: str,
        partitions: list[str],
    ) -> dict:
        """Start dumping partitions from a device."""
        # Use shared directory (bind-mounted from host) so the bridge can write
        # to it on the host side and the backend can read it inside the container
        dump_id = str(uuid.uuid4())
        dump_dir = os.path.join(self.DUMP_SHARED_DIR, dump_id)
        os.makedirs(dump_dir, exist_ok=True)

        # Check disk space on the shared mount
        disk_usage = shutil.disk_usage(self.DUMP_SHARED_DIR)
        free_gb = disk_usage.free / (1024**3)
        if free_gb < 5:
            raise ValueError(
                f"Insufficient disk space: {free_gb:.1f}GB free, "
                f"need at least 5GB for device dumps"
            )

        # Initialize dump state
        self._dump_state = {
            "status": "dumping",
            "device_id": device_id,
            "dump_id": dump_id,
            "dump_dir": dump_dir,
            "project_id": str(project_id),
            "partitions": [
                {"partition": p, "status": "pending", "bytes_written": 0}
                for p in partitions
            ],
        }

        # Start dump in background
        asyncio.create_task(
            self._run_dump(device_id, partitions, dump_dir)
        )

        return self._dump_state

    async def get_dump_status(self) -> dict:
        """Get the status of the current dump."""
        if not self._dump_state:
            return {"status": "idle", "device_id": None, "partitions": []}
        return self._dump_state

    async def cancel_dump(self) -> dict:
        """Cancel the current dump."""
        if not self._dump_state:
            return {"status": "idle", "message": "No dump in progress"}

        try:
            await self._bridge_request({"command": "cancel_dump"})
        except ConnectionError:
            pass

        self._dump_state["status"] = "cancelled"
        return self._dump_state

    async def import_dump(
        self,
        project_id: uuid.UUID,
        device_id: str,
        version_label: str | None = None,
    ) -> Firmware:
        """Import a completed dump as firmware into the project."""
        if not self._dump_state:
            raise ValueError("No dump to import")

        if self._dump_state["status"] not in ("complete", "partial"):
            raise ValueError(f"Dump is {self._dump_state['status']}, cannot import")

        dump_dir = self._dump_state["dump_dir"]

        # Find all completed partition images
        img_files = sorted(Path(dump_dir).glob("*.img"))
        if not img_files:
            raise ValueError("No partition images found in dump directory")

        # Get device info for metadata
        try:
            device_info = await self.get_device_info(device_id)
            device_metadata = device_info.get("device_metadata", {})
        except ConnectionError:
            device_metadata = {}

        # Add acquisition metadata
        device_metadata["acquisition_method"] = "adb_root"
        device_metadata["partition_list"] = [
            p["partition"] for p in self._dump_state["partitions"]
            if p["status"] == "complete"
        ]
        device_metadata["source_partitions"] = {
            f.stem: f.name for f in img_files
        }

        # Compute SHA256 of first (or only) image for firmware record
        first_img = img_files[0]
        sha256 = hashlib.sha256()
        with open(first_img, "rb") as f:
            for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                sha256.update(chunk)

        total_size = sum(f.stat().st_size for f in img_files)

        # Create firmware record
        firmware = Firmware(
            project_id=project_id,
            original_filename=f"device-dump-{device_id}",
            sha256=sha256.hexdigest(),
            file_size=total_size,
            storage_path=str(first_img),
            extraction_dir=dump_dir,
            version_label=version_label or f"Device dump ({device_id})",
            device_metadata=device_metadata,
        )
        self._db.add(firmware)
        await self._db.flush()

        # Trigger unpack pipeline for the first/main image
        asyncio.create_task(
            self._run_import_unpack(project_id, firmware.id, str(first_img), dump_dir)
        )

        return firmware

    # ── Internal helpers ──

    async def _run_dump(
        self,
        device_id: str,
        partitions: list[str],
        dump_dir: str,
    ) -> None:
        """Run partition dumps sequentially via the bridge."""
        completed = 0
        failed = 0

        for i, partition in enumerate(partitions):
            self._dump_state["partitions"][i]["status"] = "active"

            try:
                result = await self._bridge_request_streaming(
                    {
                        "command": "dump_partition",
                        "device_id": device_id,
                        "partition": partition,
                        "output_dir": dump_dir,
                    },
                    progress_callback=lambda ev: self._update_partition_progress(
                        i, ev
                    ),
                )

                if result.get("status") == "complete":
                    p = self._dump_state["partitions"][i]
                    p["status"] = "complete"
                    p["bytes_written"] = result.get("size", 0)
                    p["size"] = result.get("size", 0)
                    p["path"] = result.get("path")
                    if "total_bytes" in result:
                        p["total_bytes"] = result["total_bytes"]
                    completed += 1
                else:
                    self._dump_state["partitions"][i]["status"] = "failed"
                    self._dump_state["partitions"][i]["error"] = result.get("error", "Unknown")
                    failed += 1

            except Exception as e:
                self._dump_state["partitions"][i]["status"] = "failed"
                self._dump_state["partitions"][i]["error"] = str(e)
                failed += 1
                logger.warning("Dump of %s failed: %s", partition, e, exc_info=True)

        if failed == 0:
            self._dump_state["status"] = "complete"
        elif completed > 0:
            self._dump_state["status"] = "partial"
        else:
            self._dump_state["status"] = "failed"

    def _update_partition_progress(self, index: int, event: dict) -> None:
        """Update progress for a partition from a bridge progress event."""
        if event.get("event") == "progress":
            p = self._dump_state["partitions"][index]
            p["bytes_written"] = event.get("bytes_written", 0)
            if "total_bytes" in event:
                p["total_bytes"] = event["total_bytes"]
            if "progress_percent" in event:
                p["progress_percent"] = event["progress_percent"]
            if "throughput_mbps" in event:
                p["throughput_mbps"] = event["throughput_mbps"]

    async def _run_import_unpack(
        self,
        project_id: uuid.UUID,
        firmware_id: uuid.UUID,
        storage_path: str,
        output_base: str,
    ) -> None:
        """Run unpack pipeline in background after import."""
        from app.database import async_session_factory

        try:
            result = await unpack_firmware(storage_path, output_base)

            async with async_session_factory() as db:
                try:
                    proj_result = await db.execute(
                        select(Project).where(Project.id == project_id)
                    )
                    project = proj_result.scalar_one_or_none()
                    fw_result = await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                    firmware = fw_result.scalar_one_or_none()

                    if not project or not firmware:
                        logger.error("Import unpack: project or firmware not found")
                        return

                    if result.success:
                        firmware.extracted_path = result.extracted_path
                        firmware.extraction_dir = result.extraction_dir
                        firmware.architecture = result.architecture
                        firmware.endianness = result.endianness
                        firmware.os_info = result.os_info
                        firmware.kernel_path = result.kernel_path
                        firmware.unpack_log = result.unpack_log
                        project.status = "ready"
                    else:
                        firmware.unpack_log = result.unpack_log
                        project.status = "error"

                    await db.commit()
                except Exception:
                    await db.rollback()
                    raise
        except Exception:
            logger.exception("Import unpack failed for firmware %s", firmware_id)

    async def _bridge_request(self, request: dict) -> dict:
        """Send a JSON request to the bridge and return the response."""
        settings = get_settings()
        host = settings.device_bridge_host
        port = settings.device_bridge_port

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ConnectionError(
                f"Cannot reach device bridge at {host}:{port}. "
                f"Is wairz-device-bridge.py running on the host? Error: {exc}"
            ) from exc

        try:
            # Add request ID
            if "id" not in request:
                request["id"] = str(uuid.uuid4())

            payload = json.dumps(request) + "\n"
            writer.write(payload.encode("utf-8"))
            await writer.drain()

            line = await asyncio.wait_for(reader.readline(), timeout=60)
            if not line:
                raise ConnectionError("Bridge closed connection without response")

            response = json.loads(line.decode("utf-8"))
            if not response.get("ok"):
                raise ValueError(response.get("error", "Unknown bridge error"))

            return response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _bridge_request_streaming(
        self,
        request: dict,
        progress_callback=None,
    ) -> dict:
        """Send a request and read multiple lines (progress events + final result)."""
        settings = get_settings()
        host = settings.device_bridge_host
        port = settings.device_bridge_port

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ConnectionError(
                f"Cannot reach device bridge at {host}:{port}. Error: {exc}"
            ) from exc

        try:
            if "id" not in request:
                request["id"] = str(uuid.uuid4())

            payload = json.dumps(request) + "\n"
            writer.write(payload.encode("utf-8"))
            await writer.drain()

            # Read lines until we get a final status (complete, error, cancelled)
            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=1860,  # 31 min (30 min partition timeout + margin)
                )
                if not line:
                    raise ConnectionError("Bridge closed connection")

                response = json.loads(line.decode("utf-8"))

                if response.get("event") == "progress":
                    if progress_callback:
                        progress_callback(response)
                    continue

                # Final response
                return response
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
