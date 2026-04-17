from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat as _stat
import time
import uuid
from collections import deque

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.hardware_firmware.classifier import classify
from app.services.hardware_firmware.parsers import ParsedBlob, get_parser

logger = logging.getLogger(__name__)

_MIN_FILE_SIZE = 512
_MAX_FILE_SIZE = 128 * 1024 * 1024  # 128 MB
_MAX_CANDIDATES = 10_000
_MAGIC_READ_BYTES = 64
_HASH_CHUNK = 1 * 1024 * 1024
_SLOW_WALK_SECONDS = 45
_DETECTION_SOURCE = "phase1_classifier"


def _detect_partition(extracted_path: str, blob_path: str) -> str | None:
    """Return the top-level directory under extracted_path, or None."""
    try:
        rel = os.path.relpath(blob_path, extracted_path)
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    parts = rel.split(os.sep, 1)
    if not parts or not parts[0] or parts[0] == ".":
        return None
    top = parts[0]
    # Only return top-level partition-shaped names; ignore files directly at root.
    if len(parts) < 2:
        return None
    return top


def _read_magic_and_hash(path: str, size: int) -> tuple[bytes, str] | None:
    """Open with O_NOFOLLOW, read magic bytes, stream sha256; None on error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, PermissionError):
        # Fallback: realpath guard + normal open (should rarely hit)
        try:
            real = os.path.realpath(path)
            if os.path.islink(path) or real != os.path.abspath(path):
                return None
            fd = os.open(real, os.O_RDONLY)
        except (OSError, PermissionError):
            return None
    try:
        with os.fdopen(fd, "rb", closefd=True) as f:
            magic = f.read(_MAGIC_READ_BYTES)
            hasher = hashlib.sha256()
            hasher.update(magic)
            remaining = size - len(magic)
            while remaining > 0:
                chunk = f.read(min(_HASH_CHUNK, remaining))
                if not chunk:
                    break
                hasher.update(chunk)
                remaining -= len(chunk)
            return magic, hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def _walk_and_classify(extracted_path: str) -> list[dict]:
    """Walk the extracted tree, classify candidates, return row dicts."""
    rows: list[dict] = []
    if not extracted_path or not os.path.isdir(extracted_path):
        return rows

    candidates_seen = 0
    queue: deque[str] = deque([extracted_path])
    capped = False
    start = time.monotonic()

    while queue and not capped:
        dir_path = queue.popleft()
        try:
            it = os.scandir(dir_path)
        except (OSError, PermissionError):
            continue
        with it:
            for entry in it:
                try:
                    if entry.is_symlink():
                        continue
                    # Skip sockets / fifos / block / char devices
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except (OSError, PermissionError):
                        continue
                    if _stat.S_ISDIR(mode):
                        queue.append(entry.path)
                        continue
                    if not _stat.S_ISREG(mode):
                        continue

                    size = entry.stat(follow_symlinks=False).st_size
                    if size < _MIN_FILE_SIZE or size > _MAX_FILE_SIZE:
                        continue

                    candidates_seen += 1
                    if candidates_seen > _MAX_CANDIDATES:
                        capped = True
                        break

                    read = _read_magic_and_hash(entry.path, size)
                    if read is None:
                        continue
                    magic, sha256 = read

                    cls = classify(entry.path, magic, size)
                    if cls is None:
                        continue

                    # Invoke per-format parser (sync I/O is fine — we're
                    # already in run_in_executor).  Parsers must never
                    # raise; catch defensively in case one does.
                    parser = get_parser(cls.format)
                    parsed: ParsedBlob
                    if parser is None:
                        parsed = ParsedBlob()
                    else:
                        try:
                            parsed = parser.parse(entry.path, magic, size)
                        except Exception:  # noqa: BLE001
                            logger.debug(
                                "Parser %s raised on %s",
                                cls.format,
                                entry.path,
                                exc_info=True,
                            )
                            parsed = ParsedBlob(metadata={"error": "parser raised"})

                    partition = _detect_partition(extracted_path, entry.path)
                    rows.append({
                        "blob_path": entry.path,
                        "partition": partition,
                        "blob_sha256": sha256,
                        "file_size": size,
                        "category": cls.category,
                        "vendor": cls.vendor if cls.vendor != "unknown" else None,
                        "format": cls.format,
                        "detection_source": _DETECTION_SOURCE,
                        "detection_confidence": cls.confidence,
                        "version": parsed.version,
                        "signed": parsed.signed,
                        "signature_algorithm": parsed.signature_algorithm,
                        "cert_subject": parsed.cert_subject,
                        "chipset_target": parsed.chipset_target,
                        "metadata": parsed.metadata or {},
                    })
                except (OSError, PermissionError):
                    continue

    elapsed = time.monotonic() - start
    if capped:
        logger.warning(
            "Hardware firmware detector: candidate cap reached (%d), walk truncated",
            _MAX_CANDIDATES,
        )
    if elapsed > _SLOW_WALK_SECONDS:
        logger.warning(
            "Hardware firmware detector: slow walk (%.1fs, %d candidates, %d classified)",
            elapsed,
            candidates_seen,
            len(rows),
        )
    else:
        logger.info(
            "Hardware firmware detector: walk done in %.1fs (%d candidates, %d classified)",
            elapsed,
            candidates_seen,
            len(rows),
        )
    return rows


async def detect_hardware_firmware(
    firmware_id: uuid.UUID,
    db: AsyncSession,
    extracted_path: str,
) -> int:
    """Walk extracted firmware, classify candidate blobs, persist rows; return count."""
    if not extracted_path:
        return 0

    loop = asyncio.get_event_loop()
    rows = await loop.run_in_executor(None, _walk_and_classify, extracted_path)
    if not rows:
        logger.info("Hardware firmware detector: no candidates classified")
        return 0

    values = []
    for row in rows:
        version = row.get("version")
        sig_algo = row.get("signature_algorithm")
        chipset = row.get("chipset_target")
        values.append({
            "firmware_id": firmware_id,
            "blob_path": row["blob_path"][:1024],
            "partition": row["partition"][:64] if row["partition"] else None,
            "blob_sha256": row["blob_sha256"],
            "file_size": row["file_size"],
            "category": row["category"],
            "vendor": row["vendor"],
            "format": row["format"],
            "detection_source": row["detection_source"],
            "detection_confidence": row["detection_confidence"],
            "version": version[:128] if version else None,
            "signed": row.get("signed") or "unknown",
            "signature_algorithm": sig_algo[:64] if sig_algo else None,
            "cert_subject": row.get("cert_subject"),
            "chipset_target": chipset[:64] if chipset else None,
            # Model column is named "metadata" in DB; ORM attribute is metadata_.
            "metadata": row.get("metadata") or {},
        })

    stmt = insert(HardwareFirmwareBlob).values(values)
    # Unique per (firmware_id, blob_sha256) — idempotent upsert.
    stmt = stmt.on_conflict_do_nothing(constraint="uq_hwfw_firmware_sha256")
    await db.execute(stmt)
    await db.flush()

    logger.info(
        "Hardware firmware detector: persisted %d blob row(s) for firmware_id=%s",
        len(values),
        firmware_id,
    )
    return len(values)
