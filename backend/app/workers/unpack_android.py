"""Android-specific firmware extraction — OTA, sparse images, super.img."""

import asyncio
import os


def _identify_partition_by_content(partition_dir: str) -> str | None:
    """Identify an Android partition by its directory contents.

    Returns a human-readable name like 'system', 'vendor', 'product',
    or None if the partition cannot be identified.
    """
    if not os.path.isdir(partition_dir):
        return None
    try:
        entries = set(os.listdir(partition_dir))
    except OSError:
        return None

    if ("init" in entries and ("bin" in entries or "system" in entries)) or \
       ("app" in entries and "framework" in entries and "priv-app" in entries):
        return "system"

    if "build.prop" in entries and ("firmware" in entries or "lib" in entries or "etc" in entries):
        if "app" not in entries or "framework" not in entries:
            return "vendor"

    if ("app" in entries or "priv-app" in entries) and "framework" not in entries:
        if "overlay" in entries or "media" in entries:
            return "product"

    if "priv-app" in entries and "apex" in entries and "framework" not in entries:
        return "system_ext"

    if "etc" in entries and "lib" in entries and "build.prop" not in entries and \
       "app" not in entries and "framework" not in entries:
        if "firmware" in entries or "overlay" in entries:
            return "odm"

    return None


async def _try_extract_partition(
    raw_path: str, rootfs_dir: str, partition_name: str, log_lines: list[str]
) -> bool:
    """Try to extract a single partition image as ext4 or EROFS."""
    import shutil

    dest_dir = os.path.join(rootfs_dir, partition_name)
    os.makedirs(dest_dir, exist_ok=True)

    if shutil.which("fsck.erofs"):
        proc = await asyncio.create_subprocess_exec(
            "fsck.erofs", f"--extract={dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                log_lines.append(f"Extracted {partition_name} as EROFS ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except asyncio.TimeoutError:
            proc.kill()
            log_lines.append(f"fsck.erofs timed out on {partition_name}")

    if shutil.which("debugfs"):
        proc = await asyncio.create_subprocess_exec(
            "debugfs", "-R", f"rdump / {dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                log_lines.append(f"Extracted {partition_name} as ext4 ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except asyncio.TimeoutError:
            proc.kill()
            log_lines.append(f"debugfs timed out on {partition_name}")

    try:
        os.rmdir(dest_dir)
    except OSError:
        pass
    return False


async def _scan_super_partitions(
    raw_path: str, rootfs_dir: str, log_lines: list[str]
) -> int:
    """Scan a raw super.img for embedded EROFS/ext4 partitions and extract them."""
    import mmap
    import tempfile

    EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"
    EXT4_MAGIC = b"\x53\xef"

    partitions: list[tuple[str, int]] = []

    try:
        with open(raw_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            size = mm.size()

            for offset in range(1024, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 4] == EROFS_MAGIC:
                    partitions.append(("erofs", offset - 1024))

            for offset in range(0x438, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 2] == EXT4_MAGIC:
                    partitions.append(("ext4", offset - 0x438))

            mm.close()
    except Exception as e:
        log_lines.append(f"Error scanning super.img: {e}")
        return 0

    if not partitions:
        log_lines.append("No EROFS or ext4 partitions found in super.img")
        return 0

    partitions.sort(key=lambda x: x[1])
    log_lines.append(f"Found {len(partitions)} partition(s) in super.img")

    extracted_count = 0
    for i, (fs_type, start_offset) in enumerate(partitions):
        if i + 1 < len(partitions):
            part_size = partitions[i + 1][1] - start_offset
        else:
            part_size = os.path.getsize(raw_path) - start_offset

        if part_size < 1024 * 1024:
            continue

        partition_name = f"partition_{i}_{fs_type}"

        try:
            with tempfile.NamedTemporaryFile(suffix=f".{fs_type}", delete=False) as tmp:
                tmp_path = tmp.name
                with open(raw_path, "rb") as src:
                    src.seek(start_offset)
                    remaining = part_size
                    while remaining > 0:
                        chunk = src.read(min(remaining, 8 * 1024 * 1024))
                        if not chunk:
                            break
                        tmp.write(chunk)
                        remaining -= len(chunk)

            if await _try_extract_partition(tmp_path, rootfs_dir, partition_name, log_lines):
                identified = _identify_partition_by_content(
                    os.path.join(rootfs_dir, partition_name)
                )
                if identified and identified != partition_name:
                    old_path = os.path.join(rootfs_dir, partition_name)
                    new_path = os.path.join(rootfs_dir, identified)
                    if not os.path.exists(new_path):
                        os.rename(old_path, new_path)
                        log_lines.append(f"Identified {partition_name} as '{identified}'")
                        partition_name = identified
                extracted_count += 1
        except Exception as e:
            log_lines.append(f"Error extracting partition at offset 0x{start_offset:x}: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    log_lines.append(f"Extracted {extracted_count}/{len(partitions)} partitions from super.img")
    return extracted_count


async def _extract_android_ota(firmware_path: str, extraction_dir: str) -> str:
    """Extract Android OTA ZIP — handles sparse images, ext4, EROFS."""
    import shutil
    import zipfile as _zipfile

    log_lines: list[str] = []

    if _zipfile.is_zipfile(firmware_path):
        with _zipfile.ZipFile(firmware_path, "r") as zf:
            names = zf.namelist()

            if "payload.bin" in names:
                payload_path = os.path.join(extraction_dir, "payload.bin")
                zf.extract("payload.bin", extraction_dir)
                log_lines.append("Found payload.bin (A/B OTA)")
                if shutil.which("payload-dumper-go"):
                    partitions_dir = os.path.join(extraction_dir, "partitions")
                    os.makedirs(partitions_dir, exist_ok=True)
                    proc = await asyncio.create_subprocess_exec(
                        "payload-dumper-go", "-o", partitions_dir, payload_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    try:
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
                        log_lines.append(stdout.decode(errors="replace")[:2000])
                    except asyncio.TimeoutError:
                        proc.kill()
                        log_lines.append("payload-dumper-go timed out")
                    os.remove(payload_path)
                else:
                    log_lines.append("payload-dumper-go not installed, skipping payload.bin")
            else:
                for name in names:
                    if name.endswith(".img") or name.endswith(".bin"):
                        zf.extract(name, extraction_dir)
                        log_lines.append(f"Extracted {name}")
    else:
        import shutil
        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        if not dest.endswith(".img"):
            dest += ".img"
        shutil.copy2(firmware_path, dest)
        log_lines.append(f"Copied raw sparse image: {os.path.basename(firmware_path)}")

    rootfs_dir = os.path.join(extraction_dir, "rootfs")
    os.makedirs(rootfs_dir, exist_ok=True)

    search_dirs = [extraction_dir, os.path.join(extraction_dir, "partitions")]

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for img_name in sorted(os.listdir(search_dir)):
            if not img_name.endswith(".img"):
                continue
            img_path = os.path.join(search_dir, img_name)

            try:
                if os.path.getsize(img_path) < 1024 * 1024:
                    continue
            except OSError:
                continue

            raw_path = img_path
            try:
                with open(img_path, "rb") as f:
                    img_magic = f.read(4)
                if img_magic == b"\x3a\xff\x26\xed" and shutil.which("simg2img"):
                    raw_path = img_path + ".raw"
                    proc = await asyncio.create_subprocess_exec(
                        "simg2img", img_path, raw_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=600)
                    log_lines.append(f"Converted {img_name} sparse → raw ({os.path.getsize(raw_path) // (1024*1024)}MB)")
                    os.remove(img_path)
            except Exception as e:
                log_lines.append(f"Error converting {img_name}: {e}")
                continue

            is_super = False
            try:
                with open(raw_path, "rb") as f:
                    f.seek(0x1000)
                    lp_magic = f.read(4)
                    if lp_magic == b"\x67\x44\x6c\x61":
                        is_super = True
                        log_lines.append(f"{img_name} is a super partition — scanning for embedded filesystems")
            except Exception:
                pass

            if is_super:
                await _scan_super_partitions(raw_path, rootfs_dir, log_lines)
                if os.path.exists(raw_path):
                    os.remove(raw_path)
                continue

            partition_name = img_name.replace(".img", "").replace(".raw", "")
            await _try_extract_partition(raw_path, rootfs_dir, partition_name, log_lines)

            if raw_path != img_path and os.path.exists(raw_path):
                os.remove(raw_path)

    return "\n".join(log_lines)
