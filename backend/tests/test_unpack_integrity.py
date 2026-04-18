"""Phase 1 — Extraction integrity regression tests.

Guards the six "stop-the-bleeding" fixes in
``feature-extraction-integrity`` Phase 1:

1. 1 MiB minimum-size filter gone — tiny partition stubs survive.
2. Mount-fail no longer os.remove()'s the raw image.
3. simg2img output verification helper behaves sanely.
4. cleanup_unblob_artifacts keeps non-empty .unknown chunks.
5. Scatter-zip version subdirs are relocated to extraction root.
6. Recursive nested-archive extraction handles tar.md5 → tar.lz4.
"""

import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.workers.unpack_android import (
    _MIN_PARTITION_BYTES,
    _USER_DATA_PARTITION_BASES,
    _extract_android_ota,
    _is_user_data_partition,
    _relocate_scatter_subdirs,
    _verify_simg_output,
)
from app.workers.unpack_common import (
    _recursive_extract_nested,
    cleanup_unblob_artifacts,
)

# ─── Test 1: 1 MiB filter gone ────────────────────────────────────────────

class TestTinyPartitionSurvives:
    """Phase 1 fix 1: remove the 1 MB minimum-size filter."""

    def test_min_partition_bytes_is_lower_than_1_mb(self):
        """The floor is under 1 KB so DPCS10-class stubs survive."""
        assert _MIN_PARTITION_BYTES < 1024, (
            "Floor must be well under 1 MiB to preserve 528-byte modem.img etc."
        )
        # But it has to drop *truly* empty files
        assert _MIN_PARTITION_BYTES > 0

    @pytest.mark.asyncio
    async def test_tiny_scatter_imgs_survive_ota_extract(self, tmp_path: Path):
        """A scatter-zip fixture with 528B modem.img + 2KB md1dsp.img → both
        end up somewhere on disk after _extract_android_ota (not silently
        dropped as they were when the floor was 1 MiB)."""
        # Build a scatter-style zip: files nested under a version subdir,
        # both below the old 1 MiB floor.
        src_zip = tmp_path / "DPCS10_scatter.zip"
        inner_dir = "DPCS10_260414-1134"
        modem_bytes = b"\xaa" * 528           # below 1 KB
        md1dsp_bytes = b"\xbb" * (2 * 1024)  # 2 KiB
        with zipfile.ZipFile(src_zip, "w") as zf:
            zf.writestr(f"{inner_dir}/modem.img", modem_bytes)
            zf.writestr(f"{inner_dir}/md1dsp.img", md1dsp_bytes)

        extraction_dir = tmp_path / "extracted"
        extraction_dir.mkdir()
        log = await _extract_android_ota(str(src_zip), str(extraction_dir))

        # After extraction both files should still exist either at the
        # extraction root (after relocation) or in the version subdir.
        def _find(name: str) -> Path | None:
            for root, _dirs, files in os.walk(extraction_dir):
                if name in files:
                    return Path(root) / name
            return None

        modem_path = _find("modem.img")
        md1dsp_path = _find("md1dsp.img")
        assert modem_path is not None, f"modem.img was silently dropped: {log}"
        assert md1dsp_path is not None, f"md1dsp.img was silently dropped: {log}"
        assert modem_path.stat().st_size == 528
        assert md1dsp_path.stat().st_size == 2048


# ─── Test 2: mount-fail keeps the image ───────────────────────────────────

class TestMountFailPreservesRawImage:
    """Phase 1 fix 2: stop os.remove()'ing after partition mount fails."""

    @pytest.mark.asyncio
    async def test_corrupt_erofs_img_survives_failed_mount(self, tmp_path: Path):
        """A partition image with EROFS magic but corrupt body → mount
        fails inside _try_extract_partition, but the raw image MUST remain
        on disk so Phase 3 MediaTek parsers can still read it."""
        # EROFS magic (0xE2E1F5E0) at offset 0, then garbage.
        # Size must be above _MIN_PARTITION_BYTES so it isn't skipped.
        img = tmp_path / "extracted" / "corrupt.img"
        img.parent.mkdir()
        payload = b"\xe2\xe1\xf5\xe0" + os.urandom(200_000)
        img.write_bytes(payload)

        # Build a minimal wrapper zip and run _extract_android_ota so the
        # full mount-fail code path runs (not just _try_extract_partition).
        # We pass the corrupt image inside a zip to exercise the full flow.
        zip_path = tmp_path / "ota.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("corrupt.img", payload)
            # Add an Android marker so classify would recognise if called,
            # though here we call _extract_android_ota directly.
            zf.writestr("system.img", b"\x00" * 128)

        extraction_dir = tmp_path / "extract_out"
        extraction_dir.mkdir()
        log = await _extract_android_ota(str(zip_path), str(extraction_dir))

        # After run, the corrupt.img (raw bytes) should still be recoverable.
        # It's either at the extraction root or in rootfs depending on
        # whether mount succeeded.  For a corrupt image mount WILL fail,
        # which means the image must still exist at its original location.
        def _exists_anywhere(name: str) -> bool:
            for _r, _d, files in os.walk(extraction_dir):
                if name in files:
                    return True
            return False

        assert _exists_anywhere("corrupt.img"), (
            f"Raw image removed after mount failure — Phase 3 parsers "
            f"would lose it.\nLog:\n{log}"
        )
        # We should log the "keeping raw image" decision somewhere.
        # This is informational — check the log reflects we kept it.
        # (The log line is logger.info; here we just confirm no error.)


# ─── Test 3: simg2img verification semantics ──────────────────────────────

class TestVerifySimgOutput:
    """Phase 1 fix 3: _verify_simg_output helper semantics."""

    def test_missing_file(self, tmp_path: Path):
        verified, note = _verify_simg_output(str(tmp_path / "nope.raw"))
        assert verified is False
        assert note == "missing"

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.raw"
        f.write_bytes(b"")
        verified, note = _verify_simg_output(str(f))
        assert verified is False
        assert note == "empty"

    def test_all_zero_first_4kb(self, tmp_path: Path):
        """1 KiB of all zero — not empty, so kept, but flagged suspicious."""
        f = tmp_path / "zero.raw"
        f.write_bytes(b"\x00" * 1024)
        verified, note = _verify_simg_output(str(f))
        assert verified is True
        assert "suspicious" in note or "all-zero" in note

    def test_elf_magic(self, tmp_path: Path):
        f = tmp_path / "elf.raw"
        f.write_bytes(b"\x7fELF" + os.urandom(1020))
        verified, note = _verify_simg_output(str(f))
        assert verified is True
        assert "elf" in note.lower()

    def test_erofs_magic(self, tmp_path: Path):
        f = tmp_path / "erofs.raw"
        f.write_bytes(b"\xe2\xe1\xf5\xe0" + os.urandom(1020))
        verified, note = _verify_simg_output(str(f))
        assert verified is True
        assert "erofs" in note.lower()

    def test_ext4_superblock_marker(self, tmp_path: Path):
        """ext4 magic 0x53EF at offset 0x438."""
        f = tmp_path / "ext4.raw"
        payload = bytearray(0x438 + 2 + 100)
        payload[0x438:0x438 + 2] = b"\x53\xef"
        f.write_bytes(bytes(payload))
        verified, note = _verify_simg_output(str(f))
        assert verified is True
        assert "ext4" in note.lower()

    def test_unknown_but_nonempty(self, tmp_path: Path):
        """Unknown magic with real content → kept, flagged unverified."""
        f = tmp_path / "blob.raw"
        f.write_bytes(b"RANDOM_VENDOR_BLOB" + b"\xde\xad" * 100)
        verified, note = _verify_simg_output(str(f))
        assert verified is True
        assert "unverified" in note or "non-empty" in note


# ─── Test 4: .unknown chunks preserved ────────────────────────────────────

class TestCleanupPreservesUnknownChunks:
    """Phase 1 fix 4: cleanup_unblob_artifacts keeps non-empty .unknown."""

    def test_nonempty_unknown_survives(self, tmp_path: Path):
        """foo.unknown (10 bytes) + baz.unknown (10 bytes) MUST remain;
        empty.unknown (0 bytes) and bar.test are swept away."""
        (tmp_path / "foo.unknown").write_bytes(b"\xaa" * 10)
        (tmp_path / "baz.unknown").write_bytes(b"\xbb" * 10)
        (tmp_path / "empty.unknown").write_bytes(b"")
        (tmp_path / "bar.test").write_bytes(b"junk")

        removed = cleanup_unblob_artifacts(str(tmp_path))

        assert (tmp_path / "foo.unknown").exists(), (
            "non-empty .unknown chunk was deleted — hw-firmware parsers "
            "rely on these for GFH/MBN identification"
        )
        assert (tmp_path / "baz.unknown").exists()
        assert not (tmp_path / "empty.unknown").exists()
        assert not (tmp_path / "bar.test").exists()
        # 2 removed: empty.unknown + bar.test
        assert removed == 2

    def test_extract_sibling_chunk_still_removed(self, tmp_path: Path):
        """The foo_extract/ sibling pattern still triggers cleanup of the
        raw chunk (content survives in the _extract/ dir)."""
        (tmp_path / "chunk.squashfs_v4_le").write_bytes(b"raw bytes")
        (tmp_path / "chunk.squashfs_v4_le_extract").mkdir()
        removed = cleanup_unblob_artifacts(str(tmp_path))
        assert not (tmp_path / "chunk.squashfs_v4_le").exists()
        assert (tmp_path / "chunk.squashfs_v4_le_extract").is_dir()
        assert removed == 1


# ─── Test 5: scatter-zip subdir relocation ────────────────────────────────

class TestScatterSubdirRelocation:
    """Phase 1 fix 5: relocate .img/.bin from scatter version subdirs."""

    def test_relocates_imgs_from_version_subdir(self, tmp_path: Path):
        """Files inside a version-named subdir are moved to the extraction
        root, preserving content and size."""
        extract = tmp_path / "extract"
        extract.mkdir()
        subdir = extract / "DPCS10_260414-1134"
        subdir.mkdir()
        lk = subdir / "lk.img"
        lk.write_bytes(b"LKIMG" * 100)
        md = subdir / "modem.bin"
        md.write_bytes(b"MD" * 64)

        log: list[str] = []
        moved = _relocate_scatter_subdirs(str(extract), log)

        assert moved == 2
        assert (extract / "lk.img").exists()
        assert (extract / "modem.bin").exists()
        assert not lk.exists()
        assert not md.exists()
        # Content preserved
        assert (extract / "lk.img").read_bytes() == b"LKIMG" * 100

    def test_collision_suffixed_not_overwritten(self, tmp_path: Path):
        """If lk.img already exists at root, the subdir copy is saved as
        lk.img_scatter."""
        extract = tmp_path / "extract"
        extract.mkdir()
        (extract / "lk.img").write_bytes(b"ORIGINAL")
        subdir = extract / "VERSION"
        subdir.mkdir()
        (subdir / "lk.img").write_bytes(b"SCATTER")

        log: list[str] = []
        moved = _relocate_scatter_subdirs(str(extract), log)

        assert moved == 1
        assert (extract / "lk.img").read_bytes() == b"ORIGINAL"
        assert (extract / "lk.img_scatter").read_bytes() == b"SCATTER"

    def test_reserved_dirs_ignored(self, tmp_path: Path):
        """rootfs/ / partitions/ / boot/ are never relocated from."""
        extract = tmp_path / "extract"
        extract.mkdir()
        (extract / "rootfs").mkdir()
        (extract / "rootfs" / "vmlinux.img").write_bytes(b"XX")
        log: list[str] = []
        moved = _relocate_scatter_subdirs(str(extract), log)
        assert moved == 0
        assert (extract / "rootfs" / "vmlinux.img").exists()

    @pytest.mark.asyncio
    async def test_scatter_zip_end_to_end_flattens(self, tmp_path: Path):
        """Full _extract_android_ota flow: scatter zip → lk.img appears at
        extraction_dir root."""
        src_zip = tmp_path / "scatter.zip"
        ver_dir = "DPCS10_260414-1134"
        lk_bytes = b"LK_CONTENT" * 500  # 5 KB — above floor, below 1 MiB
        with zipfile.ZipFile(src_zip, "w") as zf:
            zf.writestr(f"{ver_dir}/lk.img", lk_bytes)

        extraction_dir = tmp_path / "ext"
        extraction_dir.mkdir()
        await _extract_android_ota(str(src_zip), str(extraction_dir))

        assert (extraction_dir / "lk.img").exists(), (
            "lk.img did not make it to extraction root — scatter "
            "relocation did not run"
        )


# ─── Test 6: recursive nested extraction ──────────────────────────────────

class TestRecursiveNestedExtraction:
    """Phase 1 fix 6: _recursive_extract_nested unwraps Samsung-style
    tar.md5 → inner tar → .lz4 chains."""

    def test_plain_nested_tar_extracts(self, tmp_path: Path):
        """A .tar containing an inner .tar produces nested _extracted dirs."""
        root = tmp_path / "root"
        root.mkdir()

        # Inner tar → has a text file
        inner_tar = tmp_path / "inner.tar"
        payload_file = tmp_path / "payload.txt"
        payload_file.write_text("HELLO INNER")
        with tarfile.open(inner_tar, "w") as tf:
            tf.add(payload_file, arcname="payload.txt")

        # Outer tar contains the inner tar verbatim
        outer_tar = root / "outer.tar"
        with tarfile.open(outer_tar, "w") as tf:
            tf.add(inner_tar, arcname="inner.tar")

        new_dirs = _recursive_extract_nested(str(root), max_depth=3)
        assert len(new_dirs) >= 2, (
            f"Expected at least 2 extraction dirs (outer + inner), got "
            f"{new_dirs}"
        )
        # The final payload.txt should be present somewhere under root
        found = False
        for _r, _d, files in os.walk(root):
            if "payload.txt" in files:
                found = True
                break
        assert found, "Recursive extraction did not reach the inner payload"

    def test_tar_md5_with_tar_lz4_unwraps(self, tmp_path: Path):
        """Samsung-style nesting: outer.tar.md5 → inner.tar.lz4 → payload.

        We build the real artefacts (using the `lz4` CLI from the container
        image) and verify the helper recursively unwraps to the payload.
        """
        import shutil as _sh
        if not _sh.which("lz4"):
            pytest.skip("lz4 CLI not available")

        root = tmp_path / "root"
        root.mkdir()

        # Step 1: payload file
        payload_txt = tmp_path / "payload.txt"
        payload_txt.write_text("SAMSUNG PAYLOAD")

        # Step 2: wrap into inner.tar
        inner_tar = tmp_path / "inner.tar"
        with tarfile.open(inner_tar, "w") as tf:
            tf.add(payload_txt, arcname="payload.txt")

        # Step 3: compress inner.tar → inner.tar.lz4
        import subprocess
        inner_tar_lz4 = tmp_path / "inner.tar.lz4"
        subprocess.run(
            ["lz4", "-f", str(inner_tar), str(inner_tar_lz4)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Step 4: wrap in outer tar, name as .tar.md5
        outer = root / "fw.tar.md5"
        with tarfile.open(outer, "w") as tf:
            tf.add(inner_tar_lz4, arcname="inner.tar.lz4")

        new_dirs = _recursive_extract_nested(str(root), max_depth=3)
        assert new_dirs, "Helper produced no nested dirs"

        # payload.txt should be somewhere under the root
        found_payload = False
        for root_dir, _d, files in os.walk(root):
            if "payload.txt" in files:
                content = (Path(root_dir) / "payload.txt").read_text()
                if content == "SAMSUNG PAYLOAD":
                    found_payload = True
                    break
        assert found_payload, (
            f"tar.md5 → tar.lz4 → payload chain did not produce payload.txt. "
            f"new_dirs={new_dirs}"
        )

    def test_respects_max_depth(self, tmp_path: Path):
        """max_depth=1 must NOT recurse into child extraction dirs."""
        root = tmp_path / "root"
        root.mkdir()

        inner_tar = tmp_path / "inner.tar"
        p = tmp_path / "p.txt"
        p.write_text("x")
        with tarfile.open(inner_tar, "w") as tf:
            tf.add(p, arcname="p.txt")

        outer_tar = root / "outer.tar"
        with tarfile.open(outer_tar, "w") as tf:
            tf.add(inner_tar, arcname="inner.tar")

        # With depth 1 we expand outer.tar but NOT the inner.tar inside it
        new_dirs = _recursive_extract_nested(str(root), max_depth=1)
        # outer.tar_extracted exists; it contains inner.tar but no inner_extracted
        outer_out = root / "outer.tar_extracted"
        assert outer_out.is_dir()
        # inner.tar present inside — NOT yet expanded at depth 1
        assert (outer_out / "inner.tar").exists()
        assert not (outer_out / "inner.tar_extracted").exists()
        assert len(new_dirs) == 1

    def test_skips_symlinks(self, tmp_path: Path):
        """Never follow symlinks into archives."""
        root = tmp_path / "root"
        root.mkdir()
        real = tmp_path / "real.tar"
        p = tmp_path / "p.txt"
        p.write_text("x")
        with tarfile.open(real, "w") as tf:
            tf.add(p, arcname="p.txt")
        # symlink in root points at the real tar
        (root / "link.tar").symlink_to(real)

        new_dirs = _recursive_extract_nested(str(root), max_depth=3)
        # symlinked archive must not be extracted
        assert not (root / "link.tar_extracted").exists()
        # (new_dirs may still be 0 or include anything that isn't the symlink)
        for d in new_dirs:
            assert "link.tar_extracted" not in d


# ─── Test 7: Encrypted-container diagnostic ───────────────────────────────

class TestDiagnoseFailedArchives:
    """Surface vendor-encrypted / unrecognised archive-named files that
    ``_recursive_extract_nested`` silently dropped."""

    def test_empty_tree_returns_empty_dict(self, tmp_path: Path):
        from app.workers.unpack_common import diagnose_failed_archives

        (tmp_path / "note.txt").write_text("x")
        assert diagnose_failed_archives([str(tmp_path)]) == {}

    def test_real_tar_xz_not_flagged(self, tmp_path: Path):
        """A genuine tar.xz that extracted cleanly must not be flagged."""
        import lzma

        from app.workers.unpack_common import diagnose_failed_archives

        inner = tmp_path / "inner.txt"
        inner.write_text("hello")
        tar_path = tmp_path / "real.tar"
        with tarfile.open(tar_path, "w") as tf:
            tf.add(inner, arcname="inner.txt")
        xz_path = tmp_path / "real.tar.xz"
        with open(tar_path, "rb") as src, lzma.open(xz_path, "wb") as dst:
            dst.write(src.read())
        tar_path.unlink()

        result = diagnose_failed_archives([str(tmp_path)])
        assert result == {}

    def test_edan_signed_container_flagged(self, tmp_path: Path):
        """EDAN MPM magic (16 bytes) is recognised and tagged with vendor."""
        from app.workers.unpack_common import diagnose_failed_archives

        magic = bytes.fromhex("a3dfbbbf4e947c6649859f5e45d273ed")
        (tmp_path / "rootfs_partition.tar.xz").write_bytes(magic + b"\x00" * 64)
        (tmp_path / "boot_partition.tar.xz").write_bytes(magic + b"\xff" * 64)

        result = diagnose_failed_archives([str(tmp_path)])
        assert result["partial_extraction"] is True
        assert len(result["encrypted_archives"]) == 2
        assert all(e["vendor"] == "edan" for e in result["encrypted_archives"])
        assert all(e["format"] == "edan_mpm_signed" for e in result["encrypted_archives"])
        assert "edan" in result["summary"]

    def test_unknown_container_flagged_as_unrecognised(self, tmp_path: Path):
        """Random bytes named .tar.xz land in unrecognised_archives."""
        from app.workers.unpack_common import diagnose_failed_archives

        (tmp_path / "mystery.tar.xz").write_bytes(b"\x00" * 64)

        result = diagnose_failed_archives([str(tmp_path)])
        assert result["partial_extraction"] is True
        assert len(result["encrypted_archives"]) == 0
        assert len(result["unrecognised_archives"]) == 1

    def test_populated_extracted_sibling_skipped(self, tmp_path: Path):
        """If a *_extracted/ sibling has content, the archive is considered
        successfully extracted and NOT flagged."""
        from app.workers.unpack_common import diagnose_failed_archives

        # Archive file (invalid but with populated sibling)
        (tmp_path / "pkg.tar.xz").write_bytes(b"\x00" * 64)
        sibling = tmp_path / "pkg.tar.xz_extracted"
        sibling.mkdir()
        (sibling / "payload").write_text("x")

        result = diagnose_failed_archives([str(tmp_path)])
        assert result == {}


# ─── Test 8: Architecture fallback from zImage ────────────────────────────

class TestArchFallbackFromKernel:
    """Rootfs-less firmware still yields ``architecture`` from a kernel
    image header — used when rootfs payloads are vendor-encrypted."""

    def test_arm_zimage_header_returns_arm_little(self, tmp_path: Path):
        from app.workers.unpack_linux import detect_architecture_from_kernel

        # ARM zImage: magic 0x016F2818 at 0x24, endian marker at 0x30
        head = bytearray(0x40)
        head[0x24:0x28] = (0x016F2818).to_bytes(4, "little")
        head[0x30:0x34] = (0x04030201).to_bytes(4, "little")
        path = tmp_path / "zImage-restore"
        path.write_bytes(bytes(head) + b"\x00" * 1024)

        arch, endian = detect_architecture_from_kernel([str(tmp_path)])
        assert arch == "arm"
        assert endian == "little"

    def test_arm_big_endian_zimage_returns_big(self, tmp_path: Path):
        from app.workers.unpack_linux import detect_architecture_from_kernel

        head = bytearray(0x40)
        head[0x24:0x28] = (0x016F2818).to_bytes(4, "little")
        head[0x30:0x34] = (0x01020304).to_bytes(4, "little")
        (tmp_path / "zImage").write_bytes(bytes(head) + b"\x00" * 1024)

        arch, endian = detect_architecture_from_kernel([str(tmp_path)])
        assert arch == "arm"
        assert endian == "big"

    def test_aarch64_image_header(self, tmp_path: Path):
        from app.workers.unpack_linux import detect_architecture_from_kernel

        head = bytearray(0x40)
        head[0x38:0x3C] = b"ARM\x64"  # arm64 magic
        head[0x30:0x38] = (0).to_bytes(8, "little")  # LE flag
        (tmp_path / "Image").write_bytes(bytes(head) + b"\x00" * 1024)

        arch, endian = detect_architecture_from_kernel([str(tmp_path)])
        assert arch == "aarch64"
        assert endian == "little"

    def test_no_kernel_returns_none(self, tmp_path: Path):
        from app.workers.unpack_linux import detect_architecture_from_kernel

        (tmp_path / "notes.txt").write_text("nothing to see")
        assert detect_architecture_from_kernel([str(tmp_path)]) == (None, None)

    def test_walks_nested_extracted_dirs(self, tmp_path: Path):
        """RespArray shape: zImage lives 2 dirs deep in a sibling _extracted/."""
        from app.workers.unpack_linux import detect_architecture_from_kernel

        nested = tmp_path / "zImage-restore.tar.xz_extracted" / "zImage-restore"
        nested.mkdir(parents=True)
        head = bytearray(0x40)
        head[0x24:0x28] = (0x016F2818).to_bytes(4, "little")
        head[0x30:0x34] = (0x04030201).to_bytes(4, "little")
        (nested / "zImage-restore").write_bytes(bytes(head) + b"\x00" * 1024)

        arch, endian = detect_architecture_from_kernel([str(tmp_path)])
        assert arch == "arm"
        assert endian == "little"


# ─── Test 7: user-data partitions skipped before conversion ───────────────

class TestUserDataPartitionSkipped:
    """Skip ``userdata`` / ``cache`` / ``metadata`` / ``persist`` / ``misc``
    before sparse→raw conversion so their multi-GB declared sizes don't
    inflate the extraction tree and trip bomb limits (DPCS10 regression).
    """

    def test_every_aosp_user_data_partition_matches(self):
        for base in ("userdata", "cache", "metadata", "persist", "misc"):
            assert _is_user_data_partition(f"{base}.img") is True, base

    def test_ab_slot_suffixes_match(self):
        assert _is_user_data_partition("userdata_a.img") is True
        assert _is_user_data_partition("userdata_b.img") is True
        assert _is_user_data_partition("cache_a.img") is True

    def test_case_insensitive(self):
        assert _is_user_data_partition("USERDATA.img") is True
        assert _is_user_data_partition("Cache.IMG") is True

    def test_firmware_partitions_are_not_user_data(self):
        for name in (
            "system.img", "vendor.img", "vbmeta.img", "super.img",
            "boot.img", "init_boot.img", "dtbo.img", "modem.img",
            "tee.img", "gz.img", "scp.img", "lk.img",
            "vbmeta_system.img", "vbmeta_vendor.img",
        ):
            assert _is_user_data_partition(name) is False, name

    def test_user_data_base_set_matches_aosp_doc(self):
        assert _USER_DATA_PARTITION_BASES == frozenset({
            "userdata", "cache", "metadata", "persist", "misc",
        })

    @pytest.mark.asyncio
    async def test_userdata_img_removed_during_ota_extract(self, tmp_path: Path):
        """Scatter zip with userdata.img + firmware partition → userdata
        deleted early, firmware survives, log records the skip."""
        src_zip = tmp_path / "scatter.zip"
        ver_dir = "DPCS10_260414-1134"
        # Sparse-magic userdata (ensures the skip beats sparse→raw conversion)
        userdata_bytes = b"\x3a\xff\x26\xed" + b"\x00" * 4096
        lk_bytes = b"LK_CONTENT" * 500
        with zipfile.ZipFile(src_zip, "w") as zf:
            zf.writestr(f"{ver_dir}/userdata.img", userdata_bytes)
            zf.writestr(f"{ver_dir}/lk.img", lk_bytes)

        extraction_dir = tmp_path / "ext"
        extraction_dir.mkdir()
        log = await _extract_android_ota(str(src_zip), str(extraction_dir))

        def _exists_anywhere(name: str) -> bool:
            for _r, _d, files in os.walk(extraction_dir):
                if name in files:
                    return True
            return False

        assert not _exists_anywhere("userdata.img"), (
            f"userdata.img should have been removed; log:\n{log}"
        )
        assert _exists_anywhere("lk.img"), (
            f"lk.img was incorrectly removed; log:\n{log}"
        )
        assert "user-data partition" in log.lower(), (
            f"Skip log missing; log:\n{log}"
        )

    @pytest.mark.asyncio
    async def test_all_five_user_data_names_skipped(self, tmp_path: Path):
        src_zip = tmp_path / "scatter.zip"
        ver_dir = "VER"
        noise = b"\x00" * 128
        with zipfile.ZipFile(src_zip, "w") as zf:
            for name in ("cache.img", "metadata.img", "persist.img", "misc.img"):
                zf.writestr(f"{ver_dir}/{name}", noise)
            zf.writestr(f"{ver_dir}/userdata_a.img", noise)
            zf.writestr(f"{ver_dir}/vbmeta.img", b"VBMETA" * 50)

        extraction_dir = tmp_path / "ext"
        extraction_dir.mkdir()
        log = await _extract_android_ota(str(src_zip), str(extraction_dir))

        def _exists_anywhere(name: str) -> bool:
            for _r, _d, files in os.walk(extraction_dir):
                if name in files:
                    return True
            return False

        for name in (
            "cache.img", "metadata.img", "persist.img", "misc.img",
            "userdata_a.img",
        ):
            assert not _exists_anywhere(name), (
                f"{name} should have been skipped; log:\n{log}"
            )
        assert _exists_anywhere("vbmeta.img"), "firmware partition lost"


# ─── Test 8: super.img scan returns (extracted, total) tuple ──────────────

class TestScanSuperReturnsTuple:
    """Post-fix, ``_scan_super_partitions`` returns ``(extracted, total)``
    so the caller can decide whether the raw LP2 container is redundant
    (delete when full extraction succeeded — saves ~9 GB on real
    Android firmware) or still load-bearing (keep when partial)."""

    @pytest.mark.asyncio
    async def test_empty_super_returns_zero_zero(self, tmp_path: Path):
        from app.workers.unpack_android import _scan_super_partitions

        raw = tmp_path / "super.img.raw"
        raw.write_bytes(b"\x00" * 4096)
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        log: list[str] = []

        result = await _scan_super_partitions(str(raw), str(rootfs), log)

        assert isinstance(result, tuple) and len(result) == 2
        assert result == (0, 0)

