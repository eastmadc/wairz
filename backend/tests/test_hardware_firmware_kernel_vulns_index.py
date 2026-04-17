"""Unit tests for the kernel.org vulns.git subsystem index (Phase 4).

The module under test talks to Redis and shells out to git.  Tests here
mock both at the ``redis.asyncio.from_url`` boundary and at the
``asyncio.create_subprocess_exec`` boundary, so nothing touches the real
network or a real Redis instance.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.hardware_firmware import kernel_vulns_index as kvi
from app.services.hardware_firmware.cve_matcher import _KMOD_TO_SUBSYSTEM, _kmod_basename

# ---------------------------------------------------------------------------
# Inline mock Redis — only the surface kernel_vulns_index uses.
# ---------------------------------------------------------------------------


class _FakePipeline:
    def __init__(self, store: dict[str, str]) -> None:
        self._store = store
        self._ops: list[tuple[str, str]] = []

    def set(self, key: str, value: str, ex: int | None = None) -> None:  # noqa: ARG002
        self._ops.append((key, value))

    async def execute(self) -> None:
        for k, v in self._ops:
            self._store[k] = v
        self._ops.clear()


class FakeRedis:
    """In-memory stand-in covering the 5 methods kernel_vulns_index calls."""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._store: dict[str, str] = dict(initial or {})
        self.ping_ok = True

    async def ping(self) -> bool:
        if not self.ping_ok:
            raise ConnectionError("redis ping failed")
        return True

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    def pipeline(self, transaction: bool = False) -> _FakePipeline:  # noqa: ARG002
        return _FakePipeline(self._store)

    async def scan_iter(self, match: str, count: int = 10):  # noqa: ARG002
        prefix = match.rstrip("*")
        for k in list(self._store.keys()):
            if k.startswith(prefix):
                yield k

    async def aclose(self) -> None:
        return None


def _patch_redis(fake: FakeRedis):
    """Patch ``aioredis.from_url`` to return the supplied FakeRedis."""
    return patch(
        "app.services.hardware_firmware.kernel_vulns_index.aioredis.from_url",
        return_value=fake,
    )


# ---------------------------------------------------------------------------
# _KMOD_TO_SUBSYSTEM — coverage sanity
# ---------------------------------------------------------------------------


def test_kmod_to_subsystem_has_enough_entries() -> None:
    # Campaign target: 40-50 entries.  Allow a floor of 40.
    assert len(_KMOD_TO_SUBSYSTEM) >= 40, (
        f"Expected >=40 subsystem mappings, got {len(_KMOD_TO_SUBSYSTEM)}"
    )


def test_kmod_to_subsystem_paths_end_in_slash() -> None:
    # Every value must be a subsystem *directory* with trailing slash so the
    # Redis key naming is consistent with _subsystem_from_programfile output.
    for basename, path in _KMOD_TO_SUBSYSTEM.items():
        assert path.endswith("/"), f"{basename} -> {path} missing trailing slash"
        assert not path.startswith("/"), f"{basename} -> {path} should be relative"


# ---------------------------------------------------------------------------
# _kmod_basename normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("blob_path", "expected"),
    [
        ("/vendor/lib/modules/bluetooth.ko", "bluetooth"),
        ("/system/lib/modules/fuse.ko", "fuse"),
        ("/vendor/lib/modules/mali_kbase_mt6771_r49p0.ko", "mali_kbase"),
        ("/vendor/lib/modules/ath11k_pci.ko", "ath11k_pci"),  # exact hit, stays
        ("/vendor/lib/modules/nft_ct.ko", "nft_ct"),  # exact hit, stays
        ("/vendor/lib/modules/iwlwifi.ko", "iwlwifi"),
        ("/vendor/lib/modules/iwlwifi_8000.ko", "iwlwifi"),  # anchor collapse
        ("/vendor/lib/modules/brcmfmac_pcie.ko", "brcmfmac"),  # anchor collapse
        ("/vendor/lib/modules/bluetooth.ko.xz", "bluetooth"),  # compressed kmod
        ("/vendor/lib/modules/unknown_driver.ko", "unknown_driver"),
        ("", ""),
        (None, ""),
    ],
)
def test_kmod_basename(blob_path: str | None, expected: str) -> None:
    assert _kmod_basename(blob_path) == expected


# ---------------------------------------------------------------------------
# _subsystem_from_programfile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("program_file", "expected"),
    [
        ("net/bluetooth/smp.c", "net/bluetooth/"),
        ("drivers/gpu/arm/midgard/mali_kbase.c", "drivers/gpu/arm/midgard/"),
        ("fs/ext4/namei.c", "fs/ext4/"),
        ("topfile.c", None),  # no slash -> no subsystem
        ("", None),
        ("./fs/fuse/dir.c", "fs/fuse/"),  # dot-slash stripped
    ],
)
def test_subsystem_from_programfile(program_file: str, expected: str | None) -> None:
    assert kvi._subsystem_from_programfile(program_file) == expected


# ---------------------------------------------------------------------------
# _extract_entries — CVE JSON -> (subsystem, entry) pairs
# ---------------------------------------------------------------------------


def _sample_cve(
    cve_id: str,
    program_files: list[str],
    version: str | None = "6.5",
    less_than: str | None = "6.6.70",
    severity: str = "HIGH",
    description: str = "sample description",
) -> dict[str, Any]:
    return {
        "cveMetadata": {"cveId": cve_id},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "programFiles": program_files,
                        "versions": [
                            {
                                "version": version,
                                "lessThan": less_than,
                                "status": "affected",
                                "versionType": "semver",
                            }
                        ],
                    }
                ],
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": [
                    {"cvssV3_1": {"baseSeverity": severity}},
                ],
            }
        },
    }


def test_extract_entries_single_file() -> None:
    cve = _sample_cve("CVE-2024-26920", ["net/bluetooth/smp.c"])
    entries = kvi._extract_entries(cve)
    assert len(entries) == 1
    subsystem, entry = entries[0]
    assert subsystem == "net/bluetooth/"
    assert entry["cve_id"] == "CVE-2024-26920"
    assert entry["min_version"] == "6.5"
    assert entry["max_version_excl"] == "6.6.70"
    assert entry["severity"] == "high"


def test_extract_entries_multiple_files_multiple_subsystems() -> None:
    cve = _sample_cve(
        "CVE-2024-XYZ",
        ["net/bluetooth/hci_core.c", "net/wireless/core.c"],
    )
    entries = kvi._extract_entries(cve)
    subsystems = {s for s, _e in entries}
    assert subsystems == {"net/bluetooth/", "net/wireless/"}


def test_extract_entries_missing_cve_id_returns_empty() -> None:
    bogus = {"containers": {"cna": {"affected": []}}}
    assert kvi._extract_entries(bogus) == []


def test_extract_entries_accepts_cveid_key_variant() -> None:
    """Real kernel.org CNA output uses ``cveID`` (capital D); tolerate both."""
    cve = {
        "cveMetadata": {"cveID": "CVE-2024-42424"},  # capitalised ID
        "containers": {
            "cna": {
                "affected": [
                    {
                        "programFiles": ["net/bluetooth/l2cap_core.c"],
                        "versions": [
                            {
                                "version": "6.6.133",
                                "lessThanOrEqual": "6.6.*",
                                "status": "unaffected",
                                "versionType": "semver",
                            },
                        ],
                    }
                ],
                "descriptions": [{"lang": "en", "value": "sample bt flaw"}],
                "metrics": [{"cvssV3_1": {"baseSeverity": "HIGH"}}],
            }
        },
    }
    entries = kvi._extract_entries(cve)
    assert len(entries) == 1
    subsystem, entry = entries[0]
    assert subsystem == "net/bluetooth/"
    assert entry["cve_id"] == "CVE-2024-42424"
    # unaffected status with version=6.6.133 means "fixed at 6.6.133" => the
    # affected range is [None, 6.6.133).
    assert entry["min_version"] is None
    assert entry["max_version_excl"] == "6.6.133"


def test_extract_entries_affected_point_release_bumps_patch() -> None:
    """status=affected, version=6.11 with no lessThan -> affected at exactly 6.11,
    so the range is [6.11, 6.11.1) after the patch-bump helper."""
    cve = {
        "cveMetadata": {"cveID": "CVE-2024-POINT"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "programFiles": ["fs/ext4/namei.c"],
                        "versions": [
                            {"version": "6.11", "status": "affected", "versionType": "semver"},
                        ],
                    }
                ],
                "descriptions": [{"lang": "en", "value": ""}],
            }
        },
    }
    entries = kvi._extract_entries(cve)
    assert len(entries) == 1
    _sub, entry = entries[0]
    assert entry["min_version"] == "6.11"
    assert entry["max_version_excl"] == "6.11.1"


def test_extract_entries_skips_git_sha_version_type() -> None:
    """``versionType=git`` entries are commit SHAs; we can't do semver
    comparison on them and must skip, falling back to an open-ended record
    only if nothing else survived."""
    cve = {
        "cveMetadata": {"cveID": "CVE-GIT-ONLY"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "programFiles": ["fs/xattr.c"],
                        "versions": [
                            {
                                "version": "c03185f4a23e",
                                "lessThan": "9a3a2ae5efbb",
                                "status": "affected",
                                "versionType": "git",
                            }
                        ],
                    }
                ],
                "descriptions": [{"lang": "en", "value": ""}],
            }
        },
    }
    entries = kvi._extract_entries(cve)
    # No semver survived -> the fallback open-ended record still lands.
    assert len(entries) == 1
    _sub, entry = entries[0]
    assert entry["min_version"] is None
    assert entry["max_version_excl"] is None


# ---------------------------------------------------------------------------
# _filter_by_version — semver-aware range filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_by_version_in_range() -> None:
    entries = [
        {"cve_id": "CVE-A", "min_version": "6.5", "max_version_excl": "6.6.70"},
        {"cve_id": "CVE-B", "min_version": "7.0", "max_version_excl": "7.2"},
    ]
    out = await kvi._filter_by_version(entries, "6.6.50")
    assert {e["cve_id"] for e in out} == {"CVE-A"}


@pytest.mark.asyncio
async def test_filter_by_version_open_bounds() -> None:
    entries = [
        {"cve_id": "CVE-OPEN", "min_version": None, "max_version_excl": None},
    ]
    out = await kvi._filter_by_version(entries, "6.6.102")
    assert len(out) == 1


@pytest.mark.asyncio
async def test_filter_by_version_boundary_exclusive() -> None:
    # max_version_excl is *exclusive* — 6.6.70 should fall outside.
    entries = [
        {"cve_id": "CVE-EDGE", "min_version": "6.5", "max_version_excl": "6.6.70"},
    ]
    assert await kvi._filter_by_version(entries, "6.6.70") == []
    # But 6.6.69 is inside.
    out = await kvi._filter_by_version(entries, "6.6.69")
    assert len(out) == 1


@pytest.mark.asyncio
async def test_filter_by_version_invalid_kernel_returns_empty() -> None:
    entries = [{"cve_id": "CVE-A", "min_version": None, "max_version_excl": None}]
    assert await kvi._filter_by_version(entries, "not-a-version") == []


# ---------------------------------------------------------------------------
# lookup — end-to-end through FakeRedis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_returns_in_range_cves_only() -> None:
    entries = [
        {
            "cve_id": "CVE-IN",
            "min_version": "6.5",
            "max_version_excl": "6.6.105",
            "severity": "high",
            "description": "in range",
        },
        {
            "cve_id": "CVE-OUT",
            "min_version": "7.0",
            "max_version_excl": "7.1",
            "severity": "medium",
            "description": "out of range",
        },
    ]
    fake = FakeRedis(
        {"kernel_vulns:subsystem:net/bluetooth/": json.dumps(entries)}
    )
    with _patch_redis(fake):
        matches = await kvi.lookup("net/bluetooth/", "6.6.102")
    assert {m["cve_id"] for m in matches} == {"CVE-IN"}


@pytest.mark.asyncio
async def test_lookup_empty_subsystem_returns_empty_list() -> None:
    fake = FakeRedis({})
    with _patch_redis(fake):
        matches = await kvi.lookup("net/bluetooth/", "6.6.102")
    assert matches == []


@pytest.mark.asyncio
async def test_lookup_no_redis_returns_empty() -> None:
    """Redis unavailable -> graceful []; never raises."""
    with patch(
        "app.services.hardware_firmware.kernel_vulns_index.aioredis.from_url",
        side_effect=ConnectionError("down"),
    ):
        out = await kvi.lookup("net/bluetooth/", "6.6.102")
    assert out == []


# ---------------------------------------------------------------------------
# is_populated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_populated_false_on_empty_redis() -> None:
    fake = FakeRedis({})
    with _patch_redis(fake):
        assert await kvi.is_populated() is False


@pytest.mark.asyncio
async def test_is_populated_true_when_subsystem_key_present() -> None:
    fake = FakeRedis({"kernel_vulns:subsystem:fs/ext4/": "[]"})
    with _patch_redis(fake):
        assert await kvi.is_populated() is True


# ---------------------------------------------------------------------------
# sync — graceful degradation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_returns_no_git_when_binary_missing() -> None:
    """``sync()`` must not raise when ``git`` is absent; returns a status dict."""
    with patch(
        "app.services.hardware_firmware.kernel_vulns_index.shutil.which",
        return_value=None,
    ):
        result = await kvi.sync()
    assert result == {"status": "no_git"}


@pytest.mark.asyncio
async def test_sync_returns_clone_failed_on_git_error() -> None:
    """Simulate git clone returning non-zero — sync falls through cleanly."""

    async def _fake_run_git(args: list[str], cwd: str | None = None, timeout: int = 0):  # noqa: ARG001, ASYNC109
        return (128, "", "fatal: unable to access host")

    with (
        patch(
            "app.services.hardware_firmware.kernel_vulns_index.shutil.which",
            return_value="/usr/bin/git",
        ),
        patch(
            "app.services.hardware_firmware.kernel_vulns_index._run_git",
            side_effect=_fake_run_git,
        ),
        patch(
            "app.services.hardware_firmware.kernel_vulns_index.Path.is_dir",
            return_value=False,
        ),
    ):
        result = await kvi.sync()
    assert result["status"] == "clone_failed"
    assert "fatal" in result["error"]


# ---------------------------------------------------------------------------
# Integration — cve_matcher Tier 5 wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tier5_matcher_produces_kernel_subsystem_rows() -> None:
    """Bluetooth.ko blob @ kernel 6.6.102 -> 1 Tier-5 CveMatch.

    Mocks ``kernel_vulns_index.is_populated`` and ``.lookup`` so no real
    Redis / git involvement.
    """
    import uuid

    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.hardware_firmware.cve_matcher import _match_kernel_subsystem

    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = uuid.uuid4()
    blob.category = "kernel_module"
    blob.blob_path = "/vendor/lib/modules/bluetooth.ko"
    blob.metadata_ = {"kernel_semver": "6.6.102"}

    with (
        patch.object(kvi, "is_populated", AsyncMock(return_value=True)),
        patch.object(
            kvi,
            "lookup",
            AsyncMock(
                return_value=[
                    {
                        "cve_id": "CVE-2024-TEST-BT",
                        "severity": "high",
                        "description": "Bluetooth subsystem flaw",
                    }
                ]
            ),
        ),
    ):
        matches = await _match_kernel_subsystem([blob])

    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2024-TEST-BT"
    assert matches[0].tier == "kernel_subsystem"
    assert matches[0].confidence == "high"
    assert matches[0].blob_id == blob.id


@pytest.mark.asyncio
async def test_tier5_matcher_skips_when_index_not_populated() -> None:
    """If Redis is empty, Tier 5 logs and returns [] — never raises."""
    import uuid

    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.hardware_firmware.cve_matcher import _match_kernel_subsystem

    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = uuid.uuid4()
    blob.category = "kernel_module"
    blob.blob_path = "/vendor/lib/modules/bluetooth.ko"
    blob.metadata_ = {"kernel_semver": "6.6.102"}

    with patch.object(kvi, "is_populated", AsyncMock(return_value=False)):
        matches = await _match_kernel_subsystem([blob])
    assert matches == []


@pytest.mark.asyncio
async def test_tier5_matcher_skips_without_kernel_semver() -> None:
    """A kmod blob with no kernel_semver metadata contributes nothing."""
    import uuid

    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.hardware_firmware.cve_matcher import _match_kernel_subsystem

    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.id = uuid.uuid4()
    blob.category = "kernel_module"
    blob.blob_path = "/vendor/lib/modules/bluetooth.ko"
    blob.metadata_ = {}  # no kernel_semver

    with (
        patch.object(kvi, "is_populated", AsyncMock(return_value=True)),
        patch.object(kvi, "lookup", AsyncMock()) as lookup_mock,
    ):
        matches = await _match_kernel_subsystem([blob])
    assert matches == []
    lookup_mock.assert_not_called()


@pytest.mark.asyncio
async def test_tier5_matcher_ignores_non_kmod_blobs() -> None:
    """Only kernel_module blobs are considered for Tier 5."""
    import uuid

    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.hardware_firmware.cve_matcher import _match_kernel_subsystem

    wifi_blob = MagicMock(spec=HardwareFirmwareBlob)
    wifi_blob.id = uuid.uuid4()
    wifi_blob.category = "wifi"
    wifi_blob.blob_path = "/vendor/firmware/wifi.bin"
    wifi_blob.metadata_ = {"kernel_semver": "6.6.102"}

    # No DB/Redis mocks needed — short-circuit before any async work.
    matches = await _match_kernel_subsystem([wifi_blob])
    assert matches == []
