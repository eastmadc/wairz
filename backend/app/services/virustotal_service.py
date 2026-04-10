"""VirusTotal hash-only lookup service.

Privacy-first: only SHA-256 hashes are sent to VirusTotal, never file
contents. Graceful degradation when VT_API_KEY is not configured.
Rate limiting respects the free-tier limit of 4 requests/minute.
"""

import asyncio
import hashlib
import logging
import os
import stat
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"

# Free tier: 4 lookups per minute
FREE_TIER_BATCH = 4
FREE_TIER_DELAY = 15.0  # seconds between batches of 4

# ELF magic bytes
ELF_MAGIC = b"\x7fELF"
# PE magic bytes
PE_MAGIC = b"MZ"


@dataclass
class VTResult:
    """Result of a VirusTotal hash lookup."""
    sha256: str
    found: bool
    detection_count: int = 0
    total_engines: int = 0
    detections: list[str] = field(default_factory=list)
    permalink: str = ""
    file_path: str = ""


def _get_api_key() -> str:
    from app.config import get_settings
    return get_settings().virustotal_api_key


def _compute_sha256(file_path: str) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


async def check_hash(sha256: str) -> VTResult | None:
    """Look up a single SHA-256 hash on VirusTotal.

    Returns None if VT API key is not configured.
    Returns VTResult with found=False if hash not in VT corpus.
    """
    api_key = _get_api_key()
    if not api_key:
        return None

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{VT_API_BASE}/files/{sha256}",
                headers={"x-apikey": api_key},
            )

            if resp.status_code == 404:
                return VTResult(sha256=sha256, found=False)

            if resp.status_code == 429:
                # Rate limited — wait and retry once
                await asyncio.sleep(FREE_TIER_DELAY)
                resp = await client.get(
                    f"{VT_API_BASE}/files/{sha256}",
                    headers={"x-apikey": api_key},
                )
                if resp.status_code != 200:
                    return VTResult(
                        sha256=sha256, found=False,
                    )

            if resp.status_code != 200:
                logger.warning("VT API returned %d for %s", resp.status_code, sha256)
                return VTResult(sha256=sha256, found=False)

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            detection_count = malicious + suspicious
            total_engines = sum(stats.values())

            # Collect detection names
            detections: list[str] = []
            for engine, info in results.items():
                if info.get("category") in ("malicious", "suspicious"):
                    result_name = info.get("result", engine)
                    detections.append(f"{engine}: {result_name}")

            permalink = f"https://www.virustotal.com/gui/file/{sha256}"

            return VTResult(
                sha256=sha256,
                found=True,
                detection_count=detection_count,
                total_engines=total_engines,
                detections=detections[:20],  # Cap to avoid huge output
                permalink=permalink,
            )

    except Exception as e:
        logger.warning("VT lookup failed for %s: %s", sha256, e)
        return VTResult(sha256=sha256, found=False)


async def batch_check_hashes(
    hashes: list[tuple[str, str]],  # [(sha256, file_path), ...]
    max_concurrent: int = 4,
) -> list[VTResult]:
    """Batch check multiple hashes with rate limiting.

    Processes in batches of max_concurrent, sleeping between batches
    to respect the free-tier rate limit.

    Each entry is a (sha256, file_path) tuple so results can be
    associated back to files.
    """
    api_key = _get_api_key()
    if not api_key:
        return []

    results: list[VTResult] = []

    for i in range(0, len(hashes), max_concurrent):
        if i > 0:
            # Rate limit: wait between batches
            await asyncio.sleep(FREE_TIER_DELAY)

        batch = hashes[i : i + max_concurrent]
        tasks = [check_hash(sha256) for sha256, _ in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for (sha256, file_path), result in zip(batch, batch_results):
            if isinstance(result, Exception):
                logger.warning("VT batch check failed for %s: %s", sha256, result)
                results.append(VTResult(sha256=sha256, found=False, file_path=file_path))
            elif result is None:
                results.append(VTResult(sha256=sha256, found=False, file_path=file_path))
            else:
                result.file_path = file_path
                results.append(result)

    return results


def collect_binary_hashes(
    extracted_root: str, max_files: int = 200
) -> list[tuple[str, str]]:
    """Collect SHA-256 hashes of ELF/PE binaries in extracted firmware.

    Prioritizes: shared libraries > executables > scripts.
    Returns list of (sha256, relative_path) tuples.

    This is a sync function — call from run_in_executor().
    """
    libs: list[str] = []
    executables: list[str] = []
    others: list[str] = []

    for dirpath, _dirs, filenames in os.walk(extracted_root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                st = os.lstat(fpath)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size < 64 or st.st_size > 100 * 1024 * 1024:
                continue

            # Check if ELF or PE by reading magic bytes
            try:
                with open(fpath, "rb") as f:
                    magic = f.read(4)
            except OSError:
                continue

            if magic[:4] == ELF_MAGIC or magic[:2] == PE_MAGIC:
                rel = "/" + os.path.relpath(fpath, extracted_root)
                if ".so" in fname or fname.endswith(".dll"):
                    libs.append(fpath)
                elif st.st_mode & stat.S_IXUSR:
                    executables.append(fpath)
                else:
                    others.append(fpath)

    # Prioritize: libs > executables > others
    all_files = libs + executables + others
    all_files = all_files[:max_files]

    result: list[tuple[str, str]] = []
    for fpath in all_files:
        try:
            sha256 = _compute_sha256(fpath)
            rel = "/" + os.path.relpath(fpath, extracted_root)
            result.append((sha256, rel))
        except OSError:
            continue

    return result
