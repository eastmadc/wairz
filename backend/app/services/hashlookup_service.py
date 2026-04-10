"""CIRCL Hashlookup service for known-good file identification.

Uses the CIRCL hashlookup.circl.lu API to check if a file hash exists
in the NSRL (National Software Reference Library) or other known-good
databases. This helps reduce analyst workload by filtering out
legitimate files from threat intel results.

No API key required. Rate limiting is polite (1 req/sec default).
"""

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

HASHLOOKUP_API = "https://hashlookup.circl.lu"

# Polite rate limiting
BATCH_DELAY = 0.3  # seconds between requests


@dataclass
class HashlookupResult:
    """Result of a CIRCL hashlookup query."""
    sha256: str
    known: bool
    source: str = ""
    product_name: str = ""
    vendor: str = ""
    file_name: str = ""
    file_path: str = ""


async def check_known_good(sha256: str) -> HashlookupResult:
    """Look up a SHA-256 hash in CIRCL's known-good database.

    Returns HashlookupResult with known=True if the hash is recognized
    as a legitimate file (from NSRL or other sources).
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{HASHLOOKUP_API}/lookup/sha256/{sha256}",
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 404:
                return HashlookupResult(sha256=sha256, known=False)

            if resp.status_code != 200:
                logger.warning("CIRCL hashlookup returned %d for %s", resp.status_code, sha256)
                return HashlookupResult(sha256=sha256, known=False)

            data = resp.json()
            return HashlookupResult(
                sha256=sha256,
                known=True,
                source=data.get("source", "NSRL"),
                product_name=data.get("ProductName", ""),
                vendor=data.get("MfgName", ""),
                file_name=data.get("FileName", ""),
            )

    except Exception as e:
        logger.warning("CIRCL hashlookup failed for %s: %s", sha256, e)
        return HashlookupResult(sha256=sha256, known=False)


async def batch_check_known_good(
    hashes: list[tuple[str, str]],  # [(sha256, file_path), ...]
    max_files: int = 200,
) -> list[HashlookupResult]:
    """Batch check multiple hashes against CIRCL hashlookup.

    Returns results for all hashes, with known=True for recognized files.
    Inserts a small delay between requests.
    """
    results: list[HashlookupResult] = []

    # Also try the bulk endpoint first for efficiency
    sha256_list = [h for h, _ in hashes[:max_files]]
    bulk_results = await _bulk_lookup(sha256_list)

    for sha256, file_path in hashes[:max_files]:
        if sha256 in bulk_results:
            result = bulk_results[sha256]
            result.file_path = file_path
            results.append(result)
        else:
            results.append(HashlookupResult(
                sha256=sha256, known=False, file_path=file_path
            ))

    return results


async def _bulk_lookup(sha256_list: list[str]) -> dict[str, HashlookupResult]:
    """Use CIRCL's bulk lookup endpoint for efficiency.

    Falls back to individual lookups if bulk fails.
    """
    results: dict[str, HashlookupResult] = {}

    # CIRCL supports bulk lookup via POST to /bulk/sha256
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{HASHLOOKUP_API}/bulk/sha256",
                json=sha256_list,
                headers={"Accept": "application/json"},
            )

            if resp.status_code == 200:
                body = resp.json()
                for entry in body if isinstance(body, list) else []:
                    sha256 = entry.get("sha256", entry.get("SHA-256", "")).lower()
                    if sha256 and entry.get("ProductName") or entry.get("FileName"):
                        results[sha256] = HashlookupResult(
                            sha256=sha256,
                            known=True,
                            source=entry.get("source", "NSRL"),
                            product_name=entry.get("ProductName", ""),
                            vendor=entry.get("MfgName", ""),
                            file_name=entry.get("FileName", ""),
                        )
                return results

    except Exception as e:
        logger.debug("Bulk hashlookup failed, falling back to individual: %s", e)

    # Fallback: individual lookups
    for i, sha256 in enumerate(sha256_list):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        result = await check_known_good(sha256)
        if result.known:
            results[sha256] = result

    return results
