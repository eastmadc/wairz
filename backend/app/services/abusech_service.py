"""abuse.ch threat intelligence service.

Integrates four abuse.ch services for firmware threat intel:
- MalwareBazaar: hash → known malware sample?
- ThreatFox: IOC (hash/IP/domain) → known C2/malware?
- URLhaus: URL → known malicious distribution point?
- YARAify: hash → community YARA rule matches?

All lookups are hash/IOC-based — no file contents are ever uploaded.
Graceful degradation when ABUSECH_AUTH_KEY is not configured (most
endpoints work without auth, but rate limits are stricter).
"""

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# API endpoints
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
YARAIFY_API = "https://yaraify-api.abuse.ch/api/v2"

# Rate limiting: abuse.ch is generous but we still batch politely
BATCH_DELAY = 0.5  # seconds between requests


def _get_auth_key() -> str:
    from app.config import get_settings
    return get_settings().abusech_auth_key


@dataclass
class MalwareBazaarResult:
    """Result from MalwareBazaar hash lookup."""
    sha256: str
    found: bool
    file_type: str = ""
    signature: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    reporter: str = ""
    file_path: str = ""


@dataclass
class ThreatFoxResult:
    """Result from ThreatFox IOC lookup."""
    ioc: str
    ioc_type: str  # ip:port, domain, url, md5_hash, sha256_hash
    found: bool
    threat_type: str = ""
    malware: str = ""
    confidence_level: int = 0
    tags: list[str] = field(default_factory=list)
    reference: str = ""


@dataclass
class URLhausResult:
    """Result from URLhaus URL lookup."""
    url: str
    found: bool
    threat: str = ""
    status: str = ""  # online, offline, unknown
    tags: list[str] = field(default_factory=list)
    date_added: str = ""


@dataclass
class YARAifyResult:
    """Result from YARAify hash lookup."""
    sha256: str
    found: bool
    rule_matches: list[str] = field(default_factory=list)
    file_path: str = ""


async def check_malwarebazaar(sha256: str) -> MalwareBazaarResult:
    """Look up a SHA-256 hash on MalwareBazaar.

    Works without an API key. Returns whether the hash is a known
    malware sample, with signature and tags if found.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = {"query": "get_info", "hash": sha256}
            auth_key = _get_auth_key()
            if auth_key:
                data["api_key"] = auth_key

            resp = await client.post(MALWAREBAZAAR_API, data=data)
            if resp.status_code != 200:
                logger.warning("MalwareBazaar returned %d for %s", resp.status_code, sha256)
                return MalwareBazaarResult(sha256=sha256, found=False)

            body = resp.json()
            if body.get("query_status") != "ok":
                return MalwareBazaarResult(sha256=sha256, found=False)

            # First result
            samples = body.get("data", [])
            if not samples:
                return MalwareBazaarResult(sha256=sha256, found=False)

            sample = samples[0]
            return MalwareBazaarResult(
                sha256=sha256,
                found=True,
                file_type=sample.get("file_type", ""),
                signature=sample.get("signature") or "",
                tags=sample.get("tags") or [],
                first_seen=sample.get("first_seen", ""),
                reporter=sample.get("reporter", ""),
            )

    except Exception as e:
        logger.warning("MalwareBazaar lookup failed for %s: %s", sha256, e)
        return MalwareBazaarResult(sha256=sha256, found=False)


async def check_threatfox(ioc: str, ioc_type: str = "sha256_hash") -> list[ThreatFoxResult]:
    """Look up an IOC on ThreatFox.

    ioc_type: ip:port, domain, url, md5_hash, sha256_hash
    Works without an API key.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            payload: dict = {"query": "search_ioc", "search_term": ioc}
            auth_key = _get_auth_key()
            headers = {}
            if auth_key:
                headers["Auth-Key"] = auth_key

            resp = await client.post(THREATFOX_API, json=payload, headers=headers)
            if resp.status_code != 200:
                logger.warning("ThreatFox returned %d for %s", resp.status_code, ioc)
                return []

            body = resp.json()
            if body.get("query_status") != "ok":
                return []

            results: list[ThreatFoxResult] = []
            for entry in (body.get("data") or [])[:20]:
                results.append(ThreatFoxResult(
                    ioc=ioc,
                    ioc_type=entry.get("ioc_type", ioc_type),
                    found=True,
                    threat_type=entry.get("threat_type", ""),
                    malware=entry.get("malware_printable", ""),
                    confidence_level=entry.get("confidence_level", 0),
                    tags=entry.get("tags") or [],
                    reference=entry.get("reference", ""),
                ))
            return results

    except Exception as e:
        logger.warning("ThreatFox lookup failed for %s: %s", ioc, e)
        return []


async def check_urlhaus(url: str) -> URLhausResult:
    """Look up a URL on URLhaus.

    Works without an API key. Returns whether the URL is a known
    malware distribution point.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{URLHAUS_API}/url/", data={"url": url})
            if resp.status_code != 200:
                logger.warning("URLhaus returned %d for %s", resp.status_code, url)
                return URLhausResult(url=url, found=False)

            body = resp.json()
            if body.get("query_status") != "ok":
                return URLhausResult(url=url, found=False)

            return URLhausResult(
                url=url,
                found=True,
                threat=body.get("threat", ""),
                status=body.get("url_status", "unknown"),
                tags=body.get("tags") or [],
                date_added=body.get("date_added", ""),
            )

    except Exception as e:
        logger.warning("URLhaus lookup failed for %s: %s", url, e)
        return URLhausResult(url=url, found=False)


async def check_yaraify(sha256: str) -> YARAifyResult:
    """Look up a SHA-256 hash on YARAify.

    Returns community YARA rule matches for the given hash.
    Works without an API key.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{YARAIFY_API}/query/hash/sha256/{sha256}/"
            )
            if resp.status_code != 200:
                logger.warning("YARAify returned %d for %s", resp.status_code, sha256)
                return YARAifyResult(sha256=sha256, found=False)

            body = resp.json()
            if body.get("query_status") != "ok":
                return YARAifyResult(sha256=sha256, found=False)

            data = body.get("data", [])
            if not data:
                return YARAifyResult(sha256=sha256, found=False)

            # Collect unique rule names
            rules: set[str] = set()
            for entry in data:
                for task in entry.get("tasks", []):
                    rule_name = task.get("rule_name")
                    if rule_name:
                        rules.add(rule_name)

            return YARAifyResult(
                sha256=sha256,
                found=bool(rules),
                rule_matches=sorted(rules)[:50],
            )

    except Exception as e:
        logger.warning("YARAify lookup failed for %s: %s", sha256, e)
        return YARAifyResult(sha256=sha256, found=False)


async def batch_check_malwarebazaar(
    hashes: list[tuple[str, str]],  # [(sha256, file_path), ...]
) -> list[MalwareBazaarResult]:
    """Batch check multiple hashes against MalwareBazaar.

    Inserts a small delay between requests to be polite.
    """
    results: list[MalwareBazaarResult] = []
    for i, (sha256, file_path) in enumerate(hashes):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        result = await check_malwarebazaar(sha256)
        result.file_path = file_path
        results.append(result)
    return results


async def enrich_iocs(
    hashes: list[tuple[str, str]],
    ips: list[str] | None = None,
    urls: list[str] | None = None,
    max_hashes: int = 50,
    max_ips: int = 30,
    max_urls: int = 30,
) -> dict:
    """Run all abuse.ch checks on extracted IOCs.

    Returns a summary dict with results from all four services.
    """
    summary: dict = {
        "malwarebazaar": [],
        "threatfox": [],
        "urlhaus": [],
        "yaraify": [],
    }

    # MalwareBazaar hash checks
    for i, (sha256, file_path) in enumerate(hashes[:max_hashes]):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        result = await check_malwarebazaar(sha256)
        result.file_path = file_path
        if result.found:
            summary["malwarebazaar"].append(result)

    # ThreatFox checks on hashes
    for i, (sha256, _) in enumerate(hashes[:max_hashes]):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        results = await check_threatfox(sha256, "sha256_hash")
        summary["threatfox"].extend(results)

    # ThreatFox checks on IPs
    for i, ip in enumerate((ips or [])[:max_ips]):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        results = await check_threatfox(ip, "ip:port")
        summary["threatfox"].extend(results)

    # URLhaus checks
    for i, url in enumerate((urls or [])[:max_urls]):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        result = await check_urlhaus(url)
        if result.found:
            summary["urlhaus"].append(result)

    # YARAify checks on hashes
    for i, (sha256, file_path) in enumerate(hashes[:max_hashes]):
        if i > 0:
            await asyncio.sleep(BATCH_DELAY)
        result = await check_yaraify(sha256)
        result.file_path = file_path
        if result.found:
            summary["yaraify"].append(result)

    return summary
