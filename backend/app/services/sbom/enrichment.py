"""Post-scan CPE enrichment for SBOM components.

Runs after all detection strategies have populated the
:class:`ComponentStore`.  Fills in CPE identifiers for components that
don't have one via a 5-step pipeline:

1. Direct ``CPE_VENDOR_MAP`` lookup (exact + normalized name).
2. Local fuzzy matching (strip ``lib`` prefix, normalize hyphens /
   underscores).
3. NVD CPE dictionary fuzzy matching (rapidfuzz against 1M+ official
   CPEs).
4. Kernel-module inheritance (inherit the ``linux_kernel`` CPE).
5. Android APK ``targetSdkVersion`` → Android-version CPE.

Each enriched component gets metadata tracking:

- ``enrichment_source``: how the CPE was determined.
- ``cpe_confidence``: 0.0-1.0 confidence score.

Previously ``SbomService._enrich_cpes / _find_kernel_version /
_is_kernel_module / _is_android_component / _fuzzy_cpe_lookup`` +
``_ANDROID_API_TO_VERSION`` in the ``sbom_service.py`` monolith.
"""

from __future__ import annotations

import logging
import re

from app.services.sbom.constants import CPE_VENDOR_MAP, IdentifiedComponent
from app.services.sbom.normalization import ComponentStore
from app.services.sbom.purl import build_cpe, build_os_cpe

logger = logging.getLogger(__name__)

# Android API level to version mapping for CPE enrichment
ANDROID_API_TO_VERSION: dict[int, str] = {
    21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1",
    26: "8.0", 27: "8.1", 28: "9", 29: "10", 30: "11",
    31: "12", 32: "12L", 33: "13", 34: "14", 35: "15",
}


def find_kernel_version(store: ComponentStore) -> str | None:
    """Look up the kernel version from already-identified components."""
    for comp in store.values():
        if comp.name == "linux-kernel" and comp.version:
            return comp.version
    return None


def is_kernel_module(comp: IdentifiedComponent) -> bool:
    """Return True if the component is a kernel module."""
    if comp.type == "kernel-module":
        return True
    if "kernel_module" in comp.metadata.get("type", ""):
        return True
    if comp.detection_source in ("android_kernel_module", "kernel_module"):
        return True
    # Check file paths for .ko extension or /modules/ directory
    for fp in comp.file_paths:
        if fp.endswith(".ko") or "/modules/" in fp:
            return True
    return False


def is_android_component(comp: IdentifiedComponent) -> bool:
    """Return True if the component looks like an Android APK/app."""
    if comp.detection_source in ("android_apk", "android_init_service"):
        return True
    if comp.metadata.get("source") == "android":
        return True
    return False


def fuzzy_cpe_lookup(
    name: str,
    version: str,
    comp_type: str,
) -> str | None:
    """Attempt fuzzy matching against CPE_VENDOR_MAP.

    Tries multiple normalization strategies:

    - Strip 'lib' prefix (``libfoo`` → ``foo``).
    - Normalize hyphens <-> underscores.
    - Try common suffixes (``libfoo-dev`` → ``libfoo``).
    - Try with/without version suffix in name (``openssl-1.1`` → ``openssl``).
    """
    candidates: list[str] = []
    name_lower = name.lower().strip()

    # Strip lib prefix
    if name_lower.startswith("lib"):
        candidates.append(name_lower[3:])

    # Normalize hyphens <-> underscores
    candidates.append(name_lower.replace("-", "_"))
    candidates.append(name_lower.replace("_", "-"))
    if name_lower.startswith("lib"):
        candidates.append(name_lower[3:].replace("-", "_"))
        candidates.append(name_lower[3:].replace("_", "-"))

    # Strip common suffixes
    for suffix in ("-dev", "-dbg", "-bin", "-utils", "-tools",
                   "-client", "-server", "-common", "-core"):
        if name_lower.endswith(suffix):
            base = name_lower[:-len(suffix)]
            candidates.append(base)
            if base.startswith("lib"):
                candidates.append(base[3:])

    # Strip version suffix from name (e.g. "openssl1.1" -> "openssl")
    stripped = re.sub(r"[\d.]+$", "", name_lower).rstrip("-_")
    if stripped and stripped != name_lower:
        candidates.append(stripped)
        if stripped.startswith("lib"):
            candidates.append(stripped[3:])

    # Deduplicate while preserving order
    seen: set[str] = {name_lower}
    unique_candidates: list[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    for candidate in unique_candidates:
        vendor_product = CPE_VENDOR_MAP.get(candidate)
        if vendor_product:
            part = "o" if comp_type == "operating-system" else "a"
            return build_cpe(
                vendor_product[0], vendor_product[1], version, part=part
            )

    return None


def enrich_cpes(store: ComponentStore) -> None:
    """Post-processing pass to fill in missing CPEs.

    Runs after all scanning strategies have completed.  See module
    docstring for the 5-step enrichment pipeline.
    """
    from app.services.cpe_dictionary_service import (
        CONFIDENCE_AUTO,
        get_cpe_dictionary_service,
    )

    # Find the kernel version for module inheritance
    kernel_version = find_kernel_version(store)

    # Try to get the CPE dictionary (non-blocking, may not be loaded yet)
    cpe_dict = get_cpe_dictionary_service()

    stats: dict[str, int] = {
        "direct_map": 0,
        "local_fuzzy": 0,
        "nvd_fuzzy": 0,
        "kernel_inherit": 0,
        "android_sdk": 0,
        "already_had_cpe": 0,
        "no_match": 0,
    }

    for _key, comp in list(store.items()):
        if comp.cpe:
            stats["already_had_cpe"] += 1
            # Tag existing CPEs with source if not already tagged
            if "enrichment_source" not in comp.metadata:
                comp.metadata["enrichment_source"] = "scanner"
                comp.metadata["cpe_confidence"] = 0.9
            continue

        enriched = False

        # --- 1. Direct CPE_VENDOR_MAP lookup ---
        name_lower = comp.name.lower()
        vendor_product = CPE_VENDOR_MAP.get(name_lower)
        if vendor_product and comp.version:
            part = "o" if comp.type == "operating-system" else "a"
            comp.cpe = build_cpe(
                vendor_product[0], vendor_product[1], comp.version, part=part
            )
            comp.supplier = comp.supplier or vendor_product[0]
            comp.metadata["enrichment_source"] = "exact_match"
            comp.metadata["cpe_confidence"] = 0.95
            stats["direct_map"] += 1
            enriched = True

        # --- 2. Local fuzzy matching (name normalization against CPE_VENDOR_MAP) ---
        if not enriched and comp.version:
            fuzzy_cpe = fuzzy_cpe_lookup(comp.name, comp.version, comp.type)
            if fuzzy_cpe:
                comp.cpe = fuzzy_cpe
                comp.metadata["enrichment_source"] = "local_fuzzy"
                comp.metadata["cpe_confidence"] = 0.85
                stats["local_fuzzy"] += 1
                enriched = True

        # --- 3. NVD CPE dictionary fuzzy matching ---
        if not enriched and comp.version and cpe_dict._index is not None:
            matches = cpe_dict.lookup_fuzzy(
                comp.name, comp.version, limit=3
            )
            if matches and matches[0].confidence >= CONFIDENCE_AUTO:
                best = matches[0]
                comp.cpe = best.cpe23
                comp.supplier = comp.supplier or best.vendor
                comp.metadata["enrichment_source"] = best.source
                comp.metadata["cpe_confidence"] = round(best.confidence, 2)
                stats["nvd_fuzzy"] += 1
                enriched = True

        # --- 4. Kernel module inheritance ---
        if not enriched and kernel_version and is_kernel_module(comp):
            comp.cpe = build_os_cpe(
                "linux", "linux_kernel", kernel_version
            )
            comp.metadata["cpe_inherited_from"] = "linux-kernel"
            comp.metadata["enrichment_source"] = "inherited"
            comp.metadata["cpe_confidence"] = 0.80
            stats["kernel_inherit"] += 1
            enriched = True

        # --- 5. Android APK targetSdkVersion ---
        if not enriched and is_android_component(comp):
            sdk_version = comp.metadata.get("targetSdkVersion")
            if sdk_version:
                try:
                    api_level = int(sdk_version)
                    android_ver = ANDROID_API_TO_VERSION.get(api_level)
                    if android_ver:
                        comp.cpe = build_os_cpe(
                            "google", "android", android_ver
                        )
                        comp.metadata["enrichment_source"] = "android_sdk"
                        comp.metadata["cpe_confidence"] = 0.90
                        stats["android_sdk"] += 1
                        enriched = True
                except (ValueError, TypeError):
                    pass

        # Promote generic detections validated by CPE enrichment
        if (
            enriched
            and comp.detection_confidence == "low"
            and comp.metadata.get("detection_method") == "generic_filename_match"
        ):
            comp.detection_confidence = "medium"
            comp.metadata["generic_detection_validated"] = True
            logger.info(
                "Promoted generic detection %s %s to medium (CPE validated)",
                comp.name, comp.version,
            )

        if not enriched:
            comp.metadata["enrichment_source"] = "none"
            comp.metadata["cpe_confidence"] = 0.0
            stats["no_match"] += 1

    total_enriched = (
        stats["direct_map"] + stats["local_fuzzy"] + stats["nvd_fuzzy"]
        + stats["kernel_inherit"] + stats["android_sdk"]
    )
    logger.info(
        "CPE enrichment complete: %d components enriched "
        "(direct_map=%d, local_fuzzy=%d, nvd_fuzzy=%d, "
        "kernel_inherit=%d, android_sdk=%d), "
        "%d already had CPE, %d unmatched",
        total_enriched,
        stats["direct_map"],
        stats["local_fuzzy"],
        stats["nvd_fuzzy"],
        stats["kernel_inherit"],
        stats["android_sdk"],
        stats["already_had_cpe"],
        stats["no_match"],
    )
