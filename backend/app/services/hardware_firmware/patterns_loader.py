"""Data-driven firmware filename classifier.

Loads two YAML files once at import:

* ``data/vendor_prefixes.yaml`` — canonical vendor names, display strings,
  and aliases.  Provides :data:`VENDORS` and :data:`VENDOR_DISPLAY` for UI
  lookups and :func:`resolve_vendor`.
* ``data/firmware_patterns.yaml`` — ordered, first-match-wins list of
  filename regexes mapped to (vendor, product, category, confidence, source,
  format).  See :func:`match`.

The loaders are tolerant — on YAML parse errors or missing files we log a
warning and return empty tables rather than crashing the whole import.  Any
regex that fails to compile is skipped (logged) so one bad entry cannot
break classification for all other patterns.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_DATA_DIR = Path(__file__).parent / "data"
_VENDOR_YAML = _DATA_DIR / "vendor_prefixes.yaml"
_PATTERNS_YAML = _DATA_DIR / "firmware_patterns.yaml"

# Canonical vendor prefixes Wairz ships with — classifier.py reads this set
# (via the legacy ``VENDORS`` import) to gate downstream normalization.  The
# loader always seeds this fallback so classification keeps working even if
# the YAML file goes missing.
_CORE_VENDORS: frozenset[str] = frozenset(
    {
        "qualcomm",
        "mediatek",
        "samsung",
        "broadcom",
        "nvidia",
        "imagination",
        "arm",
        "apple",
        "cypress",
        "unisoc",
        "hisilicon",
        "intel",
        "realtek",
        "unknown",
    }
)


@dataclass
class PatternMatch:
    """Result of matching a filename against firmware_patterns.yaml.

    ``format`` defaults to ``raw_bin`` so callers can always pass it to the
    ``Classification`` dataclass without None-checking.
    """

    vendor: str
    category: str
    product: str | None
    confidence: str  # high | medium | low
    source: str | None = None
    format: str = "raw_bin"


def _safe_load(path: Path) -> dict:
    """Load a YAML file, returning {} on any error (logged)."""
    if not path.is_file():
        logger.warning("patterns_loader: YAML not found at %s", path)
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:  # pragma: no cover — exercised in tests
        logger.warning("patterns_loader: failed to parse %s: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning(
            "patterns_loader: %s top-level must be a mapping, got %s",
            path,
            type(data).__name__,
        )
        return {}
    return data


def _load_vendors() -> tuple[frozenset[str], dict[str, str], dict[str, str]]:
    """Return (canonical prefixes, alias→canonical, canonical→display).

    Falls back to the hard-coded ``_CORE_VENDORS`` when the YAML is missing
    so the rest of the codebase keeps working.
    """
    data = _safe_load(_VENDOR_YAML)
    entries = data.get("vendors") or []
    if not isinstance(entries, list):
        logger.warning("patterns_loader: 'vendors' must be a list in %s", _VENDOR_YAML)
        entries = []

    canonical: set[str] = set(_CORE_VENDORS)
    display: dict[str, str] = {}
    alias_map: dict[str, str] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        prefix = str(entry.get("prefix") or "").strip().lower()
        if not prefix:
            continue
        canonical.add(prefix)
        disp = entry.get("display")
        if isinstance(disp, str) and disp.strip():
            display[prefix] = disp.strip()
        aliases = entry.get("aliases") or []
        if isinstance(aliases, list):
            for a in aliases:
                a_str = str(a or "").strip().lower()
                if a_str and a_str != prefix:
                    alias_map[a_str] = prefix

    # Seed display for the core vendors if not overridden by the YAML.
    display.setdefault("qualcomm", "Qualcomm Technologies, Inc.")
    display.setdefault("mediatek", "MediaTek Inc.")
    display.setdefault("unknown", "Unknown Vendor")

    return frozenset(canonical), alias_map, display


def _compile_patterns() -> list[tuple[re.Pattern[str], PatternMatch]]:
    """Load and compile firmware_patterns.yaml → [(regex, match-template)]."""
    data = _safe_load(_PATTERNS_YAML)
    raw = data.get("patterns") or []
    if not isinstance(raw, list):
        logger.warning("patterns_loader: 'patterns' must be a list in %s", _PATTERNS_YAML)
        return []

    compiled: list[tuple[re.Pattern[str], PatternMatch]] = []
    skipped = 0
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            skipped += 1
            continue
        pat = entry.get("pattern")
        vendor = entry.get("vendor")
        category = entry.get("category")
        if not (isinstance(pat, str) and isinstance(vendor, str) and isinstance(category, str)):
            logger.warning(
                "patterns_loader: entry #%d missing required field (pattern/vendor/category)", idx
            )
            skipped += 1
            continue
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error as exc:
            logger.warning(
                "patterns_loader: entry #%d pattern %r failed to compile: %s",
                idx,
                pat,
                exc,
            )
            skipped += 1
            continue

        confidence = str(entry.get("confidence") or "medium").strip().lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"

        fmt = entry.get("format")
        fmt_str = str(fmt).strip() if isinstance(fmt, str) and fmt.strip() else "raw_bin"

        product = entry.get("product")
        product_str = str(product).strip() if isinstance(product, str) and product.strip() else None

        source = entry.get("source")
        source_str = str(source).strip() if isinstance(source, str) and source.strip() else None

        compiled.append(
            (
                rx,
                PatternMatch(
                    vendor=vendor.strip().lower(),
                    category=category.strip().lower(),
                    product=product_str,
                    confidence=confidence,
                    source=source_str,
                    format=fmt_str,
                ),
            )
        )

    if skipped:
        logger.info(
            "patterns_loader: loaded %d patterns (%d skipped due to errors)",
            len(compiled),
            skipped,
        )
    else:
        logger.info("patterns_loader: loaded %d firmware patterns", len(compiled))
    return compiled


# ---------------------------------------------------------------------------
# Module-level tables (loaded once at import time).
# ---------------------------------------------------------------------------
VENDORS, _VENDOR_ALIASES, VENDOR_DISPLAY = _load_vendors()
_PATTERNS: list[tuple[re.Pattern[str], PatternMatch]] = _compile_patterns()


def resolve_vendor(name: str | None) -> str:
    """Canonicalise a vendor token via the alias map.

    Returns the input lowercased if no alias match is found — callers can
    then check ``name in VENDORS`` themselves.  An empty/None input returns
    ``"unknown"``.
    """
    if not name:
        return "unknown"
    key = name.strip().lower()
    return _VENDOR_ALIASES.get(key, key)


def match(path: str) -> PatternMatch | None:
    """Return the first PatternMatch whose regex matches the basename.

    The matcher is case-insensitive (regexes compiled with ``re.IGNORECASE``)
    and operates on ``os.path.basename(path)`` — full-path matching is *not*
    supported to keep YAML patterns portable across extraction roots.
    """
    if not path:
        return None
    # basename without importing os (cheap split is fine and keeps this
    # module importable before os in some sandbox scenarios).
    base = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not base:
        return None
    for rx, tmpl in _PATTERNS:
        if rx.search(base):
            return tmpl
    return None


__all__ = [
    "PatternMatch",
    "VENDORS",
    "VENDOR_DISPLAY",
    "match",
    "resolve_vendor",
]
