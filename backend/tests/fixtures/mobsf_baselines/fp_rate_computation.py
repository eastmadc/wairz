#!/usr/bin/env python3
"""Multi-phase false-positive rate computation for APK security scanning.

Compares collected findings against ground-truth annotations for each APK,
computes per-phase (manifest, bytecode, SAST) and aggregate FP rates, and
outputs a summary table with pass/fail thresholds.

Usage (from backend/ directory):
    python -m tests.fixtures.mobsf_baselines.fp_rate_computation

    # With actual scan results JSON:
    python -m tests.fixtures.mobsf_baselines.fp_rate_computation \\
        --manifest-results diva_manifest.json \\
        --bytecode-results diva_bytecode.json \\
        --sast-results diva_sast.json

Each phase has independent ground-truth baselines and FP thresholds.
The aggregate FP rate is the weighted average across all phases.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent

# Default FP rate threshold (20% as specified in evaluation principles)
DEFAULT_MAX_FP_RATE = 0.20

# Phase names for consistent keying
PHASE_MANIFEST = "manifest"
PHASE_BYTECODE = "bytecode"
PHASE_SAST = "sast"

ALL_PHASES = [PHASE_MANIFEST, PHASE_BYTECODE, PHASE_SAST]

# Severity ordering for priority comparisons
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PhaseResult:
    """Result of FP rate computation for a single scan phase."""

    phase: str
    apk_name: str
    total_findings: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0
    # Detailed classification
    matched_ids: list[str] = field(default_factory=list)
    false_positive_ids: list[str] = field(default_factory=list)
    false_negative_ids: list[str] = field(default_factory=list)
    expected_absent_violations: list[dict[str, str]] = field(default_factory=list)
    # Metrics
    fp_rate: float = 0.0
    detection_rate: float = 0.0
    fp_tolerance: int = 0
    max_fp_rate: float = DEFAULT_MAX_FP_RATE
    # Verdict
    passed: bool = False
    failure_reasons: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "PASS" if self.passed else "FAIL"


@dataclass
class AggregateResult:
    """Aggregate FP rate result across all phases for one APK."""

    apk_name: str
    phase_results: dict[str, PhaseResult] = field(default_factory=dict)
    # Aggregate metrics (weighted by finding count per phase)
    aggregate_fp_rate: float = 0.0
    aggregate_detection_rate: float = 0.0
    total_findings_all_phases: int = 0
    total_true_positives: int = 0
    total_false_positives: int = 0
    total_false_negatives: int = 0
    # Overall verdict
    all_phases_pass: bool = False
    aggregate_fp_under_threshold: bool = False
    overall_verdict: str = "FAIL"


@dataclass
class MultiAPKSummary:
    """Summary across all APKs and all phases."""

    apk_results: dict[str, AggregateResult] = field(default_factory=dict)
    per_phase_aggregate: dict[str, dict[str, float]] = field(default_factory=dict)
    overall_fp_rate: float = 0.0
    overall_detection_rate: float = 0.0
    overall_verdict: str = "FAIL"


# ---------------------------------------------------------------------------
# Ground-truth baseline loaders
# ---------------------------------------------------------------------------


def load_manifest_baseline(apk_key: str) -> dict[str, Any] | None:
    """Load manifest-phase ground truth from existing MobSF baseline JSON."""
    filename_map = {
        "diva": "diva_baseline.json",
        "insecurebankv2": "insecurebankv2_baseline.json",
        "ovaa": "ovaa_baseline.json",
    }
    fname = filename_map.get(apk_key.lower())
    if not fname:
        return None
    path = _THIS_DIR / fname
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def load_phase_baseline(apk_key: str, phase: str) -> dict[str, Any] | None:
    """Load bytecode or SAST phase ground truth from baseline JSON."""
    fname = f"{apk_key.lower()}_{phase}_baseline.json"
    path = _THIS_DIR / fname
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Phase-specific comparison logic
# ---------------------------------------------------------------------------


def compute_manifest_fp_rate(
    scan_findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> PhaseResult:
    """Compute FP rate for manifest phase using existing MobSF baseline format.

    Args:
        scan_findings: List of finding dicts with at minimum ``check_id`` and
            ``severity`` keys (Wairz ManifestFinding schema).
        baseline: Loaded MobSF baseline JSON (``*_baseline.json``).

    Returns:
        PhaseResult with classified findings and metrics.
    """
    apk_name = baseline.get("_meta", {}).get("apk_name", "unknown")
    result = PhaseResult(phase=PHASE_MANIFEST, apk_name=apk_name)

    # Build lookup of expected true-positive check IDs from baseline
    expected_tp_ids: set[str] = set()
    for bf in baseline.get("mobsf_findings", []):
        expected_tp_ids.add(bf["wairz_check_id"])

    # Build expected-absent set
    expected_absent_ids: set[str] = set()
    expected_absent_reasons: dict[str, str] = {}
    for ea in baseline.get("expected_absent", []):
        cid = ea["wairz_check_id"]
        expected_absent_ids.add(cid)
        expected_absent_reasons[cid] = ea.get("reason", "")

    # Classify each scan finding
    scan_check_ids: set[str] = set()
    for finding in scan_findings:
        cid = finding.get("check_id", "")
        scan_check_ids.add(cid)

        if cid in expected_tp_ids:
            result.matched_ids.append(cid)
        elif cid in expected_absent_ids:
            result.false_positive_ids.append(cid)
            result.expected_absent_violations.append({
                "check_id": cid,
                "reason_should_be_absent": expected_absent_reasons.get(cid, ""),
            })
        else:
            # Extra finding not in baseline at all — potential FP
            result.false_positive_ids.append(cid)

    # Check for false negatives (baseline findings not detected)
    for cid in expected_tp_ids:
        if cid not in scan_check_ids:
            result.false_negative_ids.append(cid)

    # Compute metrics
    result.total_findings = len(scan_findings)
    result.true_positive_count = len(set(result.matched_ids))
    result.false_positive_count = len(set(result.false_positive_ids))
    result.false_negative_count = len(result.false_negative_ids)

    summary = baseline.get("summary", {})
    result.fp_tolerance = summary.get("false_positive_tolerance", 2)
    result.max_fp_rate = summary.get("max_fp_rate", DEFAULT_MAX_FP_RATE)

    if result.total_findings > 0:
        result.fp_rate = result.false_positive_count / result.total_findings
    else:
        result.fp_rate = 0.0

    total_expected = len(expected_tp_ids)
    if total_expected > 0:
        result.detection_rate = result.true_positive_count / total_expected
    else:
        result.detection_rate = 1.0

    # Verdict
    result.passed = True
    if result.false_negative_count > 0:
        result.passed = False
        result.failure_reasons.append(
            f"Missing {result.false_negative_count} expected finding(s): "
            f"{', '.join(sorted(result.false_negative_ids))}"
        )
    if result.false_positive_count > result.fp_tolerance:
        result.passed = False
        result.failure_reasons.append(
            f"FP count {result.false_positive_count} exceeds tolerance "
            f"{result.fp_tolerance}"
        )
    if result.fp_rate >= result.max_fp_rate:
        result.passed = False
        result.failure_reasons.append(
            f"FP rate {result.fp_rate:.1%} >= threshold {result.max_fp_rate:.0%}"
        )

    return result


def compute_bytecode_fp_rate(
    scan_findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> PhaseResult:
    """Compute FP rate for bytecode phase.

    Args:
        scan_findings: List of finding dicts with ``pattern_id`` or ``id`` key.
        baseline: Loaded bytecode baseline JSON.

    Returns:
        PhaseResult with classified findings and metrics.
    """
    apk_name = baseline.get("_meta", {}).get("apk_name", "unknown")
    result = PhaseResult(phase=PHASE_BYTECODE, apk_name=apk_name)

    # Expected true-positive pattern IDs
    expected_tp_ids: set[str] = set(
        baseline.get("true_positive_pattern_ids", [])
    )

    # Expected-absent pattern IDs
    expected_absent_ids: set[str] = set()
    expected_absent_reasons: dict[str, str] = {}
    for ea in baseline.get("expected_absent_pattern_ids", []):
        pid = ea["pattern_id"]
        expected_absent_ids.add(pid)
        expected_absent_reasons[pid] = ea.get("reason", "")

    # Classify each finding
    scan_pattern_ids: set[str] = set()
    for finding in scan_findings:
        pid = finding.get("pattern_id") or finding.get("id", "")
        scan_pattern_ids.add(pid)

        if pid in expected_tp_ids:
            result.matched_ids.append(pid)
        elif pid in expected_absent_ids:
            result.false_positive_ids.append(pid)
            result.expected_absent_violations.append({
                "pattern_id": pid,
                "reason_should_be_absent": expected_absent_reasons.get(pid, ""),
            })
        else:
            # Extra finding — potential FP
            result.false_positive_ids.append(pid)

    # False negatives
    for pid in expected_tp_ids:
        if pid not in scan_pattern_ids:
            result.false_negative_ids.append(pid)

    # Metrics
    result.total_findings = len(scan_findings)
    result.true_positive_count = len(set(result.matched_ids))
    result.false_positive_count = len(set(result.false_positive_ids))
    result.false_negative_count = len(result.false_negative_ids)

    summary = baseline.get("summary", {})
    result.fp_tolerance = summary.get("false_positive_tolerance", 3)
    result.max_fp_rate = summary.get("max_fp_rate", DEFAULT_MAX_FP_RATE)

    if result.total_findings > 0:
        result.fp_rate = result.false_positive_count / result.total_findings
    else:
        result.fp_rate = 0.0

    total_expected = len(expected_tp_ids)
    if total_expected > 0:
        result.detection_rate = result.true_positive_count / total_expected
    else:
        result.detection_rate = 1.0

    # Verdict
    result.passed = True
    if result.false_negative_count > 0:
        result.passed = False
        result.failure_reasons.append(
            f"Missing {result.false_negative_count} expected finding(s): "
            f"{', '.join(sorted(result.false_negative_ids))}"
        )
    if result.false_positive_count > result.fp_tolerance:
        result.passed = False
        result.failure_reasons.append(
            f"FP count {result.false_positive_count} exceeds tolerance "
            f"{result.fp_tolerance}"
        )
    if result.fp_rate >= result.max_fp_rate:
        result.passed = False
        result.failure_reasons.append(
            f"FP rate {result.fp_rate:.1%} >= threshold {result.max_fp_rate:.0%}"
        )

    return result


def compute_sast_fp_rate(
    scan_findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> PhaseResult:
    """Compute FP rate for SAST (jadx+mobsfscan) phase.

    Args:
        scan_findings: List of finding dicts with ``rule_id`` or ``rule`` key.
        baseline: Loaded SAST baseline JSON.

    Returns:
        PhaseResult with classified findings and metrics.
    """
    apk_name = baseline.get("_meta", {}).get("apk_name", "unknown")
    result = PhaseResult(phase=PHASE_SAST, apk_name=apk_name)

    # Expected true-positive rule IDs
    expected_tp_ids: set[str] = set(
        baseline.get("true_positive_rule_ids", [])
    )

    # Expected-absent rule IDs
    expected_absent_ids: set[str] = set()
    expected_absent_reasons: dict[str, str] = {}
    for ea in baseline.get("expected_absent_rule_ids", []):
        rid = ea["rule_id"]
        expected_absent_ids.add(rid)
        expected_absent_reasons[rid] = ea.get("reason", "")

    # Classify each finding
    scan_rule_ids: set[str] = set()
    for finding in scan_findings:
        rid = finding.get("rule_id") or finding.get("rule", "")
        scan_rule_ids.add(rid)

        if rid in expected_tp_ids:
            result.matched_ids.append(rid)
        elif rid in expected_absent_ids:
            result.false_positive_ids.append(rid)
            result.expected_absent_violations.append({
                "rule_id": rid,
                "reason_should_be_absent": expected_absent_reasons.get(rid, ""),
            })
        else:
            # Extra finding — potential FP
            result.false_positive_ids.append(rid)

    # False negatives
    for rid in expected_tp_ids:
        if rid not in scan_rule_ids:
            result.false_negative_ids.append(rid)

    # Metrics
    result.total_findings = len(scan_findings)
    result.true_positive_count = len(set(result.matched_ids))
    result.false_positive_count = len(set(result.false_positive_ids))
    result.false_negative_count = len(result.false_negative_ids)

    summary = baseline.get("summary", {})
    result.fp_tolerance = summary.get("false_positive_tolerance", 3)
    result.max_fp_rate = summary.get("max_fp_rate", DEFAULT_MAX_FP_RATE)

    if result.total_findings > 0:
        result.fp_rate = result.false_positive_count / result.total_findings
    else:
        result.fp_rate = 0.0

    total_expected = len(expected_tp_ids)
    if total_expected > 0:
        result.detection_rate = result.true_positive_count / total_expected
    else:
        result.detection_rate = 1.0

    # Verdict
    result.passed = True
    if result.false_negative_count > 0:
        result.passed = False
        result.failure_reasons.append(
            f"Missing {result.false_negative_count} expected finding(s): "
            f"{', '.join(sorted(result.false_negative_ids))}"
        )
    if result.false_positive_count > result.fp_tolerance:
        result.passed = False
        result.failure_reasons.append(
            f"FP count {result.false_positive_count} exceeds tolerance "
            f"{result.fp_tolerance}"
        )
    if result.fp_rate >= result.max_fp_rate:
        result.passed = False
        result.failure_reasons.append(
            f"FP rate {result.fp_rate:.1%} >= threshold {result.max_fp_rate:.0%}"
        )

    return result


# ---------------------------------------------------------------------------
# Phase dispatcher
# ---------------------------------------------------------------------------

# Map of phase -> comparison function
_PHASE_COMPARATORS = {
    PHASE_MANIFEST: compute_manifest_fp_rate,
    PHASE_BYTECODE: compute_bytecode_fp_rate,
    PHASE_SAST: compute_sast_fp_rate,
}


def compute_phase_fp_rate(
    phase: str,
    scan_findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> PhaseResult:
    """Dispatch to the correct phase-specific FP rate computation.

    Args:
        phase: One of ``PHASE_MANIFEST``, ``PHASE_BYTECODE``, ``PHASE_SAST``.
        scan_findings: List of finding dicts from the scanner.
        baseline: Loaded ground-truth baseline JSON for this phase.

    Returns:
        PhaseResult with classified findings and metrics.

    Raises:
        ValueError: If phase is not recognized.
    """
    comparator = _PHASE_COMPARATORS.get(phase)
    if comparator is None:
        raise ValueError(
            f"Unknown phase '{phase}'. Must be one of: {list(_PHASE_COMPARATORS.keys())}"
        )
    return comparator(scan_findings, baseline)


# ---------------------------------------------------------------------------
# Aggregate computation
# ---------------------------------------------------------------------------


def compute_aggregate_fp_rate(
    apk_name: str,
    phase_results: dict[str, PhaseResult],
    max_aggregate_fp_rate: float = DEFAULT_MAX_FP_RATE,
) -> AggregateResult:
    """Compute aggregate FP rate across all phases for a single APK.

    Uses weighted average (weighted by total findings per phase) to avoid
    phases with fewer findings dominating the aggregate rate.

    Args:
        apk_name: Display name for the APK.
        phase_results: Dict mapping phase name to PhaseResult.
        max_aggregate_fp_rate: Maximum acceptable aggregate FP rate.

    Returns:
        AggregateResult with per-phase and aggregate metrics.
    """
    result = AggregateResult(apk_name=apk_name, phase_results=phase_results)

    total_findings = 0
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_expected = 0

    for pr in phase_results.values():
        total_findings += pr.total_findings
        total_tp += pr.true_positive_count
        total_fp += pr.false_positive_count
        total_fn += pr.false_negative_count
        # For detection rate: sum expected TP counts
        total_expected += pr.true_positive_count + pr.false_negative_count

    result.total_findings_all_phases = total_findings
    result.total_true_positives = total_tp
    result.total_false_positives = total_fp
    result.total_false_negatives = total_fn

    # Weighted aggregate FP rate
    if total_findings > 0:
        result.aggregate_fp_rate = total_fp / total_findings
    else:
        result.aggregate_fp_rate = 0.0

    # Aggregate detection rate
    if total_expected > 0:
        result.aggregate_detection_rate = total_tp / total_expected
    else:
        result.aggregate_detection_rate = 1.0

    # Verdicts
    result.all_phases_pass = all(pr.passed for pr in phase_results.values())
    result.aggregate_fp_under_threshold = (
        result.aggregate_fp_rate < max_aggregate_fp_rate
    )
    result.overall_verdict = (
        "PASS"
        if result.all_phases_pass and result.aggregate_fp_under_threshold
        else "FAIL"
    )

    return result


def compute_multi_apk_summary(
    apk_results: dict[str, AggregateResult],
) -> MultiAPKSummary:
    """Compute summary across all APKs and all phases.

    Args:
        apk_results: Dict mapping APK key to AggregateResult.

    Returns:
        MultiAPKSummary with cross-APK phase aggregates.
    """
    summary = MultiAPKSummary(apk_results=apk_results)

    # Per-phase aggregates across APKs
    for phase in ALL_PHASES:
        phase_total_findings = 0
        phase_total_fp = 0
        phase_total_tp = 0
        phase_total_expected = 0

        for agg in apk_results.values():
            pr = agg.phase_results.get(phase)
            if pr:
                phase_total_findings += pr.total_findings
                phase_total_fp += pr.false_positive_count
                phase_total_tp += pr.true_positive_count
                phase_total_expected += (
                    pr.true_positive_count + pr.false_negative_count
                )

        phase_fp_rate = (
            phase_total_fp / phase_total_findings
            if phase_total_findings > 0
            else 0.0
        )
        phase_detection_rate = (
            phase_total_tp / phase_total_expected
            if phase_total_expected > 0
            else 1.0
        )
        summary.per_phase_aggregate[phase] = {
            "total_findings": phase_total_findings,
            "total_fp": phase_total_fp,
            "fp_rate": round(phase_fp_rate, 4),
            "detection_rate": round(phase_detection_rate, 4),
            "verdict": "PASS" if phase_fp_rate < DEFAULT_MAX_FP_RATE else "FAIL",
        }

    # Overall across all APKs and phases
    grand_total_findings = sum(
        a.total_findings_all_phases for a in apk_results.values()
    )
    grand_total_fp = sum(a.total_false_positives for a in apk_results.values())
    grand_total_tp = sum(a.total_true_positives for a in apk_results.values())
    grand_total_expected = sum(
        a.total_true_positives + a.total_false_negatives
        for a in apk_results.values()
    )

    summary.overall_fp_rate = (
        grand_total_fp / grand_total_findings
        if grand_total_findings > 0
        else 0.0
    )
    summary.overall_detection_rate = (
        grand_total_tp / grand_total_expected
        if grand_total_expected > 0
        else 1.0
    )
    summary.overall_verdict = (
        "PASS"
        if all(a.overall_verdict == "PASS" for a in apk_results.values())
        else "FAIL"
    )

    return summary


# ---------------------------------------------------------------------------
# Summary table formatting
# ---------------------------------------------------------------------------


def format_phase_result_row(pr: PhaseResult) -> str:
    """Format a single PhaseResult as a table row."""
    return (
        f"| {pr.phase:<10} | {pr.apk_name:<20} | "
        f"{pr.total_findings:>5} | {pr.true_positive_count:>4} | "
        f"{pr.false_positive_count:>4} | {pr.false_negative_count:>4} | "
        f"{pr.fp_rate:>7.1%} | {pr.detection_rate:>9.1%} | "
        f"{pr.fp_tolerance:>5} | {pr.max_fp_rate:>6.0%} | "
        f"{pr.verdict:<6} |"
    )


def format_summary_table(
    multi_summary: MultiAPKSummary,
    *,
    include_header: bool = True,
) -> str:
    """Format multi-APK, multi-phase results as an ASCII summary table.

    Args:
        multi_summary: Computed MultiAPKSummary.
        include_header: Whether to include the column header row.

    Returns:
        Formatted ASCII table string.
    """
    lines: list[str] = []

    # Header
    separator = (
        "+" + "-" * 12 + "+" + "-" * 22 + "+" + "-" * 7 + "+" + "-" * 6 + "+"
        + "-" * 6 + "+" + "-" * 6 + "+" + "-" * 9 + "+" + "-" * 11 + "+"
        + "-" * 7 + "+" + "-" * 8 + "+" + "-" * 8 + "+"
    )

    if include_header:
        lines.append(separator)
        lines.append(
            "| Phase      | APK                  | Total |  TP  |  FP  |  FN  | FP Rate | Det. Rate | Tol.  | Max FP | Result |"
        )
        lines.append(separator)

    # Per-APK, per-phase rows
    for apk_key, agg in sorted(multi_summary.apk_results.items()):
        for phase in ALL_PHASES:
            pr = agg.phase_results.get(phase)
            if pr:
                lines.append(format_phase_result_row(pr))
        # APK aggregate row
        lines.append(
            f"| {'AGGREGATE':<10} | {agg.apk_name:<20} | "
            f"{agg.total_findings_all_phases:>5} | {agg.total_true_positives:>4} | "
            f"{agg.total_false_positives:>4} | {agg.total_false_negatives:>4} | "
            f"{agg.aggregate_fp_rate:>7.1%} | {agg.aggregate_detection_rate:>9.1%} | "
            f"{'---':>5} | {DEFAULT_MAX_FP_RATE:>6.0%} | "
            f"{agg.overall_verdict:<6} |"
        )
        lines.append(separator)

    # Cross-APK phase aggregates
    lines.append("")
    lines.append("Cross-APK Phase Aggregates:")
    lines.append(
        "+------------+---------+--------+-----------+---------+"
    )
    lines.append(
        "| Phase      | Total   | FP     | FP Rate   | Verdict |"
    )
    lines.append(
        "+------------+---------+--------+-----------+---------+"
    )
    for phase in ALL_PHASES:
        pa = multi_summary.per_phase_aggregate.get(phase, {})
        lines.append(
            f"| {phase:<10} | {pa.get('total_findings', 0):>7} | "
            f"{pa.get('total_fp', 0):>6} | "
            f"{pa.get('fp_rate', 0):>8.1%} | "
            f"{pa.get('verdict', 'N/A'):<7} |"
        )
    lines.append(
        "+------------+---------+--------+-----------+---------+"
    )

    # Overall
    lines.append("")
    lines.append(
        f"Overall: FP rate={multi_summary.overall_fp_rate:.1%}, "
        f"Detection rate={multi_summary.overall_detection_rate:.1%}, "
        f"Verdict={multi_summary.overall_verdict}"
    )

    return "\n".join(lines)


def format_failure_details(multi_summary: MultiAPKSummary) -> str:
    """Format detailed failure reasons for any failing phases.

    Args:
        multi_summary: Computed MultiAPKSummary.

    Returns:
        Formatted string with failure details, or empty if all pass.
    """
    lines: list[str] = []

    for apk_key, agg in sorted(multi_summary.apk_results.items()):
        for phase in ALL_PHASES:
            pr = agg.phase_results.get(phase)
            if pr and not pr.passed:
                lines.append(f"\nFAILURE: {pr.apk_name} / {pr.phase}")
                for reason in pr.failure_reasons:
                    lines.append(f"  - {reason}")
                if pr.false_positive_ids:
                    lines.append(
                        f"  FP IDs: {', '.join(sorted(set(pr.false_positive_ids)))}"
                    )
                if pr.expected_absent_violations:
                    lines.append("  Expected-absent violations:")
                    for v in pr.expected_absent_violations:
                        vid = v.get("check_id") or v.get("pattern_id") or v.get("rule_id", "?")
                        lines.append(
                            f"    - {vid}: {v.get('reason_should_be_absent', '')}"
                        )

    return "\n".join(lines) if lines else ""


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def phase_result_to_dict(pr: PhaseResult) -> dict[str, Any]:
    """Serialize a PhaseResult to a JSON-compatible dict."""
    return {
        "phase": pr.phase,
        "apk_name": pr.apk_name,
        "total_findings": pr.total_findings,
        "true_positive_count": pr.true_positive_count,
        "false_positive_count": pr.false_positive_count,
        "false_negative_count": pr.false_negative_count,
        "matched_ids": sorted(set(pr.matched_ids)),
        "false_positive_ids": sorted(set(pr.false_positive_ids)),
        "false_negative_ids": sorted(pr.false_negative_ids),
        "expected_absent_violations": pr.expected_absent_violations,
        "metrics": {
            "fp_rate": round(pr.fp_rate, 4),
            "detection_rate": round(pr.detection_rate, 4),
            "fp_tolerance": pr.fp_tolerance,
            "max_fp_rate": pr.max_fp_rate,
        },
        "verdict": pr.verdict,
        "failure_reasons": pr.failure_reasons,
    }


def aggregate_result_to_dict(agg: AggregateResult) -> dict[str, Any]:
    """Serialize an AggregateResult to a JSON-compatible dict."""
    return {
        "apk_name": agg.apk_name,
        "phase_results": {
            phase: phase_result_to_dict(pr)
            for phase, pr in agg.phase_results.items()
        },
        "aggregate_metrics": {
            "fp_rate": round(agg.aggregate_fp_rate, 4),
            "detection_rate": round(agg.aggregate_detection_rate, 4),
            "total_findings": agg.total_findings_all_phases,
            "total_true_positives": agg.total_true_positives,
            "total_false_positives": agg.total_false_positives,
            "total_false_negatives": agg.total_false_negatives,
        },
        "all_phases_pass": agg.all_phases_pass,
        "aggregate_fp_under_threshold": agg.aggregate_fp_under_threshold,
        "overall_verdict": agg.overall_verdict,
    }


def multi_apk_summary_to_dict(summary: MultiAPKSummary) -> dict[str, Any]:
    """Serialize a MultiAPKSummary to a JSON-compatible dict."""
    return {
        "apk_results": {
            key: aggregate_result_to_dict(agg)
            for key, agg in summary.apk_results.items()
        },
        "per_phase_aggregate": summary.per_phase_aggregate,
        "overall_metrics": {
            "fp_rate": round(summary.overall_fp_rate, 4),
            "detection_rate": round(summary.overall_detection_rate, 4),
        },
        "overall_verdict": summary.overall_verdict,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run FP rate computation using baseline fixtures and mock scan results.

    When run without arguments, loads baselines and prints the summary table
    structure. With ``--json`` flag, outputs machine-readable JSON.
    """
    json_output = "--json" in sys.argv

    print("=" * 78)
    print("Multi-Phase APK Security Scan — False Positive Rate Computation")
    print("=" * 78)

    apk_keys = ["diva", "insecurebankv2", "ovaa"]
    apk_results: dict[str, AggregateResult] = {}

    for apk_key in apk_keys:
        phase_results: dict[str, PhaseResult] = {}

        # Manifest phase — use existing MobSF baseline
        manifest_baseline = load_manifest_baseline(apk_key)
        if manifest_baseline:
            # When run standalone, produce a "no findings" result to demonstrate
            # the computation structure. In real usage, scan findings are passed in.
            phase_results[PHASE_MANIFEST] = compute_manifest_fp_rate(
                scan_findings=[], baseline=manifest_baseline
            )
            apk_name = manifest_baseline["_meta"]["apk_name"]
        else:
            apk_name = apk_key

        # Bytecode phase
        bytecode_baseline = load_phase_baseline(apk_key, PHASE_BYTECODE)
        if bytecode_baseline:
            phase_results[PHASE_BYTECODE] = compute_bytecode_fp_rate(
                scan_findings=[], baseline=bytecode_baseline
            )

        # SAST phase
        sast_baseline = load_phase_baseline(apk_key, PHASE_SAST)
        if sast_baseline:
            phase_results[PHASE_SAST] = compute_sast_fp_rate(
                scan_findings=[], baseline=sast_baseline
            )

        agg = compute_aggregate_fp_rate(apk_name, phase_results)
        apk_results[apk_key] = agg

    multi_summary = compute_multi_apk_summary(apk_results)

    if json_output:
        print(json.dumps(multi_apk_summary_to_dict(multi_summary), indent=2))
    else:
        print(format_summary_table(multi_summary))
        failure_details = format_failure_details(multi_summary)
        if failure_details:
            print(failure_details)

    print()
    print("=" * 78)
    sys.exit(0 if multi_summary.overall_verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
