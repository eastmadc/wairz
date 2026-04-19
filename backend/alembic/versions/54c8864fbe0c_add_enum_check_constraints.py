"""add enum check constraints

Revision ID: 54c8864fbe0c
Revises: bb4acf97d9dd
Create Date: 2026-04-19 17:10:13.293633

I1 of intake `data-constraints-and-backpop.md`: enforce DB-level CHECK
constraints on enum-like columns that currently only have Pydantic-side
validation. Prevents bypassed code paths (migrations, direct SQL, MCP
tool writes, batch scripts) from inserting garbage values that later
surface as `Record<UnionType, X>` `undefined` crashes on the frontend
(CLAUDE.md learned rule #9) or pydantic ValidationErrors at read time.

Allowlists were derived via Rule-19 evidence-first audit. Values that
appear in LIVE data or in code paths that write to the column are
INCLUDED even if the intake proposed a narrower set. The intake's
proposed allowlists were in several cases stale relative to the
canonical Pydantic/TypeScript enums (e.g. intake said ``apk-manifest``
but code writes ``apk-manifest-scan``). See
`.planning/fleet/outputs/stream-alpha-2026-04-19-research.md` for the
per-column rationale.

Each CHECK is independently droppable in downgrade.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '54c8864fbe0c'
down_revision: Union[str, None] = 'bb4acf97d9dd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Allowlists — kept as module constants so tests can import and assert.
FINDINGS_SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")
FINDINGS_STATUS_VALUES = ("open", "confirmed", "false_positive", "fixed")
FINDINGS_CONFIDENCE_VALUES = ("high", "medium", "low")
FINDINGS_SOURCE_VALUES = (
    # Observed in live DB
    "manual",
    "security_audit",
    "yara_scan",
    "attack_surface",
    "sbom_scan",
    "hardware_firmware_graph",
    "apk-manifest-scan",
    "apk-bytecode-scan",
    "apk-mobsfscan",
    # Referenced by code paths that write findings (not yet observed)
    "cwe_checker",
    "uefi_scan",
    "clamav_scan",
    "vt_scan",
    "abusech_scan",
    "fuzzing",
    "fuzzing_scan",
)
SBOM_RESOLUTION_VALUES = ("open", "resolved", "ignored", "false_positive")
SBOM_SEVERITY_VALUES = ("critical", "high", "medium", "low", "unknown")
EMULATION_STATUS_VALUES = (
    "created", "starting", "running", "stopping", "stopped", "error",
)
FUZZING_STATUS_VALUES = ("created", "running", "stopped", "completed", "error")


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    # Findings enums
    op.create_check_constraint(
        "ck_findings_severity",
        "findings",
        _in_list_sql("severity", FINDINGS_SEVERITY_VALUES),
    )
    op.create_check_constraint(
        "ck_findings_status",
        "findings",
        _in_list_sql("status", FINDINGS_STATUS_VALUES),
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", FINDINGS_SOURCE_VALUES),
    )
    op.create_check_constraint(
        "ck_findings_confidence",
        "findings",
        f"confidence IS NULL OR {_in_list_sql('confidence', FINDINGS_CONFIDENCE_VALUES)}",
    )

    # SBOM vulnerabilities enums
    op.create_check_constraint(
        "ck_sbom_vulns_resolution_status",
        "sbom_vulnerabilities",
        _in_list_sql("resolution_status", SBOM_RESOLUTION_VALUES),
    )
    op.create_check_constraint(
        "ck_sbom_vulns_severity",
        "sbom_vulnerabilities",
        _in_list_sql("severity", SBOM_SEVERITY_VALUES),
    )

    # Emulation / fuzzing status
    op.create_check_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        _in_list_sql("status", EMULATION_STATUS_VALUES),
    )
    op.create_check_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        _in_list_sql("status", FUZZING_STATUS_VALUES),
    )


def downgrade() -> None:
    for cname, tname in (
        ("ck_findings_severity", "findings"),
        ("ck_findings_status", "findings"),
        ("ck_findings_source", "findings"),
        ("ck_findings_confidence", "findings"),
        ("ck_sbom_vulns_resolution_status", "sbom_vulnerabilities"),
        ("ck_sbom_vulns_severity", "sbom_vulnerabilities"),
        ("ck_emulation_sessions_status", "emulation_sessions"),
        ("ck_fuzzing_campaigns_status", "fuzzing_campaigns"),
    ):
        op.drop_constraint(cname, tname, type_="check")
