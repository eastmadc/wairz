"""Standalone CLI for stateless firmware security scanning.

Wraps AssessmentService to run against a firmware image or extracted
directory without requiring PostgreSQL or Redis. Uses a temporary
SQLite database via aiosqlite for the assessment lifecycle.

Usage:
    wairz-scan /path/to/firmware.bin
    wairz-scan /path/to/extracted/ --format=markdown --fail-on-critical
    wairz-scan firmware.bin --skip-phases=sbom_vulnerability,compliance
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import uuid

# ---------------------------------------------------------------------------
# Patch pydantic-settings so ``app.config.get_settings()`` never reaches for
# a real .env / DATABASE_URL during import. The CLI provides its own DB
# engine, so these values are throwaway.
# ---------------------------------------------------------------------------
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///unused.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

logger = logging.getLogger("wairz.scan")

ALL_PHASES = [
    "credential_crypto",
    "sbom_vulnerability",
    "config_filesystem",
    "malware_detection",
    "binary_protections",
    "android",
    "compliance",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wairz-scan",
        description="Scan firmware for security vulnerabilities.",
    )
    parser.add_argument(
        "firmware_path",
        help="Path to a firmware file or an already-extracted directory.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        dest="output_format",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=False,
        help="Exit with code 1 if any critical-severity finding is created.",
    )
    parser.add_argument(
        "--skip-phases",
        default="",
        help=f"Comma-separated phases to skip. Available: {', '.join(ALL_PHASES)}",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write report to this file instead of stdout.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# Temporary SQLite engine
# ---------------------------------------------------------------------------

async def _create_temp_db(db_path: str):
    """Create a temporary async SQLite engine and initialize all tables.

    SQLAlchemy models in this project use PostgreSQL-specific column types
    (JSONB, ARRAY, gen_random_uuid).  We register DDL-level compilation
    hooks so those types render as SQLite-compatible equivalents (TEXT/JSON).
    This is safe because the CLI never reads the data back through complex
    ORM queries -- it only collects the in-memory assessment result dict
    and reads simple Finding rows.
    """
    from sqlalchemy import event, JSON, Text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.postgresql import JSONB, ARRAY as PG_ARRAY
    from sqlalchemy import ARRAY as SA_ARRAY

    # Teach SQLite how to render PostgreSQL-specific types
    @compiles(JSONB, "sqlite")
    def _compile_jsonb(type_, compiler, **kw):
        return "TEXT"

    @compiles(PG_ARRAY, "sqlite")
    def _compile_pg_array(type_, compiler, **kw):
        return "TEXT"

    @compiles(SA_ARRAY, "sqlite")
    def _compile_sa_array(type_, compiler, **kw):
        return "TEXT"

    url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(url, echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _rec):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Import Base *after* env vars are set so config doesn't explode
    from app.database import Base  # noqa: E402
    # Force all models to be registered on Base.metadata
    import app.models  # noqa: F401, E402

    # SQLite cannot execute server_default=func.gen_random_uuid() or
    # other PG-specific server defaults. Strip them all before
    # create_all -- the Python-side ``default=uuid.uuid4`` still fires
    # and supplies the value.
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            if col.server_default is not None:
                col.server_default = None

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )
    return engine, session_factory


# ---------------------------------------------------------------------------
# Extract firmware if needed
# ---------------------------------------------------------------------------

def _extract_firmware(firmware_path: str, work_dir: str) -> str:
    """Extract a firmware file into *work_dir* using binwalk or unblob.

    If *firmware_path* is already a directory, return it as-is.
    Returns the path to the extraction root.
    """
    if os.path.isdir(firmware_path):
        return os.path.realpath(firmware_path)

    if not os.path.isfile(firmware_path):
        print(f"Error: {firmware_path} does not exist", file=sys.stderr)
        sys.exit(2)

    extract_dir = os.path.join(work_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    # Try unblob first (handles more formats), fall back to binwalk
    if shutil.which("unblob"):
        logger.info("Extracting with unblob: %s", firmware_path)
        import subprocess
        result = subprocess.run(
            ["unblob", "--extract-dir", extract_dir, firmware_path],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning("unblob failed (rc=%d): %s", result.returncode, result.stderr[:500])
        else:
            return extract_dir
    elif shutil.which("binwalk"):
        logger.info("Extracting with binwalk: %s", firmware_path)
        import subprocess
        result = subprocess.run(
            ["binwalk", "-e", "-C", extract_dir, firmware_path],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning("binwalk failed (rc=%d): %s", result.returncode, result.stderr[:500])
        else:
            return extract_dir

    # If no extractor available or extraction failed, treat the file's
    # parent directory as the "extracted" root -- some phases will still
    # run (binary protections on the raw file, etc.).
    logger.warning(
        "No firmware extractor available (install unblob or binwalk). "
        "Scanning the file as-is."
    )
    # Copy the raw file into extract_dir so it has something to scan
    shutil.copy2(firmware_path, extract_dir)
    return extract_dir


# ---------------------------------------------------------------------------
# Collect findings from DB
# ---------------------------------------------------------------------------

async def _collect_findings(session_factory, project_id: uuid.UUID) -> list[dict]:
    """Read all findings back from the temp DB as plain dicts."""
    from sqlalchemy import select
    from app.models.finding import Finding

    async with session_factory() as session:
        result = await session.execute(
            select(Finding).where(Finding.project_id == project_id)
        )
        findings = []
        for f in result.scalars().all():
            findings.append({
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cve_ids": f.cve_ids,
                "cwe_ids": f.cwe_ids,
                "source": f.source,
            })
        return findings


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _format_json(summary: dict, findings: list[dict]) -> str:
    output = {
        "summary": summary,
        "findings": findings,
    }
    return json.dumps(output, indent=2, default=str)


def _format_markdown(summary: dict, findings: list[dict]) -> str:
    lines = [
        "# Wairz Firmware Security Scan Report",
        "",
        "## Summary",
        "",
        f"- **Status:** {summary.get('status', 'unknown')}",
        f"- **Total findings:** {summary.get('total_findings_created', 0)}",
        f"- **Duration:** {summary.get('total_duration_s', 0)}s",
        "",
        "### Phases",
        "",
        "| Phase | Status | Findings | Duration |",
        "|-------|--------|----------|----------|",
    ]
    for phase in summary.get("phases", []):
        lines.append(
            f"| {phase['phase']} | {phase['status']} | "
            f"{phase['findings_created']} | {phase['duration_s']}s |"
        )
    lines.append("")

    # Group findings by severity
    sev_order = ["critical", "high", "medium", "low", "info"]
    by_severity: dict[str, list[dict]] = {s: [] for s in sev_order}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    lines.append("## Findings")
    lines.append("")
    for sev in sev_order:
        group = by_severity.get(sev, [])
        if not group:
            continue
        lines.append(f"### {sev.upper()} ({len(group)})")
        lines.append("")
        for f in group:
            lines.append(f"#### {f['title']}")
            if f.get("description"):
                lines.append(f"\n{f['description']}")
            if f.get("file_path"):
                loc = f["file_path"]
                if f.get("line_number"):
                    loc += f":{f['line_number']}"
                lines.append(f"\n**Location:** `{loc}`")
            if f.get("evidence"):
                lines.append(f"\n<details><summary>Evidence</summary>\n\n```\n{f['evidence']}\n```\n</details>")
            if f.get("cve_ids"):
                lines.append(f"\n**CVEs:** {', '.join(f['cve_ids'])}")
            if f.get("cwe_ids"):
                lines.append(f"\n**CWEs:** {', '.join(f['cwe_ids'])}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace) -> int:
    """Run the assessment and return the exit code."""
    work_dir = tempfile.mkdtemp(prefix="wairz-scan-")
    db_path = os.path.join(work_dir, "scan.db")

    try:
        # Extract firmware
        extracted_path = _extract_firmware(args.firmware_path, work_dir)
        logger.info("Extracted firmware root: %s", extracted_path)

        # Create temporary database
        engine, session_factory = await _create_temp_db(db_path)

        project_id = uuid.uuid4()
        firmware_id = uuid.uuid4()

        # Seed the temp DB with a project and firmware row so FK
        # constraints are satisfied.
        from app.models.project import Project
        from app.models.firmware import Firmware
        import hashlib

        # Compute a basic sha256 for the firmware record
        fw_path = args.firmware_path
        if os.path.isfile(fw_path):
            h = hashlib.sha256()
            with open(fw_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        else:
            sha256 = hashlib.sha256(fw_path.encode()).hexdigest()

        async with session_factory() as session:
            session.add(Project(
                id=project_id,
                name="ci-scan",
                status="created",
            ))
            session.add(Firmware(
                id=firmware_id,
                project_id=project_id,
                sha256=sha256,
                original_filename=os.path.basename(fw_path),
                extracted_path=extracted_path,
                storage_path=fw_path if os.path.isfile(fw_path) else None,
            ))
            await session.commit()

        # Parse skip phases
        skip_phases = [
            s.strip() for s in args.skip_phases.split(",") if s.strip()
        ]

        # Run assessment
        async with session_factory() as session:
            from app.services.assessment_service import AssessmentService

            svc = AssessmentService(
                project_id=project_id,
                firmware_id=firmware_id,
                extracted_path=extracted_path,
                db=session,
            )
            summary = await svc.run_full_assessment(skip_phases=skip_phases)
            await session.commit()

        # Collect findings
        findings = await _collect_findings(session_factory, project_id)

        # Format output
        if args.output_format == "markdown":
            report = _format_markdown(summary, findings)
        else:
            report = _format_json(summary, findings)

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            logger.info("Report written to %s", args.output)
        else:
            print(report)

        # Determine exit code
        if args.fail_on_critical:
            critical_count = sum(
                1 for f in findings if f.get("severity") == "critical"
            )
            if critical_count > 0:
                logger.info(
                    "Exiting with code 1: %d critical finding(s)", critical_count
                )
                return 1

        await engine.dispose()
        return 0

    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


def main():
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        exit_code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        exit_code = 130
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
