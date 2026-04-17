---
title: "Data: Add CHECK Constraints, Unique Constraints, Missing Indexes, Relationship Back-Pop"
status: pending
priority: high
target: backend/app/models/, backend/alembic/versions/
---

## Problem

Four independent data-integrity gaps.

### I1. No DB-level CHECK constraints on enum-like columns

All are `String(20)` with only Pydantic-side validation. Any code path that bypasses Pydantic (migrations, direct SQL, MCP write) can insert garbage:
- `finding.py:34` — `severity`
- `finding.py` — `status`, `source`, `confidence`
- `sbom.py` — `resolution_status`
- `emulation_session.py` — `mode`, `status`
- `fuzzing.py` — `status`

Matches CLAUDE.md rule #9 class of bug — frontend `Record<UnionType, X>` crashes on unexpected values.

### I2. Missing unique constraints

- `firmware.sha256` has an index but no unique constraint — same firmware uploaded twice creates duplicate rows with duplicate extraction (wasted disk, confused comparison)
- `sbom_components(firmware_id, name, version, cpe)` — no uniqueness; rescan creates dupes and inflates CVE join counts

### I3. Missing indexes

- `attack_surface_entries.firmware_id` — not indexed (only composite `(project_id, firmware_id, score DESC)` exists; filtering by firmware_id alone will seq scan)
- `emulation_sessions.container_id` — cleanup path scans this

### I4. Missing `relationship()` back-population

Six models declare FK columns but no `relationship()` object, AND `Project` doesn't list them:
- `emulation_session.py`
- `emulation_preset.py`
- `uart_session.py`
- `fuzzing.py` (fuzzing_campaigns, fuzzing_crashes)
- `attack_surface.py`
- `analysis_cache.py`

Consequence: `db.delete(project)` only cascades at DB level (OK because FKs are `ON DELETE CASCADE`), but `selectinload(Project.emulation_sessions)` is impossible — forces raw queries. Missing `cascade="all, delete-orphan"` on Project side for these collections.

## Approach

### I1 — CHECK constraints

Prefer Postgres native ENUMs for new stable values; CHECK constraints for values that evolve.

Migration `add_enum_check_constraints.py`:
```python
def upgrade() -> None:
    # Finding severity
    op.create_check_constraint(
        "ck_findings_severity",
        "findings",
        "severity IN ('critical', 'high', 'medium', 'low', 'info')"
    )
    # Finding status
    op.create_check_constraint(
        "ck_findings_status",
        "findings",
        "status IN ('open', 'investigating', 'resolved', 'false_positive', 'wont_fix')"
    )
    # Source — list ALL current source values before adding; grep for 'source = ' in services
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        "source IN ('manual', 'security_audit', 'yara_scan', 'vulhunt_scan', 'attack_surface', 'apk-manifest', 'apk-bytecode', 'apk-sast', 'clamav', 'virustotal', 'abusech', 'cwe_checker')"
    )
    # Finding confidence
    op.create_check_constraint(
        "ck_findings_confidence",
        "findings",
        "confidence IS NULL OR confidence IN ('high', 'medium', 'low')"
    )
    # SBOM resolution
    op.create_check_constraint(
        "ck_sbom_vulns_resolution_status",
        "sbom_vulnerabilities",
        "resolution_status IN ('unresolved', 'affected', 'not_affected', 'fixed', 'false_positive')"
    )
    # Emulation/fuzzing status
    op.create_check_constraint(
        "ck_emulation_sessions_status",
        "emulation_sessions",
        "status IN ('starting', 'running', 'stopped', 'error')"
    )
    op.create_check_constraint(
        "ck_fuzzing_campaigns_status",
        "fuzzing_campaigns",
        "status IN ('pending', 'running', 'stopped', 'completed', 'failed')"
    )
```

**IMPORTANT:** Before running, audit current data:
```sql
SELECT severity, COUNT(*) FROM findings GROUP BY severity;
-- Clean up any non-enum rows before adding the constraint
```

### I2 — Unique constraints

```python
# Migration add_unique_constraints.py
op.create_unique_constraint(
    "uq_firmware_project_sha256",
    "firmware",
    ["project_id", "sha256"]
)
op.create_unique_constraint(
    "uq_sbom_components_firmware_name_version_cpe",
    "sbom_components",
    ["firmware_id", "name", "version", "cpe"]
)
```

Handle duplicates first:
```sql
-- Remove duplicate firmware rows (keep oldest)
DELETE FROM firmware a USING firmware b
WHERE a.ctid > b.ctid AND a.project_id = b.project_id AND a.sha256 = b.sha256;
-- Similar for sbom_components
```

### I3 — Missing indexes

```python
op.create_index(
    "ix_attack_surface_firmware_id",
    "attack_surface_entries",
    ["firmware_id"]
)
op.create_index(
    "ix_emulation_sessions_container_id",
    "emulation_sessions",
    ["container_id"]
)
```

### I4 — Relationship back-pop

In `backend/app/models/project.py`, add to `Project`:

```python
emulation_sessions: Mapped[list["EmulationSession"]] = relationship(
    back_populates="project",
    cascade="all, delete-orphan",
)
emulation_presets: Mapped[list["EmulationPreset"]] = relationship(
    back_populates="project",
    cascade="all, delete-orphan",
)
uart_sessions: Mapped[list["UartSession"]] = relationship(
    back_populates="project",
    cascade="all, delete-orphan",
)
fuzzing_campaigns: Mapped[list["FuzzingCampaign"]] = relationship(
    back_populates="project",
    cascade="all, delete-orphan",
)
attack_surface_entries: Mapped[list["AttackSurfaceEntry"]] = relationship(
    back_populates="project",
    cascade="all, delete-orphan",
)
```

And in each child model, add the back-ref:
```python
project: Mapped["Project"] = relationship(back_populates="emulation_sessions")
```

## Files

- `backend/alembic/versions/{new}_add_enum_check_constraints.py` (new)
- `backend/alembic/versions/{new}_add_unique_constraints.py` (new)
- `backend/alembic/versions/{new}_add_missing_indexes_2.py` (new)
- `backend/app/models/project.py` (add 5 relationships)
- `backend/app/models/emulation_session.py` (add back-ref)
- `backend/app/models/emulation_preset.py`
- `backend/app/models/uart_session.py`
- `backend/app/models/fuzzing.py`
- `backend/app/models/attack_surface.py`
- `backend/app/models/analysis_cache.py` (add back-ref to Firmware)

## Acceptance Criteria

- [ ] All CHECK constraints created; migration upgrade + downgrade tested on a fresh DB
- [ ] Inserting `severity='bogus'` via raw SQL fails
- [ ] Attempting to upload the same firmware twice (same sha256) to the same project returns 409 (router should catch `IntegrityError` and surface cleanly)
- [ ] `SELECT relname FROM pg_index WHERE indrelid = 'attack_surface_entries'::regclass` shows separate `firmware_id` index
- [ ] Can call `selectinload(Project.emulation_sessions)` in a service without error
- [ ] `db.delete(project)` cascades emulation_sessions via ORM (verify via event listener or test)

## Risks

- Adding CHECK constraints to live DBs requires data cleanup first — do the audit SELECT queries in a migration pre-check
- `ON DELETE CASCADE` already exists at DB level; adding ORM cascade duplicates the behavior, which is fine
- Enum values may drift — plan to revisit this migration when new sources/statuses are added

## References

- Data review H1, H3, H5, H6, H9
