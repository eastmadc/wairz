# Anti-patterns: CRA Compliance Report Generator

> Extracted: 2026-04-09
> Campaign: .planning/fleet/session-cra-compliance.md

## Failed Patterns

### 1. SQLAlchemy back_populates Without Reciprocal Relationship
- **What was done:** CraAssessment model defined `project: Mapped["Project"] = relationship(back_populates="cra_assessments")` but the Project model has no `cra_assessments` relationship attribute.
- **Failure mode:** `sqlalchemy.exc.InvalidRequestError: Mapper 'Mapper[Project(projects)]' has no property 'cra_assessments'` — all mappers fail to initialize, entire app crashes on first request.
- **Evidence:** Docker logs after first deploy showed mapper initialization failure. Health endpoint worked (no DB) but all API endpoints returned 500.
- **How to avoid:** When adding a new model with FK to an existing model, either (a) add the reciprocal relationship to the parent model, or (b) use `relationship()` without `back_populates`. Option (b) is simpler when you don't need parent→child navigation.

### 2. Mixing Timezone-Aware and Naive Datetimes with asyncpg
- **What was done:** Service used `datetime.now(timezone.utc)` (timezone-aware) for `assessed_at` field, but the DB column was created as `sa.DateTime()` (naive, maps to `TIMESTAMP WITHOUT TIME ZONE`).
- **Failure mode:** `asyncpg.exceptions.DataError: can't subtract offset-naive and offset-aware datetimes` — auto-populate endpoint returned 500.
- **Evidence:** First auto-populate API call after deploy failed with asyncpg DataError. Create endpoint worked because it doesn't set `assessed_at`.
- **How to avoid:** Check existing migration patterns for DateTime usage. In this codebase, most tables use `sa.DateTime()` (naive). Use `datetime.utcnow()` for these columns, not `datetime.now(timezone.utc)`. If timezone-aware is needed, use `sa.DateTime(timezone=True)` in the migration.

### 3. Agent-Generated Export Key Mismatch
- **What was done:** Smoke test script assumed export JSON would use keys `parts.part_1.requirements` but the service used `part1_security_requirements.requirements`.
- **Failure mode:** Export appeared empty in test output, causing false alarm. The actual export was correct — the test was wrong.
- **Evidence:** Re-running with correct keys showed 13 Part 1 + 7 Part 2 requirements properly exported.
- **How to avoid:** When writing smoke tests for agent-generated code, read the actual service method first to verify response structure rather than assuming key names.
