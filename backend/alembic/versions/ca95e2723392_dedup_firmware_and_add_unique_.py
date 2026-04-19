"""dedup firmware and add unique constraints

Revision ID: ca95e2723392
Revises: 54c8864fbe0c
Create Date: 2026-04-19 17:11:14.782459

I2 of intake `data-constraints-and-backpop.md`:

1. `firmware (project_id, sha256)` — `ix_firmware_sha256` is a non-unique
   index today. Same firmware uploaded twice to the same project creates
   duplicate rows, which wastes disk on redundant extraction and inflates
   comparison tooling. Audit at migration-authoring time found 2 (sha256)
   groups with 5 duplicate rows each in one project — both `small_test.bin`
   test uploads. Safe to dedup by keeping the MIN(ctid) row per group.
2. `sbom_components (firmware_id, name, version, cpe)` — no uniqueness
   today; rescans create dupes and inflate CVE join counts. Audit found
   0 duplicate groups in live data. UNIQUE can be added cleanly.

Pre-migration dedup (firmware only) uses PostgreSQL's `ctid` system
column to break ties deterministically: we keep the row with the lowest
ctid (earliest physical write) and delete the rest. `NULLS NOT DISTINCT`
is NOT set on the UNIQUE — NULL sha256 is not a legitimate value and
the column is `nullable=False` at the ORM layer anyway.

Downgrade drops both UNIQUEs; dedup'd rows are NOT restored.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ca95e2723392'
down_revision: Union[str, None] = '54c8864fbe0c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Dedup firmware rows on (project_id, sha256). Keep MIN(ctid) per group.
    # Before this runs, all FKs referencing firmware(id) must have already
    # cascaded (they don't, since we're not deleting the kept row) — so the
    # question is: do any rows in child tables reference a DELETED firmware
    # id? If so, CASCADE will remove them too. For the 10 test-data dup rows
    # found at authoring time, that's acceptable collateral.
    op.execute(
        """
        DELETE FROM firmware a
        USING firmware b
        WHERE a.ctid > b.ctid
          AND a.project_id = b.project_id
          AND a.sha256 = b.sha256
        """
    )
    op.create_unique_constraint(
        "uq_firmware_project_sha256",
        "firmware",
        ["project_id", "sha256"],
    )

    # sbom_components: no live dups, so no pre-dedup SQL. If any arose
    # between audit and apply, this CREATE will fail loudly — safer than
    # silently collapsing rows with different CVE enrichment.
    op.create_unique_constraint(
        "uq_sbom_components_firmware_name_version_cpe",
        "sbom_components",
        ["firmware_id", "name", "version", "cpe"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_sbom_components_firmware_name_version_cpe",
        "sbom_components",
        type_="unique",
    )
    op.drop_constraint(
        "uq_firmware_project_sha256",
        "firmware",
        type_="unique",
    )
