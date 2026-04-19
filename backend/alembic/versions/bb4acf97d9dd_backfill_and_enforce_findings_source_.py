"""backfill and enforce findings source not null

Revision ID: bb4acf97d9dd
Revises: 1f6c72decc84
Create Date: 2026-04-19 17:09:45.034630

D1 of intake `data-schema-drift-findings-firmware-cra.md`: the ORM model
(`app/models/finding.py:43`) declares `source: Mapped[str]` (non-nullable)
with a default of `'manual'`, but the original SBOM migration
(`b1c2d3e4f5a6_add_sbom_tables.py`) created the column as `nullable=True`.
This lets legacy rows surface as NULL and blow up the
`FindingResponse.source: str` pydantic validator at read time.

Audit at migration-authoring time (2026-04-19) showed zero NULL rows
in production data — the backfill UPDATE is a no-op safety floor, but
kept in place so the same migration is idempotent against any dev DB
with legacy state. The NOT NULL ALTER is the load-bearing change.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bb4acf97d9dd'
down_revision: Union[str, None] = '1f6c72decc84'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Safety floor: backfill any NULL source to 'manual' before the NOT NULL.
    # In production this is a no-op (0 rows); left in for idempotency.
    op.execute("UPDATE findings SET source = 'manual' WHERE source IS NULL")
    op.alter_column(
        "findings",
        "source",
        existing_type=sa.String(length=50),
        nullable=False,
        existing_server_default="manual",
    )


def downgrade() -> None:
    op.alter_column(
        "findings",
        "source",
        existing_type=sa.String(length=50),
        nullable=True,
        existing_server_default="manual",
    )
