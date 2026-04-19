"""add missing indexes attack surface emulation

Revision ID: 123cc2c5463a
Revises: ca95e2723392
Create Date: 2026-04-19 17:11:53.025512

I3 of intake `data-constraints-and-backpop.md`:

- `attack_surface_entries.firmware_id`: today only the composite
  `(project_id, firmware_id, attack_surface_score DESC)` index exists.
  Queries filtering by `firmware_id` alone (common during per-firmware
  scoring recompute) cannot use the composite on the first column and
  must seq scan. A standalone btree index on `firmware_id` restores
  the expected index hit.
- `emulation_sessions.container_id`: the cleanup path
  (`emulation_service._cleanup_*`) queries by Docker container ID to
  detect orphans after a backend restart. No index today → seq scan
  grows linearly in session count.

Both are plain btree `CREATE INDEX` (no CONCURRENTLY — acceptable for
the current row counts; <1 s lock on both tables). If row counts grow
past ~1M, consider re-running these as CONCURRENTLY in a separate
maintenance migration.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '123cc2c5463a'
down_revision: Union[str, None] = 'ca95e2723392'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_attack_surface_firmware_id",
        "attack_surface_entries",
        ["firmware_id"],
    )
    op.create_index(
        "ix_emulation_sessions_container_id",
        "emulation_sessions",
        ["container_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_emulation_sessions_container_id", table_name="emulation_sessions")
    op.drop_index("ix_attack_surface_firmware_id", table_name="attack_surface_entries")
