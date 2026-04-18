"""widen_analysis_cache_operation_to_512

Revision ID: 1f6c72decc84
Revises: d9b2e3f5a6c7
Create Date: 2026-04-18 18:31:30.775826

The AnalysisCache.operation column is a composite cache key like
`decompile:{function_name}` or `code_cleanup:{function_name}`. The ORM
model has always declared String(512) but the original migration
created the column as VARCHAR(100). Java mangled names, JADX inner
classes, and synthetic lambdas (e.g. $$ExternalSyntheticLambda0)
commonly exceed 150 chars, triggering asyncpg StringDataRightTruncation
mid-transaction with a confusing 500 response.

Widening is a metadata-only ALTER in PostgreSQL — no lock storm.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1f6c72decc84'
down_revision: Union[str, None] = 'd9b2e3f5a6c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "analysis_cache",
        "operation",
        existing_type=sa.String(length=100),
        type_=sa.String(length=512),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Truncates any rows whose operation > 100 chars. Irreversible for
    # those rows (original value not recoverable). Kept for completeness.
    op.execute(
        "UPDATE analysis_cache SET operation = LEFT(operation, 100) "
        "WHERE length(operation) > 100"
    )
    op.alter_column(
        "analysis_cache",
        "operation",
        existing_type=sa.String(length=512),
        type_=sa.String(length=100),
        existing_nullable=False,
    )
