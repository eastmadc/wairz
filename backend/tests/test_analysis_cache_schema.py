"""Regression tests for the AnalysisCache.operation column width.

Background: CLAUDE.md learned rule #15 — JADX class names with inner
classes and synthetic lambdas (``$$ExternalSyntheticLambda0``) and
Ghidra decompilation keys (``decompile:{mangled_function_name}``)
routinely exceed 150 characters. Originally sized at VARCHAR(100),
then silently corrected in the ORM model to String(512) without a
migration — leaving production DBs behind. Migration 1f6c72decc84
(widen_analysis_cache_operation_to_512) fixes the drift.

These tests lock in BOTH layers (model + migration) so a future
rename/regen doesn't re-introduce the same gap.
"""
from __future__ import annotations

from pathlib import Path

from app.models.analysis_cache import AnalysisCache


def test_model_operation_column_is_512() -> None:
    assert AnalysisCache.__table__.c.operation.type.length == 512


def test_widen_migration_present_and_sets_512() -> None:
    migrations_dir = Path(__file__).parent.parent / "alembic" / "versions"
    target = migrations_dir / "1f6c72decc84_widen_analysis_cache_operation_to_512.py"
    assert target.exists(), (
        "Widening migration is missing. If the revision was renamed, update "
        "this test. Do NOT silently drop the migration — see CLAUDE.md rule #15."
    )
    content = target.read_text()
    assert "length=512" in content
    assert "analysis_cache" in content
    assert "operation" in content
