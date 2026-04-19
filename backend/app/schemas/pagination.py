"""Reusable pagination schema for list endpoints.

``Page[T]`` is the envelope returned by any list endpoint that has been
migrated away from a bare ``list[T]`` response.  It carries the slice of
items plus the full ``total`` so clients can render "N of M" counts and
drive "load more" / numbered pagination without extra count requests.

``PageParams`` centralises the ``offset`` / ``limit`` validation so every
paginated endpoint accepts the same shape.  The intake spec (see
``.planning/intake/data-pagination-list-endpoints.md``) originally asked
for ``limit <= 500`` but we widen to 1000 to match the existing
``list_projects`` / ``list_findings`` endpoints that already accept
``Query(..., le=1000)``; narrowing would be a silent backward-compat
break.
"""
from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Generic pagination envelope: a slice plus its full total."""

    items: list[T]
    total: int = Field(ge=0, description="Total matching rows across all pages")
    offset: int = Field(ge=0, description="Offset of this slice (0-based)")
    limit: int = Field(gt=0, le=1000, description="Page size requested")


class PageParams(BaseModel):
    """Standard offset/limit query-parameter validator."""

    offset: int = Field(0, ge=0)
    limit: int = Field(100, gt=0, le=1000)
