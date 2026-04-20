"""Base protocol + shared context for SBOM detection strategies.

``StrategyContext`` is an immutable snapshot of the filesystem root a
strategy is scanning, plus the shared ``ComponentStore``. Strategies
read files under ``extracted_root`` (sandbox-validated via
``app.utils.sandbox``) and call ``store.add(...)`` for each component
they identify.

``SbomStrategy`` is a thin ABC rather than a Protocol so strategies can
share helper methods (``_abs_path``, ``_read_elf_head``) without
duplication. The coordinator holds a list of strategy instances and
invokes ``run(ctx)`` on each per scan root.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.services.sbom.normalization import ComponentStore


@dataclass(frozen=True)
class StrategyContext:
    """Immutable per-scan-root context handed to each strategy.

    The ``extracted_root`` field is the realpath of the directory to
    scan. The ``store`` is shared across strategies so dedup works
    across the whole run. ``partition_name`` is the human-readable
    label (e.g. ``"vendor"``, ``"product"``) for multi-partition
    firmware; ``None`` for the primary rootfs.
    """

    extracted_root: str
    store: ComponentStore
    partition_name: str | None = None

    def abs_path(self, rel_path: str) -> str:
        """Resolve a firmware-relative path to an absolute host path."""
        return os.path.join(self.extracted_root, rel_path.lstrip("/"))


class SbomStrategy(ABC):
    """Abstract base for a single-responsibility component scanner.

    Strategies must be stateless across runs — all mutable state belongs
    on the ``StrategyContext`` (store, partition) or on the
    ``SbomService`` coordinator. This lets a single strategy instance
    scan multiple partitions sequentially.
    """

    #: Human-readable name for logging / telemetry. Subclasses override.
    name: str = "unnamed"

    @abstractmethod
    def run(self, ctx: StrategyContext) -> None:
        """Execute this strategy against a single scan root.

        Implementations should:

        1. Walk ``ctx.extracted_root`` for the file patterns they care
           about (sandbox-validate via ``app.utils.sandbox`` if they
           build paths from user data).
        2. Parse detected files / binaries for component evidence.
        3. Call ``ctx.store.add(...)`` for each
           :class:`IdentifiedComponent` they produce.

        Any exception that indicates a malformed firmware (truncated
        ELF, unreadable directory, unexpected encoding) should be
        caught and logged rather than propagated — other strategies
        still need to run.
        """
