"""Structured logging configuration (Phase 3 / O3 — observability baseline).

Routes all Python stdlib `logging` output through structlog so every line is
emitted as a single JSON object with ISO-8601 timestamps, log level, logger
name, and any bound context. `logging.getLogger(__name__)` callers continue to
work unchanged — structlog's `ProcessorFormatter` wraps stdlib records and
hands them off to the JSON renderer.

Import + call `configure_logging()` ONCE at process start (lifespan entry /
arq on_startup). Idempotent — re-calling is safe but wastes work.

Anti-pattern avoided: configuring structlog.configure() WITHOUT routing stdlib
logging through the same formatter produces two output streams (structlog JSON
+ plain stdlib text) on the same stdout, which breaks any log aggregator's
JSON parser on alternate lines. The stdlib + structlog pipeline here is a
single path.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str = "INFO") -> None:
    """Configure stdlib + structlog to emit JSON to stdout.

    Called from FastAPI lifespan and the arq worker `on_startup` hook.
    """
    # Shared processor chain for both stdlib-bridged and structlog-native logs.
    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Structlog native loggers finish with the JSON renderer.
    structlog.configure(
        processors=shared_processors + [structlog.processors.JSONRenderer()],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib logging → structlog ProcessorFormatter so third-party
    # libraries (uvicorn, sqlalchemy, docker, arq) also emit JSON.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    # Replace handlers so uvicorn's default StreamHandler doesn't double-emit.
    root_logger.handlers = [handler]
    root_logger.setLevel(level.upper())

    # Uvicorn's "uvicorn", "uvicorn.error", "uvicorn.access", and fastapi's
    # "fastapi" loggers install their OWN handlers with a plain-text formatter
    # and set ``propagate=False``. Without rerouting they bypass the root
    # handler and emit plain-text lines (``INFO: Uvicorn running on ...``)
    # alongside the JSON produced by stdlib callers. Remove their handlers
    # and let them propagate to the root.
    for named in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "arq", "arq.worker"):
        lg = logging.getLogger(named)
        lg.handlers = []
        lg.propagate = True

    # Tame the most chatty libraries at INFO; they still bubble to WARN+.
    for noisy in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel("WARNING")
