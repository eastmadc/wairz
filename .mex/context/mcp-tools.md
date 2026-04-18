---
name: mcp-tools
description: The MCP server, tool registry, ToolContext, and project-switching model. Load when adding, modifying, or debugging MCP tool handlers — this is the primary AI surface of Wairz.
triggers:
  - "mcp"
  - "mcp_server"
  - "tool_registry"
  - "ToolContext"
  - "add mcp tool"
  - "switch_project"
  - "wairz-mcp"
edges:
  - target: context/architecture.md
    condition: when understanding how MCP fits into the overall system (FastAPI, DB, sidecars)
  - target: context/conventions.md
    condition: when writing a tool handler — sandbox, flush vs commit, session isolation rules apply
  - target: context/decisions.md
    condition: when questioning the mutable-ProjectState design or stdio transport choice
  - target: patterns/add-mcp-tool.md
    condition: when adding a new MCP tool end-to-end
  - target: patterns/debug-mcp-tool-failure.md
    condition: when a tool returns an error, silent empty string, or misbehaves
last_updated: 2026-04-17
---

# MCP Tools

The `wairz-mcp` CLI (`app.mcp_server:main`, registered in `backend/pyproject.toml`) is the primary AI interaction surface. Everything below is specific to this server — general async/DB conventions live in `context/conventions.md`.

## Runtime Model

- **Transport:** stdio. stdout is protocol; all logging goes to stderr (enforced by the `logging.basicConfig` call in `mcp_server.py`).
- **Invocation:** `wairz-mcp --project-id <uuid>`. The MCP client (Claude Code/Desktop, etc.) spawns it as a child process.
- **Startup:** loads the given `Project`, its active `Firmware`, and extracted path from PostgreSQL. Populates a `ProjectState` dataclass (see `mcp_server.py`).
- **Project switching:** `switch_project` tool mutates `ProjectState` in place. Do NOT re-exec or tear down the process. All handler closures hold the same dataclass reference.
- **Docker volume translation:** `DOCKER_STORAGE_ROOT = "/data/firmware"` in the MCP server is translated to the host-side mountpoint when `wairz-mcp` runs on the host (not in Docker). This is why extracted paths may look like `/data/firmware/...` in the DB — the translation happens at tool-dispatch time.
- **Transaction ownership:** the outer MCP dispatch opens a single `AsyncSession` per tool call and owns the `commit`/`rollback`. Tool handlers must use `context.db.flush()` only.

## Tool Registry

- **Defined in:** `backend/app/ai/tool_registry.py` (`ToolContext`, `ToolRegistry`).
- **Populated in:** `backend/app/ai/__init__.py::create_tool_registry`. Each category calls its own `register_<category>_tools(registry)`.
- **Category files live under:** `backend/app/ai/tools/<category>.py` — `filesystem`, `strings`, `binary`, `security`, `sbom`, `emulation`, `fuzzing`, `comparison`, `uart`, `reporting`, `android`, `android_bytecode`, `android_sast`, `documents`, `network`, `uefi`, `vulhunt`, `attack_surface`, `cwe_checker`.
- **EXCLUDED_TOOLS:** a set in `mcp_server.py` for tools that exist in the registry but should NOT be exposed over MCP. Currently empty. Useful when a tool is backend-only (e.g. orchestrator-internal).

## ToolContext

Every handler receives a `ToolContext` with:

- `project_id: uuid.UUID` — the current project.
- `firmware_id: uuid.UUID` — the active firmware under the project.
- `extracted_path: str` — absolute path to the unpacked firmware root (already validated against the sandbox root at startup).
- `db: AsyncSession` — transaction is owned by the dispatcher; call `flush()`, not `commit()`.
- `resolve_path(user_path: str) -> str` — validates `user_path` against `extracted_path` via `app/utils/sandbox.py::validate_path`. Raises `PathTraversalError`. Always use this for any user-supplied path.

## Output Contract

- **Max size:** 30KB by default (`MAX_TOOL_OUTPUT_KB` env var). Over-size output is auto-truncated by `app/utils/truncation.py`. Design tool outputs to degrade gracefully when truncated — put the most important info first, paginate large lists.
- **Return type:** `str`. Structured data should be JSON-stringified. MCP clients parse strings, not Python objects.
- **Errors:** raise and let the dispatcher format the MCP error envelope. Do not `return "Error: ..."` — that looks like a success to clients.

## Registering a Tool

```python
# backend/app/ai/tools/my_category.py
from app.ai.tool_registry import ToolContext, ToolRegistry


async def _handle_my_tool(input: dict, context: ToolContext) -> str:
    path = context.resolve_path(input.get("path", "/"))
    # ... do work; use run_in_executor for sync I/O on large trees
    return "result"


def register_my_category_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="my_tool",
        description="One-line description for the AI client.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": [],
        },
        handler=_handle_my_tool,
    )
```

Then wire it in `backend/app/ai/__init__.py`:

```python
from app.ai.tools.my_category import register_my_category_tools
# ... inside create_tool_registry():
register_my_category_tools(registry)
```

## Pitfalls Specific to MCP

- **Forgetting the import+call in `__init__.py`** — the tool registers cleanly in isolation but is invisible to clients. No error, no log.
- **Stdout pollution** — any `print()` or non-stderr log in a handler corrupts the MCP protocol. All logs MUST use `logger = logging.getLogger(...)` with the stderr-configured root.
- **Returning non-string** — MCP expects text content; returning a dict or list silently breaks the response. Always `json.dumps(...)` structured data.
- **Large outputs** — Ghidra decompilations of big functions can be 100KB+. Always cache (`analysis_cache` table) and truncate. Put summary fields first so truncation leaves the useful data intact.
- **`commit()` instead of `flush()`** — breaks rollback on downstream tool errors within the same dispatch.
- **Using a stale `extracted_path`** — if the user re-unpacks firmware, the path may move. Always re-read from `ProjectState` via `context`, never cache it in a module-level variable.
