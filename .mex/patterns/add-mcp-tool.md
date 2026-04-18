---
name: add-mcp-tool
description: Add a new MCP tool handler to the Wairz registry so it is exposed to MCP clients (Claude Code/Desktop etc.).
triggers:
  - "add mcp tool"
  - "new mcp tool"
  - "register_*_tools"
  - "tool handler"
  - "ToolContext"
edges:
  - target: context/mcp-tools.md
    condition: to understand ToolContext, transaction ownership, and output truncation
  - target: context/conventions.md
    condition: for flush-not-commit, sandbox, and async-session rules
  - target: patterns/debug-mcp-tool-failure.md
    condition: when the tool is registered but invisible or returning empty content
last_updated: 2026-04-17
---

# Add MCP Tool

## Context
Read `context/mcp-tools.md` first. Tools live in `backend/app/ai/tools/<category>.py` and are wired into `backend/app/ai/__init__.py::create_tool_registry`. The MCP dispatcher owns the DB transaction.

## Steps

1. Decide category. If an existing `backend/app/ai/tools/<category>.py` fits (filesystem, binary, security, sbom, emulation, fuzzing, android, android_bytecode, android_sast, uart, uefi, vulhunt, attack_surface, cwe_checker, comparison, documents, network, reporting, strings), add there. Otherwise create a new file and a new `register_<category>_tools(registry)` function.

2. Implement the handler in the category file:
   ```python
   async def _handle_my_tool(input: dict, context: ToolContext) -> str:
       path = context.resolve_path(input.get("path", "/"))  # sandbox-validated
       # Heavy sync I/O → run_in_executor
       loop = asyncio.get_running_loop()
       result = await loop.run_in_executor(None, _sync_scan, path)
       # Persist via flush, NOT commit
       # context.db.add(...); await context.db.flush()
       return json.dumps(result)[:29_000]  # leave headroom under 30KB
   ```

3. Register inside the same file's `register_<category>_tools(registry)`:
   ```python
   registry.register(
       name="my_tool",
       description="What the tool does in one line — AI clients see this.",
       input_schema={
           "type": "object",
           "properties": {"path": {"type": "string"}},
           "required": [],
       },
       handler=_handle_my_tool,
   )
   ```

4. If this is a new category file, wire it in `backend/app/ai/__init__.py`:
   - Import: `from app.ai.tools.my_category import register_my_category_tools`
   - Call inside `create_tool_registry()`: `register_my_category_tools(registry)`

5. If the tool needs a new Python dep, add it to `backend/pyproject.toml` in the same commit (Learned Rule #2).

6. Rebuild backend AND worker: `docker compose up -d --build backend worker`.

7. Reconnect the MCP client (e.g. `/mcp` in Claude Code) so it re-enumerates tools.

8. If the tool caches expensive results, use the `analysis_cache` table keyed by `(binary_sha256, operation)`. `operation` is VARCHAR(512); keep keys under that or hash them.

## Gotchas

- **Invisible tool:** forgot to import + call `register_*_tools` in `app/ai/__init__.py`. No error, no log.
- **Protocol corruption:** called `print()` or used a logger that writes to stdout. Stdout is MCP protocol; use `logging.getLogger(__name__)` which inherits the stderr handler from `mcp_server.py`.
- **`commit()` instead of `flush()`:** breaks outer-transaction rollback if a later step fails.
- **`asyncio.gather()` on session-sharing coroutines:** corrupts state (Learned Rule #7). Sequential or `async_session_factory()` per task.
- **Non-string return:** dicts/lists silently break clients. `json.dumps()` first.
- **Hard-coded `extracted_path`:** breaks after `switch_project`. Always read from `context`.
- **Tool name clash:** duplicate `registry.register(name=...)` will raise at startup. Pick a unique verb.
- **Output > 30KB:** auto-truncated by `app/utils/truncation.py`. Design important fields to appear first.

## Verify

- [ ] New tool appears in the MCP client after `/mcp` reconnect.
- [ ] `docker compose logs backend | grep ERROR` is clean after invocation.
- [ ] Handler uses `context.resolve_path()` for any user-supplied path.
- [ ] Handler uses `flush()`, never `commit()`.
- [ ] Sync filesystem work wrapped in `run_in_executor`.
- [ ] Returns a string (JSON-stringified if structured).
- [ ] `backend/pyproject.toml` updated if a new import was added.
- [ ] BOTH backend and worker rebuilt.
- [ ] If new category: import + call present in `app/ai/__init__.py`.

## Debug

Follow `patterns/debug-mcp-tool-failure.md`.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if a notable new tool category was added.
- [ ] If a new gotcha surfaced, append it here.
- [ ] If the tool category list in `context/mcp-tools.md` grew, update it.
