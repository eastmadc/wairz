---
name: debug-mcp-tool-failure
description: Diagnose MCP tool failures — invisible tool, empty response, protocol corruption, transaction rollback. The MCP stdio boundary is the most opaque debug surface in Wairz.
triggers:
  - "mcp tool broken"
  - "tool not showing"
  - "empty response"
  - "mcp error"
  - "stdio corruption"
edges:
  - target: context/mcp-tools.md
    condition: to review ToolContext, transaction ownership, and output truncation rules
  - target: patterns/add-mcp-tool.md
    condition: if the root cause is a missing import/registration — use the add pattern as the reference for correct wiring
  - target: patterns/docker-rebuild-backend-worker.md
    condition: if the tool change looks wired correctly but isn't visible — likely a stale image
last_updated: 2026-04-17
---

# Debug MCP Tool Failure

## Context
MCP uses stdio: stdout is protocol, stderr is logs. The `wairz-mcp` process is spawned by the client (e.g. Claude Code). Failures fall into five buckets: (1) tool not registered, (2) stdout corrupted by a stray print, (3) handler raised silently, (4) output too large → truncated into meaninglessness, (5) stale DB state from wrong `flush/commit` usage.

## Steps

1. **Is the tool visible to the client?** In Claude Code: `/mcp` and look for the tool name in the server's tool list.
   - Not visible → go to step 2.
   - Visible → go to step 3.

2. **Registration check:**
   - Grep: `grep -r "name=\"<tool_name>\"" backend/app/ai/tools/`. Must appear in exactly one `registry.register(...)` call.
   - Open `backend/app/ai/__init__.py`. Confirm the category's `register_<category>_tools` is BOTH imported AND called inside `create_tool_registry()`.
   - Confirm it is not in `EXCLUDED_TOOLS` in `backend/app/mcp_server.py`.
   - Rebuild: `docker compose up -d --build backend worker`. Reconnect MCP client (`/mcp`).

3. **Invocation logs:** `docker compose logs backend | grep -i <tool_name>` and check stderr of the MCP client's server pane. Anything logged to stdout in the handler corrupts the protocol — any print-like call is a red flag.

4. **Run the handler directly** against the live DB to bypass the MCP layer:
   ```
   docker compose exec backend python -c "
   import asyncio
   from app.database import async_session_factory
   from app.ai.tool_registry import ToolContext
   from app.ai.tools.<category> import _handle_<tool>
   # build a ToolContext with a known project_id/firmware_id/extracted_path
   "
   ```
   This isolates handler logic from the MCP transport.

5. **Check transaction semantics:**
   - Handler must use `await context.db.flush()`, not `commit()`.
   - If the handler runs `asyncio.gather()` on coroutines that share `context.db`, rewrite sequentially or give each coroutine an independent session via `async_session_factory()` (Learned Rule #7).

6. **Check output size and format:**
   - Return must be a `str`. `json.dumps()` structured data.
   - >30KB is auto-truncated (`app/utils/truncation.py`, `MAX_TOOL_OUTPUT_KB` env). Put the most important fields first.

7. **Path resolution:** if the tool touches firmware files, confirm `context.resolve_path()` is used (not `os.path.join(extracted_path, user_path)`). Raw joins silently escape the sandbox for symlinked firmware.

8. **After fix:** rebuild backend + worker, reconnect MCP client, retry.

## Gotchas

- **Tool silently invisible:** the #1 cause — the `register_*_tools` call is missing from `create_tool_registry` even though the file exists.
- **"Works in Python but not in MCP":** stdout pollution. Look for `print()`, `rich.print`, or a logger misconfigured to stdout.
- **DB writes don't persist:** `commit()` happened but a later tool in the same dispatch rolled the outer transaction back — actually, this symptom means the dispatcher raised AFTER the `commit()`. Use `flush()` to stay inside the outer transaction.
- **Intermittent stale reads in a single dispatch:** handler did `asyncio.gather(fn_a(db), fn_b(db))` with shared session → corrupt state (Learned Rule #7).
- **Empty string return:** a handler caught an exception and returned `""`. Let the exception propagate so MCP formats a proper error envelope.
- **Docker volume translation:** when running `wairz-mcp` on the host against a Dockerised backend, `/data/firmware` paths are translated to the host-side bind mount. If that mount moved, `extracted_path` points at a nonexistent directory.
- **Stale image:** the fix is committed but the container still runs the old code. Rebuild (see `patterns/docker-rebuild-backend-worker.md`).

## Verify

After the fix:
- [ ] Tool appears after MCP client `/mcp` reconnect.
- [ ] Invoking it with a minimal valid input returns a non-empty string.
- [ ] `docker compose logs backend` shows no ERROR around the invocation.
- [ ] Handler uses `flush()`, not `commit()`.
- [ ] No `gather()` on shared sessions.
- [ ] All filesystem access via `context.resolve_path()`.

## Update Scaffold
- [ ] If a new failure mode surfaced, add it to Gotchas here.
- [ ] If the fix implied a convention violation, add a Verify Checklist item in `context/conventions.md`.
