# Anti-patterns: Full Architecture Review (Session 8)

> Extracted: 2026-04-03
> Source: Full-repo 5-pass review (6 parallel agents, 188 files, ~114K lines)

## Failed Patterns

### 1. Fork+Execve for Interactive Shell in Web App
- **What was done:** Terminal WebSocket spawned `/bin/bash` via `os.fork()` + `os.execve()` with only `os.chdir()` for "confinement"
- **Failure mode:** `cd /` escapes immediately — no chroot, no namespace, no seccomp. Full host filesystem access from the browser.
- **Evidence:** S1 finding in routers/terminal.py. The shell ran on the HOST (inside the backend container but with all mounts visible).
- **How to avoid:** Always use container-level isolation for interactive shells. The Docker exec pattern (container.run + api.exec_create + socket proxy) provides full namespace isolation with minimal code.

### 2. Singleton Service with Swapped DB Session
- **What was done:** `_service_instance._db = db` swapped the DB session on a singleton to reuse persistent state (dump progress) across requests.
- **Failure mode:** Under concurrent requests, the second request's `db` overwrites the first's. First request operates on the wrong session, causing silent data corruption or transaction leaks.
- **Evidence:** S10 finding in routers/device.py. The pattern `if instance is None: create else: swap._db` is fundamentally unsafe in async.
- **How to avoid:** Separate persistent state (module-level dict) from per-request resources (DB session). Create new service instances per request; share state through module-level storage.

### 3. os.path.join for Security-Sensitive Paths Without validate_path
- **What was done:** `os.path.join(real_root, "etc/shadow")` constructed paths to shadow/passwd files without sandbox validation.
- **Failure mode:** If `etc/shadow` is a symlink pointing outside the extracted root, `os.path.join` follows it. Only `validate_path()` (which calls `os.path.realpath()` + prefix check) catches this.
- **Evidence:** S13 finding in ai/tools/strings.py. All other file-access tools used `context.resolve_path()` or `validate_path()`, but this one used raw join.
- **How to avoid:** Grep for `os.path.join.*root` in security-sensitive code. If the root is a firmware extraction directory, always validate the resolved path stays within the root.

### 4. String Interpolation in Shell Commands
- **What was done:** `f"-- /firmware/{binary_in_firmware}"` and `f"dd if=/dev/block/by-name/{partition}"` interpolated user-controlled strings into shell commands.
- **Failure mode:** Shell metacharacters (`$(cmd)`, `;`, `|`, backticks) execute arbitrary commands. The `"/" in partition` check only prevents path traversal, not injection.
- **Evidence:** S2/S3/S4 findings across fuzzing_service.py and wairz-device-bridge.py.
- **How to avoid:** Use `shlex.quote()` for all variable parts in shell command strings. For ADB/device inputs, use strict regex allowlists (`^[a-zA-Z0-9_-]+$`). Prefer `create_subprocess_exec` (list form) over `sh -c` (string form) when possible.

### 5. Sync Filesystem I/O in Async Handlers
- **What was done:** `service.list_directory(path)`, `service.read_file()`, `check_binary_protections()`, and `service.file_info()` called synchronously in async FastAPI handlers.
- **Failure mode:** Blocks the uvicorn event loop. On large firmware (10K+ files), file operations can take seconds, stalling all concurrent requests.
- **Evidence:** W2/W3 findings in routers/files.py and routers/analysis.py.
- **How to avoid:** Wrap all sync I/O in `await loop.run_in_executor(None, sync_fn, args)`. For MCP tools doing filesystem walks, extract the sync work into a plain function and executor-wrap the call.

### 6. Hardcoded CORS Wildcard with Credentials
- **What was done:** `allow_origins=["*"]` combined with `allow_credentials=True` when no `CORS_ORIGINS` env var set.
- **Failure mode:** Per CORS spec, browsers block `*` with credentials. Some middleware implementations may be permissive. In production with a reverse proxy, this could allow credential-bearing cross-origin requests.
- **Evidence:** S12 finding in main.py.
- **How to avoid:** Default to the known frontend origin (`http://localhost:3000`), not wildcard. Make CORS explicit.
