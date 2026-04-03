# Anti-patterns: Session 4 — Security Audit, SquashFS Fix, Zip Bomb Prevention

> Extracted: 2026-04-03
> Commit: f2b11f8

## Failed Patterns

### 1. Silent Build Failures in Dockerfile
- **What was done:** Original sasquatch build used `2>/dev/null` to suppress errors and `|| echo "WARN: ..."` as a fallback, allowing the Docker image to build successfully without the tool.
- **Failure mode:** The build failed silently on ARM64 because `-Werror` flags couldn't be patched out (the `build.sh` re-applies them after the sed replacement). The WARN message was baked into the image but never seen.
- **Evidence:** `which sasquatch` returned nothing in the running container; unblob reported `ExtractorDependencyNotFoundReport` for SquashFS
- **How to avoid:** Never suppress build errors with `2>/dev/null` for critical tools. Use `set -e` and let the build fail loudly. If a tool is truly optional, check for it at runtime with `which` instead of hiding build failures.

### 2. Missing Build Dependencies Not Caught by Existing Tests
- **What was done:** The Dockerfile had `liblzo2-dev` and `liblzma-dev` but was missing `liblz4-dev` and `libzstd-dev`. The sasquatch build failed because it needed LZ4 support.
- **Failure mode:** The build error was `lz4.h: No such file or directory` — a compile-time failure that only appears when actually building sasquatch, not during `apt-get install`.
- **Evidence:** Manual build attempt revealed the error; adding `liblz4-dev libzstd-dev` fixed it
- **How to avoid:** When adding a tool that compiles from source, check its build dependencies explicitly (e.g., read the Makefile or debian/control). Run `unblob --show-external-dependencies` after any extraction tool changes.

### 3. MCP-Only Features Without Persistence
- **What was done:** 11 security analysis tools (credential scan, setuid check, config audit, etc.) were implemented as MCP-only tools that return results as text. Results existed only in the Claude conversation and were lost when the session ended.
- **Failure mode:** Users couldn't see security scan results in the UI, couldn't filter or track them over time, and had to re-run scans in every conversation.
- **Evidence:** User asked "where are results stored?" — answer was "they're not"
- **How to avoid:** When building analysis tools, always persist results to the database. MCP tools are for interactive exploration; automated scans should write to a permanent store. Design the storage schema first, then build both the MCP tool and the automated service on top of it.

### 4. Schema Field Missing from API Response
- **What was done:** `extracted_path` existed in the ORM model and the TypeScript type but was missing from `FirmwareDetailResponse` (the Pydantic schema). The frontend's `hasUnpacked` check always returned false.
- **Failure mode:** The entire action button row ("Explore Files", "Findings", etc.) was hidden on ALL project pages. This was a pre-existing bug that went unnoticed because the SBOM and explore pages were accessed via sidebar links, not the project page buttons.
- **Evidence:** API response for `/firmware` had no `extracted_path` field; adding it to the schema fixed all buttons
- **How to avoid:** When adding new response fields to ORM models, always update the corresponding Pydantic schema. Better: use a shared type generation approach or add tests that verify API responses include expected fields.

### 5. Duplicated Pattern Lists Across Modules
- **What was done:** The same 18 API key regex patterns were copy-pasted into both `strings.py` (MCP tool) and `security_audit_service.py` (automated scan). When expanding to 65+ patterns, this would have meant maintaining two identical lists.
- **Failure mode:** Drift between the two lists — one gets updated, the other doesn't. Different detection results depending on whether the user runs the MCP tool or the automated scan.
- **Evidence:** Both files had identical `_API_KEY_PATTERNS` and `_CREDENTIAL_PATTERNS` lists
- **How to avoid:** Extract shared detection logic into `app/utils/` immediately. Don't copy-paste pattern lists between modules. Single source of truth from the start.

### 6. Virtual Root Path Mismatch
- **What was done:** Security audit stored paths relative to rootfs (`/etc/main.conf`). File explorer showed paths with virtual root prefix (`/rootfs/etc/main.conf`). Clicking finding links failed silently.
- **Failure mode:** The `navigateToPath` function searched for a tree node with ID `/etc/main.conf` which didn't exist — all nodes had `/rootfs/` prefix when `extraction_dir` was set.
- **Evidence:** Finding file links navigated to explore page but file didn't load; tree didn't expand
- **How to avoid:** When multiple systems produce/consume file paths, establish ONE canonical format and resolve at the boundary. Here: `FileService._resolve()` is the right boundary — it should accept both formats. The initial frontend-only fix was a hack; the backend resolution fix was the proper solution.
