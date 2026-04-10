# Anti-patterns: Standalone Binary Environment Synthesis Campaign

> Extracted: 2026-04-10
> Campaign: .planning/campaigns/standalone-binary-env-synthesis.md

## Failed Patterns

### 1. LIEF Enum Name Assumptions
- **What was done:** Initially used lowercase enum names (e.g., `CPU_TYPE.x86_64`) based on documentation.
- **Failure mode:** LIEF v0.16.1 uses uppercase enum names (`ARCH.I386`, `CPU_TYPE.X86_64`, `Header.ELF_DATA`). Code failed at runtime with AttributeError.
- **Evidence:** Decision Log notes "LIEF v0.16.1 API verified (ARCH.I386 not i386, Header.ELF_DATA not ELF.ELF_DATA)." Quality rule `auto-standalone-lief-enum-case` was created from this.
- **How to avoid:** Always verify third-party library enum names with `dir()` or REPL before using them. Don't trust documentation alone — API naming varies between versions.

### 2. Alembic Migration Head Conflicts
- **What was done:** Created a new migration while another branch had an unmerged migration, resulting in two Alembic heads.
- **Failure mode:** `alembic upgrade head` fails when multiple heads exist. Had to manually merge heads.
- **Evidence:** Decision Log: "Merged two Alembic migration heads (c4d5e6f7a8b9 + 81f49fd099f5)."
- **How to avoid:** Before creating a migration, run `alembic heads` to check for multiple heads. If parallel development creates divergent heads, merge them in a dedicated migration before proceeding.

### 3. .dockerignore Missing .venv Exclusion
- **What was done:** `COPY . .` in Dockerfile copied the host's .venv directory into the container, overwriting the Docker-built venv.
- **Failure mode:** Python version mismatch between host and container caused import failures. Modules installed in Docker's venv were replaced by host's incompatible versions.
- **Evidence:** Quality rule `auto-standalone-dockerignore-venv` was created. This cost significant debugging time.
- **How to avoid:** Ensure .dockerignore excludes .venv, __pycache__, and any other host-specific directories before using `COPY . .` in Dockerfiles.
