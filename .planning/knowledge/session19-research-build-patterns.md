# Patterns: Session 19 — Deep Research + Parallel Build

> Extracted: 2026-04-08
> Source: Session 19 (research-first approach, no formal campaign)
> Campaign file: none (research + Fleet wave build)

## Successful Patterns

### 1. Ouroboros Interview Before Implementation
- **Description:** Used Ouroboros 10-round Socratic interview to crystallize requirements BEFORE writing any code. The interview resolved: scoring model, architecture (persistent vs on-demand), auto-finding rules, signal hierarchy, detection approach, override mechanism, output model (numeric vs categorical), and build scope boundary.
- **Evidence:** Interview produced a complete spec (plan-attack-surface-map.md) that both Fleet agents could implement without ambiguity. Zero rework during build phase.
- **Applies when:** Building a feature with multiple viable architectures or unclear requirements. Especially valuable when the feature has downstream consumers (attack surface map feeds cwe_checker, ShellCheck, fuzzing).

### 2. Citadel Research Fleet for Competitive Analysis
- **Description:** Launched 7 parallel research agents (cwe_checker, ShellCheck/Bandit, DTB parser, input vector detection, competitive landscape, user impact prioritization, codebase health) BEFORE choosing what to build. This revealed that the original priority (hardcoded IP detection) was suboptimal — attack surface map + ShellCheck were higher leverage.
- **Evidence:** Competitive analysis identified cwe_checker and script SAST as the two biggest gaps vs EMBA — these weren't on the original roadmap. Research changed the entire priority stack.
- **Applies when:** Deciding what to build next, especially when the backlog has 5+ items. Parallel research costs ~50K tokens but saves entire sessions of building the wrong thing.

### 3. Fleet Wave with Zero-Overlap Scope Partitioning
- **Description:** Split build into Track A (attack surface map — all new files) and Track B (ShellCheck/Bandit — modifications to existing security.py and audit service) running in isolated worktrees. Zero file overlap = zero merge conflicts.
- **Evidence:** Both agents completed successfully, all changes landed cleanly in working tree, no conflicts.
- **Applies when:** Two features modify different file sets. Plan the partition explicitly before launching agents. Track A creates new files, Track B modifies existing ones in different directories.

### 4. Venv-Aware Binary Resolution
- **Description:** When Docker uses uv/venv, CLI tools installed as Python package dependencies (e.g., bandit) end up in `/app/.venv/bin/` not on system PATH. The fix: `shutil.which("bandit") or shutil.which("bandit", path="/app/.venv/bin")` in both MCP tool handlers AND audit service methods.
- **Evidence:** Fresh --no-cache Docker build installed bandit in venv but `which bandit` returned None from system PATH. Had to patch both security.py and security_audit_service.py.
- **Applies when:** Adding any Python package that provides CLI tools (bandit, shellcheck wrappers, etc.) to a uv-managed Docker project.

### 5. Hot-Patch Then Rebuild Pattern
- **Description:** For rapid iteration, `docker cp` changed files into the running container + restart, then do a full `--no-cache` rebuild only for the final verification. This cuts the feedback loop from 5 minutes to 10 seconds.
- **Evidence:** Used docker cp to patch bandit binary resolution fix, verified immediately, then did full fresh build for commit.
- **Applies when:** Iterating on backend code changes that need Docker container testing. NOT for Dockerfile changes (those require rebuild).

### 6. Smoke Test Suite as Commit Gate
- **Description:** Before committing, run a structured test suite that covers: API health, route registration, functional scan on real firmware, scoring accuracy verification, data persistence, and TypeScript compilation. This caught the bandit PATH issue that a simple py_compile would miss.
- **Evidence:** 10-test suite caught the bandit binary resolution issue on fresh build. Also verified attack surface scoring accuracy (dnsmasq:56 > uhttpd:49 > dropbear:38 matches expected ranking).
- **Applies when:** Every session that modifies backend code. The test suite should include at least one real-firmware functional test, not just import checks.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Attack surface map over hardcoded IP detection as #1 priority | Attack surface map is a force multiplier — feeds cwe_checker, ShellCheck, fuzzing. IP detection is a leaf feature. | Correct — produced a reusable scoring infrastructure, not just another scan tool |
| Numeric 0-100 score over categorical (Critical/High/Medium/Low) | Numeric enables sorting, score-difference analysis, and threshold adjustment. Badge derived in frontend. | Good — allows fine-grained ranking and future signal adjustments |
| Persistent DB table over on-demand MCP-only approach | Scan results need to persist across sessions, feed automated pipeline, and display in frontend tab | Correct — frontend tab works, data persists, MCP tool queries stored data |
| Import heuristics (Path 1) over config cross-reference (Path 2) for v1 | False positive cost is low (one extra row in table), false negative cost is high (missed listener). Path 2 deferred. | Correct — 144 binaries scanned, top 5 are all real network services |
| ShellCheck as static binary, not Docker sidecar | ShellCheck is 2MB, zero deps, runs in milliseconds. No need for container isolation. | Correct — installed via apt in Dockerfile, works immediately |
| bandit as pip dependency, not system package | Bandit is a Python tool, belongs in the Python environment. BUT needs venv-aware PATH resolution. | Partially correct — works but required a fix for PATH resolution |
