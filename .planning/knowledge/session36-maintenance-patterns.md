# Patterns: Session 36 — Maintenance & Orchestration Strategy

> Extracted: 2026-04-14
> Campaign: n/a (session-level work)
> Postmortem: none

## Successful Patterns

### 1. Parallel Research Agents for Backlog Assessment
- **Description:** Launched 3 research agents simultaneously (Citadel config, Ouroboros state, all markdown files) to build a complete project state picture before planning work.
- **Evidence:** Completed full project audit in ~90 seconds vs sequential reads which would have taken 5+ minutes.
- **Applies when:** Starting a new session with unclear project state, auditing tooling configuration, or onboarding to a mature codebase.

### 2. Stale Session Plan Detection via Cross-Reference
- **Description:** Research agents discovered CI/CD Phase 5.2 (SARIF + severity thresholds) was already completed in session 25, but the next-session-plan still listed it as remaining work.
- **Evidence:** `.planning/archive/plan-cicd-github-action.md` marked completed; `.planning/intake/next-session-plan.md` still listed it.
- **Applies when:** Resuming after a gap between sessions. Always verify "remaining work" items against actual implementation state before starting work.

### 3. Version Field Should Match CPE for Machine Readability
- **Description:** Android SBOM version field was using `display_version` (human-readable with patch info appended) but should use raw `android_version` to match CPE format and enable downstream CVE matching.
- **Evidence:** test_android_sbom expected "13" but got "13 (patch 2023-09-05)". CPE already used raw version.
- **Applies when:** Creating component identifiers for SBOM/CVE pipelines. Version fields should be machine-parseable; human-readable info goes in metadata.

### 4. Monkeypatch All Fallback Sources in Tests
- **Description:** YARA service test only patched one of three rule sources, making the test pass/fail depending on whether `/data/yara-forge` existed on the host.
- **Evidence:** `compile_rules()` loads from `[_RULES_DIR, yara_forge_dir, extra_rules_dir]` — test only patched `_RULES_DIR`.
- **Applies when:** Testing functions with fallback chains. Patch ALL sources to make tests deterministic, not just the primary source.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep Ouroboros dormant, Citadel active | Wairz in maintenance mode — remaining backlog is narrow and well-defined. Ouroboros adds overhead for work that doesn't need requirements discovery. | Saved to memory for future sessions. |
| Two-tier orchestration for Docker optimization | Quick wins fit in one session (marshal), multi-stage refactor needs persistent state (archon campaign). | Campaign file created with 5 phases. |
| Use `android_version` not `display_version` for SBOM component | Version field must match CPE for CVE correlation. Security patch already in metadata. | Test passes, CPE and version field consistent. |
