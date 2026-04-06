# Plan: CI/CD GitHub Action for Firmware Scanning (5.2)

**Priority:** High | **Effort:** Medium (~400 lines) | **Route:** `/ouroboros:interview` then `/citadel:marshal`

## Goal

GitHub Action `wairz-scan` that accepts firmware URL/artifact, runs SBOM + CVE + compliance scanning, outputs pass/fail gate.

## Existing Infrastructure

- `AssessmentService` orchestrates 7-phase security assessment (reporting.py)
- `SbomService` generates SBOM from firmware filesystem
- `GrypeService` for fast local CVE scanning (preferred over NVD API)
- `ETSIComplianceService` maps findings to ETSI EN 303 645 (13 provisions)
- `run_full_assessment()` MCP tool already does full pipeline
- Entry point: `wairz-mcp` CLI in pyproject.toml

## Files to Create

1. `backend/app/cli/scan.py` — standalone CLI wrapping AssessmentService (~150 lines)
2. `backend/Dockerfile.ci` — minimal CI image (reuse existing with build args)
3. `.github/actions/firmware-scan/action.yml` — composite action (~40 lines)
4. `.github/workflows/firmware-scan.yml` — example workflow (~30 lines)

## Key Design Decisions

- Reuse `AssessmentService` directly, don't re-implement
- Gate on: critical finding count OR compliance status
- Use `GrypeService` (fast, offline) over `VulnerabilityService` (NVD rate-limited)
- Output: JSON to `$GITHUB_OUTPUT`, markdown report as artifact
- Database: temp SQLite or skip persistence (stateless scanning)
- Firmware download: wget from URL or copy from GitHub artifact

## Phases

1. CLI entry point wrapping existing services
2. Docker image for CI (slim, no frontend)
3. GitHub Action composite + example workflow
4. Documentation + README
