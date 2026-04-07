# Plan: CI/CD GitHub Action for Firmware Scanning (5.2)

**Priority:** High | **Effort:** Medium (~400 lines) | **Status:** partially implemented
**Route:** `/citadel:marshal` (finish remaining pieces)

## Goal

GitHub Action `wairz-scan` that accepts firmware URL/artifact, runs SBOM + CVE + compliance scanning, outputs pass/fail gate. Enable firmware security scanning as a CI/CD step in any GitHub Actions workflow.

## Current State (verified 2026-04-06)

Already built (session 12, commit b26930f):
- `backend/app/cli/scan.py` -- standalone CLI wrapping AssessmentService
- `backend/Dockerfile.ci` -- minimal CI image (no frontend, no emulation)
- `.github/actions/firmware-scan/action.yml` -- composite action definition
- `.github/workflows/firmware-scan.yml` -- example workflow

## What Remains

### 1. CLI Hardening (~2h)

**Current gaps in `cli/scan.py`:**
- No `--format` flag for output format selection (JSON, SARIF, CycloneDX VEX, markdown)
- No `--fail-on` flag for configurable gate thresholds (e.g., `--fail-on critical` or `--fail-on cvss:9.0`)
- No SARIF output for GitHub Security tab integration
- No `--timeout` flag for long-running scans
- Exit codes not documented (0=pass, 1=fail, 2=error)

**Implementation:**
```python
# Add to cli/scan.py
@click.option("--format", type=click.Choice(["json", "sarif", "markdown", "vex"]), default="json")
@click.option("--fail-on", type=str, default="critical", help="Fail threshold: critical|high|medium|cvss:N.N")
@click.option("--timeout", type=int, default=600, help="Scan timeout in seconds")
```

**SARIF output:** Use `sarif-om` Python package (pip-installable) or construct SARIF 2.1.0 JSON manually. GitHub Actions natively consume SARIF via `github/codeql-action/upload-sarif@v3`. Structure:
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "wairz-scan", "version": "1.0.0" } },
    "results": [{ "ruleId": "CVE-2024-...", "level": "error", "message": {...} }]
  }]
}
```

### 2. Action Enhancement (~1h)

**Current gaps in `action.yml`:**
- No `outputs` defined for downstream steps (finding count, pass/fail, report path)
- No caching of Docker image layers between runs
- No option to upload SARIF to GitHub Security tab

**Add to `action.yml`:**
```yaml
outputs:
  result:
    description: "pass or fail"
  findings-critical:
    description: "Number of critical findings"
  findings-high:
    description: "Number of high findings"
  report-path:
    description: "Path to generated report file"
  sarif-path:
    description: "Path to SARIF file for GitHub Security tab"
```

**Add post-scan step** to upload SARIF:
```yaml
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-path }}
```

### 3. Docker Image Optimization (~1h)

**Current `Dockerfile.ci`** -- verify it includes:
- All SBOM/scanning tools: Syft, Grype, binwalk/unblob
- Python deps from `pyproject.toml` (minus emulation/fuzzing extras)
- Multi-stage build to minimize image size
- No PostgreSQL/Redis (use SQLite or in-memory for stateless scanning)

**Optimization targets:**
- Use `python:3.12-slim` base (not full)
- Pin Grype + Syft versions for reproducibility
- Pre-download Grype vulnerability DB into image (avoids 30s download per scan)
- Target image size: <500MB (vs ~2GB full backend image)

### 4. Documentation + Marketplace (~1h)

- README section in `.github/actions/firmware-scan/` with usage examples
- Marketplace metadata in `action.yml` (branding, icon, color)
- Example workflows: basic scan, PR gate with SARIF upload, scheduled weekly scan
- Badge generation: `![Firmware Security](https://img.shields.io/...)`

## Industry Context

GitHub Actions SBOM/security scanning patterns (2025-2026):
- **Syft + Grype** is the standard open-source SBOM+CVE pipeline (Anchore ecosystem)
- **cdxgen** (CycloneDX generator) is gaining traction, now in GitHub Secure Open Source Fund
- SARIF integration with GitHub Security tab is the expected output format for CI security tools
- EU Cyber Resilience Act (CRA) driving mandatory SBOM generation in CI/CD pipelines
- NVD enrichment crisis (only 29% of 2025 CVEs have CPE data) makes local Grype DB more important than NVD API

## Key Files

- `backend/app/cli/scan.py` -- CLI entry point (enhance)
- `backend/Dockerfile.ci` -- CI Docker image (optimize)
- `.github/actions/firmware-scan/action.yml` -- composite action (enhance)
- `.github/workflows/firmware-scan.yml` -- example workflow (add SARIF step)

## Acceptance Criteria

- [ ] `wairz-scan --format sarif` produces valid SARIF 2.1.0 output
- [ ] `wairz-scan --fail-on critical` exits 1 when critical findings exist, 0 otherwise
- [ ] Action outputs finding counts and pass/fail to `$GITHUB_OUTPUT`
- [ ] SARIF auto-uploads to GitHub Security tab when used in a workflow
- [ ] Docker image <500MB with pre-loaded Grype DB
- [ ] Example workflow runs successfully on a public test firmware URL
- [ ] Exit codes documented: 0=pass, 1=fail-threshold-exceeded, 2=scan-error
