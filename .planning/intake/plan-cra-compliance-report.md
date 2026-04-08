# Plan: CRA Compliance Report Generator

> Created: 2026-04-08
> Priority: Critical (EU CRA Article 14 — September 11, 2026 deadline)
> Effort: Medium-Large (1 session for MVP, expansion in future sessions)
> Dependencies: cwe_checker (S20), firmware update detection (S22) for full coverage
> Session: S23

---

## Goal

Build a CRA compliance reporting framework with a structured data model covering all of EU CRA Annex I, a pentester-oriented checklist view (MVP), and Article 14 vulnerability notification export format. The data model supports both auto-populated findings from Wairz tools and manual-entry fields for requirements Wairz can't yet automate.

## Strategic Context

**Timeline (Citadel fleet research confirmed):**
- **September 11, 2026 (5 months):** Article 14 vulnerability notification obligations take effect — manufacturers must report actively exploited vulnerabilities to ENISA/CSIRTs within 24 hours
- **December 11, 2027 (20 months):** Full Annex I Part 1 product security requirements apply

This means the September deadline is about **reporting infrastructure**, not additional security checks. The pentester checklist covering full Annex I is for ongoing assessment value, not Sep 2026 compliance.

**Competitive position:** No open-source firmware tool does CRA compliance reporting. Finite State and ONEKEY charge for it. Wairz already has ~80% of the building blocks via ETSI EN 303 645 compliance checks.

## Current State

- `compliance_service.py` maps 13 ETSI EN 303 645 provisions with pass/fail/partial/not_tested status
- REST endpoint at `/api/v1/projects/{project_id}/compliance/etsi` 
- `check_compliance` MCP tool exposes ETSI checks
- SBOM generation (CycloneDX 1.7 + SPDX 2.3) fully implemented
- VEX export (CycloneDX VEX format) implemented
- Binary protections checked (`check_binary_protections`, `check_all_binary_protections`)
- Attack surface scoring (0-100, 5 signal categories)
- Certificate analysis, credential detection, kernel hardening checks all exist
- Secure boot analysis (U-Boot FIT, dm-verity, UEFI Secure Boot)

**ETSI → CRA mapping:** ETSI EN 303 645 covers consumer IoT and maps partially to CRA. The CRA is broader (covers all "products with digital elements") and has different requirement numbering. The compliance service needs to expand from ETSI-only to a dual ETSI+CRA framework.

## CRA Annex I Requirements to Model

### Part 1: Security Requirements (Dec 2027 deadline)

| # | CRA Requirement | Wairz Auto-Assessment | Status |
|---|---|---|---|
| 1.1 | Secure by design, delivered with secure defaults | Default password check, debug interface detection | Partial |
| 1.2 | No known exploitable vulnerabilities | Grype CVE scan, cwe_checker (S20) | Good |
| 1.3 | Security risk assessment documentation | Manual entry (can reference findings) | Manual |
| 1.4 | SBOM (machine-readable) | CycloneDX + SPDX generation | Complete |
| 1.5 | Address vulnerabilities without delay | VEX export, finding triage workflow | Partial |
| 1.6 | Secure update mechanism | Firmware update detection (S22), secure boot | Partial |
| 1.7 | Data confidentiality (encryption, storage) | Certificate analysis, credential detection | Partial |
| 1.8 | Data integrity | Secure boot, hash verification | Partial |
| 1.9 | Minimize data processing | Manual entry | Manual |
| 1.10 | Availability / resilience | Manual entry | Manual |
| 1.11 | Minimize attack surface | Attack surface scoring (complete) | Good |
| 1.12 | Mitigate impact of incidents | Manual entry | Manual |
| 1.13 | Logging / monitoring | Init script analysis, syslog detection | Partial |

### Part 2: Vulnerability Handling (Sep 2026 deadline)

| # | CRA Requirement | Wairz Auto-Assessment | Status |
|---|---|---|---|
| 2.1 | Identify and document vulnerabilities | CVE scan + findings system | Good |
| 2.2 | Address vulnerabilities timely | Finding triage workflow, VEX | Partial |
| 2.3 | Effective security testing | Assessment report, SAST tools | Partial |
| 2.4 | Vulnerability disclosure policy | Manual entry (template provided) | Manual |
| 2.5 | Share info about vulnerabilities | Manual entry | Manual |
| 2.6 | Vulnerability notification to authorities | **Article 14 export** — NEW | Missing |
| 2.7 | SBOM available to authorities | CycloneDX/SPDX export | Complete |

## Implementation Plan

### Step 1: CRA Data Model

New DB table `cra_assessments`:

```sql
CREATE TABLE cra_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    firmware_id UUID REFERENCES firmware(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assessor_name TEXT,
    product_name TEXT,
    product_version TEXT,
    -- Overall status
    overall_status TEXT NOT NULL DEFAULT 'in_progress',  -- in_progress, complete, exported
    -- Auto-populated summary stats
    auto_pass_count INTEGER DEFAULT 0,
    auto_fail_count INTEGER DEFAULT 0,
    manual_count INTEGER DEFAULT 0,
    not_tested_count INTEGER DEFAULT 0
);

CREATE TABLE cra_requirement_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES cra_assessments(id) ON DELETE CASCADE,
    requirement_id TEXT NOT NULL,        -- e.g., "annex1_part1_1.2"
    requirement_title TEXT NOT NULL,     -- human-readable title
    annex_part INTEGER NOT NULL,         -- 1 or 2
    status TEXT NOT NULL DEFAULT 'not_tested', -- pass, fail, partial, not_tested, not_applicable
    auto_populated BOOLEAN DEFAULT FALSE,
    -- Auto-populated evidence
    evidence_summary TEXT,               -- markdown summary of findings
    finding_ids JSONB DEFAULT '[]',      -- references to finding IDs
    tool_sources JSONB DEFAULT '[]',     -- which tools contributed (e.g., ["grype", "cwe_checker"])
    -- Manual entry
    manual_notes TEXT,                   -- pentester notes
    manual_evidence TEXT,                -- manually provided evidence
    -- CWE / CVE references
    related_cwes JSONB DEFAULT '[]',
    related_cves JSONB DEFAULT '[]',
    -- Timestamps
    assessed_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Step 2: CRA Compliance Service

New service: `backend/app/services/cra_compliance_service.py` (~500-600 lines)

Functions:
- `create_assessment(project_id, firmware_id) -> CraAssessment` — initialize with all Annex I requirements
- `auto_populate(assessment_id)` — run through existing tools and populate results:
  - CVE scan → 1.2 (no known vulnerabilities)
  - SBOM → 1.4 (SBOM exists)
  - Binary protections → 1.11 (attack surface)
  - cwe_checker findings → 1.2 (code quality)
  - Update mechanism detection → 1.6 (secure updates)
  - Certificate analysis → 1.7 (data confidentiality)
  - Secure boot → 1.8 (data integrity)
  - Init script analysis → 1.13 (logging)
  - Credential detection → 1.1 (secure defaults)
  - Attack surface score → 1.11 (minimize attack surface)
- `update_requirement(assessment_id, requirement_id, status, notes)` — manual entry
- `export_checklist(assessment_id) -> dict` — structured JSON export
- `export_article14_notification(assessment_id, vulnerability_id) -> dict` — ENISA notification format

### Step 3: Article 14 Vulnerability Notification Export

This is the Sep 2026 deadline item. Format based on ENISA's vulnerability notification template:

```json
{
  "notification_type": "actively_exploited_vulnerability",
  "product": {"name": "...", "version": "...", "sbom_ref": "..."},
  "vulnerability": {
    "cve_id": "CVE-XXXX-XXXXX",
    "description": "...",
    "severity": "critical",
    "cwss_score": 9.8,
    "affected_components": ["..."],
    "exploitation_status": "actively_exploited"
  },
  "timeline": {
    "discovered_at": "...",
    "notification_deadline": "24h from discovery",
    "remediation_eta": "..."
  },
  "mitigation": {"temporary": "...", "planned_fix": "..."},
  "contact": {"csirt": "...", "manufacturer": "..."}
}
```

### Step 4: MCP Tools

Register in `backend/app/ai/tools/security.py`:

1. `create_cra_assessment` — Initialize a CRA assessment for the current firmware
2. `auto_populate_cra` — Run auto-population across all requirements
3. `update_cra_requirement` — Manual entry for a specific requirement
4. `export_cra_checklist` — Export full checklist as structured JSON
5. `generate_article14_notification` — Generate ENISA notification for a specific vulnerability

### Step 5: REST Endpoints

New router: `backend/app/routers/cra_compliance.py`

- `POST /api/v1/projects/{pid}/cra/assessments` — create assessment
- `GET /api/v1/projects/{pid}/cra/assessments` — list assessments
- `GET /api/v1/projects/{pid}/cra/assessments/{aid}` — get assessment with all requirement results
- `POST /api/v1/projects/{pid}/cra/assessments/{aid}/auto-populate` — trigger auto-population
- `PATCH /api/v1/projects/{pid}/cra/assessments/{aid}/requirements/{rid}` — update requirement
- `GET /api/v1/projects/{pid}/cra/assessments/{aid}/export` — export checklist (JSON)
- `GET /api/v1/projects/{pid}/cra/assessments/{aid}/article14/{vid}` — export Article 14 notification

### Step 6: Frontend — Pentester Checklist View

New tab in SecurityScanPage or dedicated CRA page:

- Assessment overview: product name, version, overall progress (X/20 assessed)
- Requirement list: grouped by Annex I Part 1 / Part 2
- Each requirement shows: status badge (pass/fail/partial/not_tested), auto-populated evidence, manual notes field
- Inline editing for manual requirements
- Export buttons: JSON, PDF (future)
- Article 14 notification generator: select a CVE, pre-fill from findings, export

## Files to Create/Modify

| File | Change |
|------|--------|
| `backend/app/models/cra_compliance.py` | **New:** SQLAlchemy models for assessments + requirements |
| `backend/app/schemas/cra_compliance.py` | **New:** Pydantic schemas |
| `backend/app/services/cra_compliance_service.py` | **New:** ~500-600 lines, compliance logic |
| `backend/app/routers/cra_compliance.py` | **New:** REST endpoints |
| `backend/app/ai/tools/security.py` | Add 5 CRA tool handlers + registration |
| `backend/app/main.py` | Register CRA router |
| `backend/app/routers/tools.py` | Whitelist CRA tools |
| `alembic/versions/xxx_add_cra_compliance.py` | Migration for new tables |
| `frontend/src/api/craCompliance.ts` | **New:** API client |
| `frontend/src/components/security/CraChecklistTab.tsx` | **New:** Pentester checklist view |
| `frontend/src/pages/SecurityScanPage.tsx` | Add CRA Compliance tab |

## What NOT to Do

- Do NOT build the manufacturer formal report export yet — pentester checklist is the MVP
- Do NOT duplicate ETSI compliance checks — reference and reuse `compliance_service.py` results
- Do NOT implement actual ENISA API submission — just generate the notification document for manual submission
- Do NOT add PDF export in this session — JSON export is sufficient for MVP
- Do NOT try to automate requirements marked "Manual" — provide text fields for pentester input
- Do NOT make Article 14 notification automated — it's a document generator, not an auto-reporter

## Acceptance Criteria

1. `create_cra_assessment` initializes all 20 Annex I requirements (13 Part 1 + 7 Part 2)
2. `auto_populate_cra` correctly maps existing tool outputs to CRA requirements
3. Manual requirements have editable text fields in the frontend
4. Each requirement shows its data sources (which tools contributed)
5. Article 14 notification export produces valid JSON with required fields
6. Frontend checklist shows progress bar and grouped requirements
7. Assessment data persists in database, survives page reload
8. All tools whitelisted for REST access
