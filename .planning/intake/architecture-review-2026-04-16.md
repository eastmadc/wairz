---
title: "Architecture Review 2026-04-16 — Master Index"
status: reference
priority: high
target: .planning/intake/
---

# Intake Queue — 2026-04-16

Contains two distinct work streams: a new high-priority feature (hardware firmware detection) and 20 items from the architecture review (security/data/backend/frontend/infra fixes).

---

## Priority-Zero — New Feature

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 0 | `feature-android-hardware-firmware-detection.md` | critical | campaign (5 phases, ~6 sessions) |

Detection and parsing of hardware firmware blobs in Android images (modem, TEE, Wi-Fi, BT, GPU, DSP, camera, drivers). Based on parallel research across 4 scouts (file formats, parsing tools, threat model, integration architecture). Covers ~20-40 blobs per Android image that are currently invisible to Wairz.

---

## Architecture Review — Critical & High Priority

Five parallel deep reviewers covered backend services, frontend, data layer, security, and infrastructure. Combined findings: **24 critical, 48 high-priority**. 20 actionable intake items in priority order below.

---

## Critical — Security (blocks any public exposure)

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 1 | `security-auth-hardening.md` | critical | medium |
| 2 | `security-fuzzing-shell-injection.md` | critical | small |
| 3 | `security-android-unpack-hardening.md` | critical | small |
| 4 | `security-docker-socket-proxy.md` | critical | large |

## Critical — Data Layer (live foot-guns)

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 5 | `data-analysis-cache-operation-varchar-fix.md` | critical | xs |
| 6 | `data-schema-drift-findings-firmware-cra.md` | critical | small |
| 7 | `data-pagination-list-endpoints.md` | high | medium |
| 8 | `data-constraints-and-backpop.md` | high | medium |

## High — Backend Structural

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 9 | `backend-cwe-checker-session-fix.md` | critical | small |
| 10 | `backend-cache-module-extraction-and-ttl.md` | high | medium |
| 11 | `backend-service-decomposition.md` | high | large (campaign) |
| 12 | `backend-private-api-and-circular-imports.md` | high | small |

## High — Frontend Structural

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 13 | `frontend-firmware-hook-dedup.md` | high | small |
| 14 | `frontend-code-splitting-and-virtualization.md` | high | medium |
| 15 | `frontend-store-isolation-and-types.md` | high | medium |
| 16 | `frontend-api-client-hardening.md` | high | small |

## High — Infrastructure

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 17 | `infra-secrets-and-auth-defaults.md` | critical | small |
| 18 | `infra-cleanup-migration-and-observability.md` | high | large |
| 19 | `infra-volumes-quotas-and-backup.md` | high | medium |

## Bundle

| # | Intake File | Severity | Scope |
|---|---|---|---|
| 20 | `quick-wins-bundle.md` | medium | medium |

---

## Recommended Execution Order

**Wave 0 (feature work — parallel to Wave 1):** 0 (hardware firmware detection) — campaign, run via `/archon`

**Wave 1 (must-fix before any external exposure):** 1, 5, 6, 9, 17

**Wave 2 (foot-guns + structural bugs):** 2, 3, 7, 8, 10, 12, 15

**Wave 3 (structural improvements):** 4, 11, 13, 14, 16, 18, 19

**Fill-in work:** 20 (quick wins can be done opportunistically)

**Note:** Item 0 (hardware firmware feature) is independent of the review items and can run in parallel with Wave 1. Items 5 (data-analysis-cache-operation-varchar-fix) and 17 (infra-secrets-and-auth-defaults) should land before item 0's Phase 4 (CVE matching) since they improve the DB schema and secrets model that item 0 depends on.

---

## Original Review Sources

Full review reports are in the session transcript of `e89b8145-5067-4b58-987c-48894ffaf5b1`. Specific sub-review agent IDs:
- Backend services: file:line evidence across 52 services
- Frontend: 14 pages + 68 components audited
- Data: 15 models + 29 migrations + Pydantic schemas
- Security: sandbox, auth, subprocess, firmware handling
- Infrastructure: Docker, CI/CD, networking, secrets

See `.planning/knowledge/session40-architecture-review-*.md` (to be created via `/learn` after work begins).
