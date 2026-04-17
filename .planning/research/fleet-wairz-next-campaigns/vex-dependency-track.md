# VEX + Dependency-Track Integration — Research Brief

> Scout: fleet-wairz-next-campaigns / vex-dependency-track
> Date: 2026-04-17

## Existing State in Wairz

**A lot is already built. The gap is much smaller than the campaign framing implies.**

`backend/app/services/dependency_track_service.py` (62 LOC) — a working `DependencyTrackService` class. `is_configured` property (URL + API key), `push_sbom(sbom_json, project_name, project_version)` method. Uses `httpx.AsyncClient`, PUTs to `{base_url}/api/v1/bom` with `autoCreate=True`, base64-encodes the JSON payload, returns DT's processing-token JSON. Auth via `X-Api-Key` header. Config at `config.py:64-65` (`dependency_track_url`, `dependency_track_api_key`). [1]

`backend/app/routers/sbom.py` — three endpoints already ship:
- `GET /export?format=cyclonedx-vex-json` → calls `_build_vex_response()` (lines 603–719). Builds a full CycloneDX **1.7** VEX doc: components + `vulnerabilities[]` with `id`, `source`, `ratings` (adjusted-score-preferred), `affects[{ref}]`, `analysis.state/justification/detail/response`.
- `POST /push-to-dependency-track` → pushes the regular CDX SBOM (not VEX, not HBOM). Inline BOM builder; no HBOM-awareness.
- Three mapper helpers already encode the Wairz→VEX translation: `_map_resolution_to_vex_state()`, `_map_resolution_to_vex_response()`, `_map_justification_to_vex()`.

`backend/app/ai/tools/sbom.py` — MCP already exposes `export_sbom` with `cyclonedx-vex-json` format (line 157) and a dedicated `set_vulnerability_vex_status` tool (line 264) that accepts standard VEX status values (`not_affected`, `affected`, `fixed`, `under_investigation`). `push_to_dependency_track` MCP tool exists (line 176/869). The MCP `export_sbom` returns a summary for VEX over 30 KB.

`backend/app/services/hardware_firmware/hbom_export.py` (301 LOC, just shipped) — `build_hbom()` emits CycloneDX **1.6** with hw+fw components + `dependencies.provides` + `vulnerabilities[]`. **Vulnerability entries currently include `id`/`affects`/`ratings`/`description`/`properties`. No `analysis.*` fields. No VEX state.** Grep confirms zero mentions of `resolution_status`, `analysis`, `adjusted_` in this file.

Models: `SbomVulnerability` has all VEX-inputs already — `resolution_status` (default `"open"`), `resolution_justification`, `adjusted_cvss_score`, `adjusted_severity`, `adjustment_rationale`, plus hw-firmware-specific `match_tier`, `match_confidence`, `blob_id`.

## Gap Analysis

What's missing to hit "VEX + DT push on HBOM":

1. **HBOM does not emit VEX analysis fields.** `hbom_export._build_vulnerability()` has no `analysis` block. The mappers exist in `routers/sbom.py` but aren't imported/reused by HBOM. This is the #1 gap.
2. **No HBOM push endpoint or MCP tool.** `push-to-dependency-track` only pushes the regular SBOM, and inlines its own BOM builder instead of calling `build_hbom()`.
3. **No VEX-specific DT endpoint usage.** `DependencyTrackService.push_sbom()` only targets `/api/v1/bom`. Dependency-Track has a separate `/api/v1/vex` endpoint for standalone VEX upload. Today you'd push a VEX-embedded CDX 1.6 HBOM through `/api/v1/bom` (which works; DT treats embedded `vulnerabilities[]` as VEX), or add a second method for the `/api/v1/vex` endpoint for suppliers pushing standalone VEX.
4. **CVE-matcher tier awareness is not fed into VEX state.** The Tier-5 `kernel_subsystem` matches auto-persist with `resolution_status="open"`; the current `_map_resolution_to_vex_state()` returns `in_triage` for open vulns when `adjusted_severity` is unset — which is actually correct for Tier-5, but there's no automatic path to mark low-confidence matches as `in_triage` vs. medium/high as `exploitable`. The mapper is score-keyed, not tier-keyed.
5. **CycloneDX version mismatch.** SBOM exports use **1.7**, HBOM uses **1.6**. Dependency-Track supports 1.6 for ingest; 1.7 support is open (Issue #5818). HBOM's 1.6 choice is the safe target for DT; we should either lock VEX-on-HBOM to 1.6 or verify DT 4.12+ tolerates 1.7. [2]

## VEX Format Reference

CycloneDX 1.6 embeds VEX inside a BOM: top-level `vulnerabilities[]` sibling to `components[]`. Each entry:

| Field | Notes |
|---|---|
| `id` | `"CVE-2024-XXXX"` |
| `source` | `{"name": "NVD", "url": "..."}` |
| `ratings[]` | `{severity, score, vector, method}` — method is `CVSSv31`/`CVSSv4` |
| `affects[]` | `[{"ref": "fw_<blob-id>"}]` — points at firmware component bom-ref |
| `analysis.state` | **VEX core**. `resolved`/`resolved_with_pedigree`/`exploitable`/`in_triage`/`false_positive`/`not_affected` |
| `analysis.justification` | Only for `not_affected`: `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_by_mitigating_control`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_policy` |
| `analysis.response[]` | `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available` |
| `analysis.detail` | Free-text justification from `resolution_justification` / `adjustment_rationale` |

CDX states are a superset of OpenVEX's (`not_affected`, `affected`, `fixed`, `under_investigation`). OpenVEX is a separate standalone doc; CDX embeds in BOM. **Dependency-Track's native model is CycloneDX VEX; OpenVEX requires conversion.** EMBA ships CDX VEX. Stay with CDX. [3] [4]

## Wairz Resolution → VEX State Mapping

Already implemented at `routers/sbom.py:555-600`. Concrete table (what ships today + one proposed refinement for hw-firmware tiers):

| `SbomVulnerability` state | → `analysis.state` | `response` | Notes |
|---|---|---|---|
| `resolution_status="resolved"` | `resolved` | `["update"]` | current |
| `resolution_status="ignored"` | `not_affected` | `["will_not_fix"]` | current |
| `resolution_status="false_positive"` | `not_affected` | — | current |
| `resolution_status="open"` + `adjusted_severity` set | `exploitable` | — | current (reviewed & confirmed exploitable) |
| `resolution_status="open"`, no adjustment | `in_triage` | — | current (default) |
| **Proposed**: `match_tier ∈ {nvd_freetext, kernel_subsystem}` + no adjustment | `in_triage` (force) | — | low-confidence tier heuristics MUST NOT auto-assert `exploitable` |
| **Proposed**: `match_tier == "curated_yaml"` + `match_confidence == "high"` + no adjustment | `exploitable` | — | curated advisories are authoritative |

Justification mapping already normalises free-text to valid CDX enum; no change needed.

## Dependency-Track API Notes

- **BOM upload**: `PUT /api/v1/bom` (JSON body with `projectName`, `projectVersion`, `autoCreate`, `bom` as base64). This is what Wairz uses. [5]
- **VEX upload**: `POST /api/v1/vex` (multipart form: `projectName`, `projectVersion`, `vex=@file`). Used to push VEX statements received from suppliers to an existing DT project. Wairz doesn't use this today.
- **Embedded-VEX BOM**: DT accepts CDX BOMs with a populated `vulnerabilities[]` array via `/api/v1/bom`. This is the path to use for HBOM-with-analysis pushing — no need for `/api/v1/vex` unless Wairz wants to offer "push VEX only without SBOM changes".
- **Auth**: `X-Api-Key` header, which Wairz already does.
- **Version support**: DT ingests up through CDX 1.6 today. CDX 1.7 support is open (Issue #5818). Some 1.5/1.6 component types (e.g., `cryptographic-asset`) aren't recognised (Issue #4361). `hardware` and `firmware` component types **are** recognised. [2] [6]
- **Schema validation**: Recent DT versions reject BOMs that fail schema validation — make sure emitted JSON is strictly valid against the CDX 1.6 schema. The existing severity-coercion guard in `hbom_export._build_vulnerability` (line 39-47) is the right pattern.

## EMBA Comparison

EMBA ships SBOM + VEX generation as part of its analysis pipeline, auto-uploads to DT with an API key, emits CDX JSON VEX. [7] [8]

**Wairz already matches:** CDX VEX emission, DT push, multi-tier matcher with provenance as properties, unmapped firmware via `fw_<blob-id>` bom-refs. **Surpasses:** 5-tier matcher with per-tier confidence, adjusted-severity separate from NVD, HBOM hw-component modelling. **Lacks:** EMBA's DT push is wired to the CRA/ENISA workflow; Wairz has `cra_compliance_service.py` but no evidence VEX push is part of its bundle yet.

## Integration into Wairz

Three small edits, likely **one session, 150–250 LOC net**:

1. **`backend/app/services/hardware_firmware/hbom_export.py`** (~40 LOC add): import the three mappers from `routers/sbom.py` (or lift them to `app/utils/vex.py` since both paths now need them). Extend `_build_vulnerability(vuln, firmware_ref)` to add an `analysis` block populated from `vuln.resolution_status`, `resolution_justification`, `adjustment_rationale`. Add the proposed tier-aware refinement to the state mapper.

2. **`backend/app/routers/hardware_firmware.py`** (~30 LOC): add `POST /cdx.json/push` that calls `build_hbom()` then `DependencyTrackService.push_sbom()`. Query param `?project_name=` override, default to firmware filename + `device_metadata.model` if present. (Consider whether a separate `GET /vex.json` endpoint is wanted — current `/cdx.json` already contains VEX-in-BOM once gap #1 is filled, so this may be unnecessary.)

3. **`backend/app/ai/tools/hardware_firmware.py`** (~25 LOC): add `push_hardware_firmware_hbom` MCP tool mirroring `export_hardware_firmware_hbom` (which exists at line 324). Reuses `DependencyTrackService`.

4. **Optional — `app/utils/vex.py`** (~60 LOC, lift + share): move the three VEX mapper helpers out of `routers/sbom.py` so HBOM export and the future refined tier logic don't import from a router module.

5. **Optional — `dependency_track_service.py`** (~20 LOC): add `push_vex(vex_json, project_name, project_version)` that targets `/api/v1/vex` via multipart for the edge case where a user wants to push a VEX snapshot without the components array (e.g., ingested third-party VEX). Not required for the core feature.

**No migrations needed.** Every field required already exists on `SbomVulnerability`.

## Dead Ends / Open Questions

- **Does Dustin run a Dependency-Track instance?** Config vars default empty. If no DT, VEX-as-file is still useful for CI artifacts / third-party sharing.
- **CDX 1.7 vs 1.6** — SBOM on 1.7, HBOM on 1.6. Recommendation: stay on 1.6 for DT-destined docs; optional `?spec_version=` param later.
- **DT classifier coverage** — web results confirm DT supports `hardware`+`firmware` types; some newer classifiers are silently dropped. Live-test before declaring end-to-end.
- **`match_tier`-aware mapping** — the "Tier 5 forced `in_triage`" rule is my recommendation, needs sign-off.
- **CRA bundle** — should VEX push be part of the CRA evidence bundle? Scope creep for this campaign.

## Confidence

**High** on gap analysis and file-level implementation sketch — I read the actual files, they exist, the mappers exist, the DT service exists, the models have every field we need. The campaign as framed ("build VEX + DT") overestimates what's missing. The real work is glue code (gap #1 and #2) — a small session, not a multi-session campaign.

**Medium** on the proposed `match_tier`-aware state mapping — it's a judgment call that needs Dustin's sign-off.

**Lower** on DT version compatibility specifics — would verify against a live instance before finalising.

## References

1. `/home/dustin/code/wairz/backend/app/services/dependency_track_service.py`
2. https://github.com/DependencyTrack/dependency-track/issues/5818 — CDX 1.7 support in DT
3. https://cyclonedx.org/capabilities/vex/ — CycloneDX VEX capability doc
4. https://openssf.org/blog/2023/09/07/vdr-vex-openvex-and-csaf/ — OpenVEX vs CDX comparison
5. https://docs.dependencytrack.org/usage/cicd/ — DT CI/CD upload examples
6. https://github.com/DependencyTrack/dependency-track/issues/4361 — CDX 1.5/1.6 classifier gaps in DT
7. https://github.com/e-m-b-a/emba/wiki/Dependency-Track-integration — EMBA DT integration docs
8. https://github.com/e-m-b-a/emba/wiki/The-EMBA-book-%E2%80%90-Chapter-5:-SBOM-and-vulnerability-aggregation — EMBA SBOM/VEX chapter
