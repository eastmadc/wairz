# Plan: CycloneDX v1.7 / HBOM Upgrade (5.5)

**Priority:** Low | **Effort:** Small (~7h) | **Route:** `/do` direct or `/citadel:marshal`

## Goal

Upgrade CycloneDX export from 1.5 to 1.7 (ECMA-424). Add HBOM hardware metadata fields.

## Current State

- CycloneDX export is hardcoded to spec version "1.5" in `routers/sbom.py` (lines 189, 433)
- Components use basic schema: type, name, version, purl, cpe, supplier
- VEX export also uses 1.5 spec (lines 533-646)
- Manual JSON construction — no `cyclonedx-python` library installed
- `packageurl-python` is the only SBOM dependency

## What 1.7 Adds

- Enhanced metadata (manufacturer, supplier contacts)
- Service components (network services, APIs)
- Hardware BOM (HBOM) fields: device manufacturer, model, serial, firmware version
- Improved vulnerability handling (exploit maturity, workarounds)
- ECMA-424 international standard compliance

## Changes Required

1. Update specVersion from "1.5" to "1.7" in export functions
2. Add HBOM metadata fields to component output (device_metadata from Firmware model)
3. Install `cyclonedx-python-lib` for proper serialization (optional — can extend manual JSON)
4. Add service components from emulation discovery (discovered_services)
5. Update VEX export to 1.7 schema
6. Add optional HBOM query param to export endpoint

## Key Files

- `backend/app/routers/sbom.py` — export functions (lines 186-232, 533-646)
- `backend/pyproject.toml` — add cyclonedx-python-lib dependency (optional)
- `backend/app/models/firmware.py` — device_metadata field (already exists)
