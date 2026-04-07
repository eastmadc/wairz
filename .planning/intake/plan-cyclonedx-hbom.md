# Plan: CycloneDX v1.7 / HBOM Upgrade (5.5) -- COMPLETED

**Priority:** Low | **Effort:** Small | **Status:** completed (2026-04-06, session 11)

## Summary

CycloneDX exports upgraded from spec version 1.5 to 1.7 (ECMA-424, 2nd edition December 2025).
HBOM device metadata fields added to main component output. VEX export also upgraded.

This plan is retained for reference. No further work needed.

## What Was Delivered

1. `specVersion` updated from "1.5" to "1.7" in all export functions (`routers/sbom.py`)
2. HBOM metadata fields added to component output (device manufacturer, model, firmware version from `Firmware.device_metadata`)
3. VEX export upgraded to 1.7 schema
4. Hardware component type support for IoT device metadata

## CycloneDX 1.7 (ECMA-424) Reference

The ECMA-424 standard (2nd edition, December 2025) defines CycloneDX v1.7 as an international standard for:
- Software Bill of Materials (SBOM)
- Hardware Bill of Materials (HBOM) -- device manufacturer, model, serial, certifications, GTINs
- Machine Learning BOM (ML-BOM)
- Cryptographic BOM (CBOM)
- Operations BOM (OBOM)
- Vulnerability Disclosure Reports (VDR) and Vulnerability Exploitability Exchange (VEX)

**HBOM component fields available in 1.7:**
- `component.type: "device"` -- hardware component type
- `component.manufacturer` -- device manufacturer details (name, url, contacts)
- `component.properties` -- name/value pairs for hardware attributes (serial, GTIN, certifications)
- `component.evidence` -- provenance and supply chain evidence

**Python library:** `cyclonedx-python-lib` supports 1.7 but was not added as a dependency. Current implementation uses manual JSON construction, which is sufficient and avoids an extra dependency.

## Key Files

- `backend/app/routers/sbom.py` -- export functions (updated)
- `backend/app/models/firmware.py` -- device_metadata field (unchanged)
