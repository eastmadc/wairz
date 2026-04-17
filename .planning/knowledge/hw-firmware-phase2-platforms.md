# Firmware Analysis Platforms — Patterns Worth Borrowing

> Extracted: 2026-04-17
> Source: Session 41 research scout 4 — established OSS firmware platforms
> Used by: `feature-hw-firmware-phase2-enrichment.md` intake
> Context: 244-row flat table UX is unusable. This scout surveys how EMBA / FACT / unblob / OFRAK / Karonte structure their analysis + output.

## Top 3 Projects to Steal From

### A. FACT_core (fkie-cad) — signature DB + tree UX
- Repo: https://github.com/fkie-cad/FACT_core — GPL-3.0
- `software_components` plugin ships **15 categorized YARA files**: `bootloader.yara`, `kernel_modules.yara`, `phone_modem.yara`, `uefi.yara`, `vendor_specific_hp.yara`, `vendor_specific_netgear.yara`, etc. This is the canonical per-vendor YARA ruleset pattern.
- **Steal:** the naming convention `vendor_specific_<name>.yara` + per-category file layout. Add `vendor_specific_mediatek.yara`, `vendor_specific_qualcomm.yara`, `vendor_specific_broadcom.yara`.
- **Steal UX:** file tree rendering + per-node summaries that load on demand — solves the "244-row wall" directly.

### B. EMBA (e-m-b-a) — config-driven classifier
- Repo: https://github.com/e-m-b-a/emba
- Uses plain-text config: `config/vendor_list.cfg` (`vendor_id;"Display Name"`), `distri_id.cfg`, `bin_version_strings.cfg`, `kernel_details.csv`. Regex + file-path + version-extraction rules live in config, not code.
- Module naming: **P-series** (pre/unpack), **S-series** (static, e.g. `S06_distribution_identification.sh` emits CPE + PURL), **L-series** (live/emulation), **F-series** (final/report), **D-series** (diff), **Q-series** (external APIs).
- **Steal:** (1) `vendor_list.cfg` + `bin_version_strings.cfg` split — Wairz's Vendor=None is a missing config file, not a missing algorithm. (2) **CPE + PURL emission** on detected components — standardized identifiers beat freeform strings.

### C. unblob (onekey-sec) — handler taxonomy
- Repo: https://github.com/onekey-sec/unblob; docs: https://unblob.org/formats/
- Handlers grouped **functionally** (`archive/`, `compression/`, `executable/`, `filesystem/`), not by vendor. Format catalog calls out vendor formats: D-Link, Broadcom SquashFS v3/v4, Xiaomi HDR1/HDR2, Netgear CHK/TRX, QNAP, HP BDL/IPKG, Autel, Engenius, Instar.
- **Gap:** MediaTek and Qualcomm preloader/MBN handlers are NOT in public unblob — those are in OneKey's closed "dozen additional proprietary handlers". **Wairz open-sourcing MediaTek detection would advance SOTA.**
- **Steal:** functional-first structure; per-format handlers as classes with one `calculate_chunk()` method.

## Standards / Schemas Worth Following

### CycloneDX HBOM (v1.6 / v1.7) — de-facto hardware BOM schema
- Spec: https://cyclonedx.org/capabilities/hbom/
- Schema: https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json
- Pattern: each chipset gets TWO components — a `hardware` component (silicon) + a linked `firmware` / `operating-system` component (software on it), connected via `bom-ref`.
- **Apply to Wairz:** emit one HBOM document per firmware upload with hardware+firmware pairs. Makes output consumable by Dependency-Track etc.

### CPE + PURL — standard identifiers
- PURL format for firmware: `pkg:firmware/mediatek/preloader@<version>?hash=<sha256>`
- CPE for kernel: `cpe:2.3:o:linux:linux_kernel:6.6.102` (already works in grype)
- EMBA emits both via `S06_distribution_identification.sh`

### YARA — tool-portable signature DSL
- FACT's choice. Don't invent a custom YAML format; YARA rules work with other tools.

## UX Patterns to Avoid the 244-Row Wall

- **FACT file-tree + lazy summary:** render firmware as explorable tree; each node loads analysis summary on demand. Search box + MIME icons.
- **Group by partition, then by vendor** (EMBA Web Reporter pattern): `system/ → MediaTek: 47 · Qualcomm: 0 · Unknown: 8`.
- **Karonte-style Binary Dependency Graph** (https://github.com/ucsb-seclab/karonte): the paper reduced 20,931 alerts to 74 by linking binaries via data flow. **For Wairz: link each firmware blob to its kernel-module consumer** (we already have `driver_references` from Phase 3) — this is the "0 CVE matches" recovery story: "no direct hits, but loaded by a driver with 3 CVEs."
- **Entropy/offset timeline** (binwalk-style): useful for carved blobs where version extraction fails; visually groups encrypted preloader vs. zlib-compressed DSP firmware.

## Direct Answers

| Question | Answer |
|---|---|
| Cleanest chipset classifier to clone? | EMBA's `config/*.cfg` + `S06_distribution_identification.sh` — regex + file-path rules in config, not code |
| Publishable signature DB to adopt? | FACT_core's YARA rules (GPL-3; verify compat); else write our own since MediaTek isn't in FACT |
| Output grouping? | Tree-by-partition (FACT) + vendor roll-up (EMBA) + BDG link view (Karonte). Not a flat table. |
| De-facto schema? | CycloneDX HBOM v1.6 — hardware+firmware component pair linked via `bom-ref` |

## Wairz Files Touched

- `backend/app/services/firmware_classifier_service.py` — new home for YARA + vendor_list config
- `backend/app/ai/tools/hardware_firmware.py` — CycloneDX HBOM emission tool
- `frontend/src/pages/HardwareFirmwarePage.tsx` — replace flat table with partition tree + vendor roll-up
- `frontend/src/components/hardware-firmware/` — new tree + graph components

## Sources

- [EMBA](https://github.com/e-m-b-a/emba)
- [FACT_core](https://github.com/fkie-cad/FACT_core)
- [FACT docs](https://fkie-cad.github.io/FACT_core/)
- [unblob formats](https://unblob.org/formats/)
- [binwalk signatures](https://github.com/ReFirmLabs/binwalk/wiki/Supported-Signatures)
- [OFRAK](https://github.com/redballoonsecurity/ofrak)
- [firmwalker](https://github.com/craigz28/firmwalker)
- [Karonte paper](https://sites.cs.ucsb.edu/~chris/research/doc/oakland20_karonte.pdf)
- [Karonte repo](https://github.com/ucsb-seclab/karonte)
- [CycloneDX HBOM](https://cyclonedx.org/capabilities/hbom/)
- [MediaTek Preloader ASN.1 secure boot bypass](https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-hwpx-69hh-6g59)
