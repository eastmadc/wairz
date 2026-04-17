# Android Hardware Firmware — Wairz Integration Architecture

> Extracted: 2026-04-16
> Source: Session 40 research scout 4 (Wairz integration design)
> Used by: `feature-android-hardware-firmware-detection.md` intake

## Overview

Wairz currently analyzes software components (SBOM via Syft/LIEF), RTOS binaries, kernel images, and Android frameworks — but the **hardware firmware blobs those platforms load** (modem, TZ TAs, Wi-Fi/BT, GPU microcode, DSP, device trees) are treated as opaque bytes. This design adds a dedicated subsystem reusing the existing unpack pipeline, adding one new data model with clean FK to `Firmware`, layered after SBOM generation.

**Guiding architectural choice:** hardware firmware gets its OWN model, **not** a `type="hardware_firmware"` flag on `SbomComponent`. SbomComponent is built around name/version/CPE with a single purpose (software CVE matching). Hardware firmware has chipset targets, signature metadata, driver references, and per-format headers that don't map cleanly to CPE. Sibling model with one-way link into `sbom_components` keeps both clean.

**Phase 1 ships Android focus; parser plugin protocol makes iBoot/IMG4, Cisco IOS, Junos extensions drop-in.**

## 5-Phase Implementation Plan

### Phase 1 — Detect & Classify (1 session)

Walk extracted firmware tree after unpack succeeds. Identify candidate blobs by magic bytes + path heuristics. Classify into `(category, vendor, format)`. Persist to `hardware_firmware_blobs`. No parsing beyond ID. **Ships tool:** `list_hardware_firmware`.

### Phase 2 — Per-format Parsers (2 sessions)

Add parser plugins for:
- Qualcomm MBN v3/v5/v6 (uses vendored qtestsign)
- Android DTB/DTBO (uses fdt pip pkg)
- Linux kernel module `.modinfo` (pyelftools)
- ELF-wrapped TEE/modem images (LIEF)
- Broadcom Wi-Fi (brcmfmac heuristics)
- Raw binary fallback (entropy + strings)

Each parser fills `version`, `signed`, `signature_algorithm`, `chipset_target`, per-format `metadata` JSONB.

### Phase 3 — Driver↔Firmware Graph (1 session)

Parse DTB `compatible` → match to kmod `alias`. Parse `firmware_request()` strings from `.ko` to populate `driver_references`. Add edges to existing `component_map` graph as `ComponentEdge.type="loads_firmware"`.

### Phase 4 — CVE Heuristic Matching (1 session)

Three-tier matcher:
1. **Chipset-level CPE lookup** (`cpe:2.3:h:qualcomm:sdm865:-:*`) via existing `cpe_dictionary_service`
2. **NVD free-text search** on vendor+category keywords
3. **Curated YAML** database (`known_firmware.yaml`) — same pattern as `KNOWN_SERVICE_RISKS`

Hits write to existing `sbom_vulnerabilities` with new `blob_id` discriminator (migration adds column).

### Phase 5 — UI + MCP Tools (1 session)

6 MCP tools + `HardwareFirmwarePage` at `/projects/:id/hardware-firmware` + driver↔firmware overlay on existing ComponentMapPage.

## Data Model

```python
# backend/app/models/hardware_firmware.py
class HardwareFirmwareBlob(Base):
    __tablename__ = "hardware_firmware_blobs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid.uuid4,
                                     server_default=func.gen_random_uuid())
    firmware_id: Mapped[UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"), nullable=False, index=True)

    # Location
    blob_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    partition: Mapped[str | None] = mapped_column(String(64))
    blob_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Classification
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # modem|tee|wifi|bluetooth|gpu|dsp|camera|audio|sensor|touchpad|nfc|usb|
    # display|fingerprint|dtb|kernel_module|bootloader|other
    vendor: Mapped[str | None] = mapped_column(String(64))
    # qualcomm|mediatek|samsung|broadcom|nvidia|imagination|arm|apple|cypress|
    # unisoc|hisilicon|intel|unknown
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    # qcom_mbn|mbn_v5|elf|dtb|dtbo|ko|fw_csd|fw_bcm|raw_bin|tzbsp|img4

    # Versioning & signing
    version: Mapped[str | None] = mapped_column(String(128))
    signed: Mapped[str] = mapped_column(String(16), default="unknown")  # signed|unsigned|unknown
    signature_algorithm: Mapped[str | None] = mapped_column(String(64))
    cert_subject: Mapped[str | None] = mapped_column(Text)
    chipset_target: Mapped[str | None] = mapped_column(String(64))

    # Graph refs
    driver_references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    sbom_component_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL"))

    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, server_default=text("'{}'"))
    detection_source: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_confidence: Mapped[str] = mapped_column(String(16), default="medium")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_hwfw_firmware_category", "firmware_id", "category"),
        Index("ix_hwfw_vendor", "vendor"),
        Index("ix_hwfw_sha256", "blob_sha256"),
    )
```

Same migration adds `blob_id: UUID | None` FK to `sbom_vulnerabilities` so CVE hits reuse that table.

## Service Layer Structure

```
backend/app/services/hardware_firmware/
├── __init__.py              # public API: detect_hardware_firmware(firmware_id, db)
├── detector.py              # walks FS, dispatches to parsers, writes DB rows
├── classifier.py            # magic bytes + path heuristics → (category, vendor, format)
├── version_extractor.py     # generic version-regex fallback
├── cve_matcher.py           # three-tier matcher
├── known_firmware.yaml      # curated vuln DB
└── parsers/
    ├── __init__.py          # PARSER_REGISTRY plugin pattern
    ├── base.py              # ParsedBlob dataclass, Parser protocol
    ├── qualcomm_mbn.py      # MBN v3/v5/v6 header + cert chain
    ├── dtb.py               # uses `fdt` pip package
    ├── kmod.py              # pyelftools .modinfo
    ├── broadcom_wl.py       # brcmfmac fingerprints
    ├── cypress_cyw.py       # Cypress/Infineon BT
    ├── elf_tee.py           # OP-TEE, Trusty TAs
    └── raw_bin.py           # entropy + string fallback
```

**Integration point:** in `backend/app/workers/unpack.py`, after `_analyze_filesystem()` succeeds, call `await detect_hardware_firmware(firmware_id, db)` as a post-extraction async step. Wrap sync FS walk in `run_in_executor` per rule #5.

**Parser protocol** (`parsers/base.py`):

```python
class Parser(Protocol):
    FORMAT: str
    def matches(path: Path, magic: bytes) -> bool: ...
    def parse(path: Path) -> ParsedBlob: ...  # dict matching model columns
```

Parsers self-register in `PARSER_REGISTRY` at import time — identical to RTOS detection tiers. New vendor = new file in `parsers/`, no detector changes.

## MCP Tools (6)

| Tool | Description | Input schema |
|---|---|---|
| `list_hardware_firmware` | List all detected blobs. Filterable by category/vendor/signed. | `{category?, vendor?, signed_only?}` |
| `analyze_hardware_firmware` | Deep analysis of one blob: headers, version, signature, chipset target | `{blob_path: str}` |
| `list_firmware_drivers` | Kernel modules + HAL libs and the firmware they request | `{module_pattern?: str}` |
| `find_unsigned_firmware` | Flag blobs with `signed=unsigned` or `signed=unknown`. Fast triage | `{}` |
| `check_firmware_cves` | Run 3-tier CVE matcher, return CVEs with confidence scores | `{force_rescan?: bool}` |
| `extract_dtb` | Parse DTB, emit `compatible_string → driver_module` | `{dtb_path: str}` |

All handlers use `context.resolve_path()` for FS, `context.db.flush()` (not commit) per rule #3, truncate to 30 KB per rule #5.

## Frontend Surface

**Dedicated page: `/projects/:projectId/hardware-firmware`** — `frontend/src/pages/HardwareFirmwarePage.tsx`.

**Rationale for dedicated page (not SBOM tab):** HW firmware has richer per-blob metadata (signatures, chipset targets, driver refs) than fits in SBOM row. Dedicated page is cleaner, matches DeviceAcquisitionPage / SecurityScanPage pattern.

**Layout:**
- **Header row:** firmware selector + stats (total blobs, unsigned, vendors, CVE matches)
- **Left panel (tree):** collapsible by category → vendor → blob with counts. Clicking opens right panel. Matches existing ComponentMap left-panel
- **Right panel (detail):** blob metadata card (path, sha256, size, format, version, signing, chipset) + parsed-header JSON viewer (Monaco read-only) + driver references list with links into ComponentMap + CVE matches if any
- **Secondary tab "Drivers":** flat table of kernel modules / HAL libs with firmware dependencies

**Graph overlay on ComponentMapPage:** toggle "Show firmware edges" that fetches `loads_firmware` edges and overlays. Reuses `ComponentNode` + `ComponentEdge` types. No new renderer.

**New API client:** `frontend/src/api/hardwareFirmware.ts` — `listBlobs`, `getBlob`, `runDetection`, `listDrivers`, `runCveMatch`.

**Sidebar entry:** "Hardware Firmware" between "SBOM" and "Emulation".

## CVE Matching — Three Tiers

All applied, not short-circuited. Confidence attached.

1. **Chipset CPE lookup** — if `chipset_target` known (e.g., `"msm8998"`), query `cpe:2.3:h:qualcomm:sdm865:*` via `cpe_dictionary_service.py`. **Confidence: high** (chipset + version both match) | **medium** (chipset only).
2. **NVD free-text search** — for blobs without CPE, NVD keyword search on `{vendor} {category} firmware` (e.g. `"qualcomm modem firmware"`). Version-substring filter on description. **Confidence: medium** (noisy, flag "needs review").
3. **Curated YAML** (`known_firmware.yaml`) — human-vetted, patterned after `KNOWN_SERVICE_RISKS`. Entries like `{vendor: broadcom, category: wifi, version_regex: "7\.35\..*", cves: [CVE-2017-9417], severity: critical, notes: BroadPwn}`. **Confidence: high**. This tier catches the famous CVE families NVD misses.

Results land in `sbom_vulnerabilities` with `blob_id` set, `component_id = NULL`. Existing `resolution_status` workflow applies unchanged.

## Open Questions

1. **Signature verification scope** — verify against bundled vendor pubkeys, or report `signed=true` based on header flags only? **Recommendation:** header-only in Phase 2; add verification later if requested.
2. **Encrypted blobs** — if `code_size_encrypted` flag set in MBN header, record `encrypted=true` in metadata, skip version extraction. Accept lossy.
3. **Kernel module overlap with SBOM** — `sbom_service._scan_android_components()` already records `.ko` files. **Decision:** keep both, add `sbom_component_id` FK on `HardwareFirmwareBlob` so kernel modules can be joined in UI.
4. **Performance budget** — 5 GB Android images can contain 2K+ firmware blobs. Cap candidate files at 10K, magic-byte read = 64 bytes, skip files <512 bytes and >128 MB. Run detection in `asyncio.create_task` (non-blocking, same pattern as `generate_sbom`).
5. **Extensibility** — parsers/ plugin pattern handles iBoot/IMG4 (next target: Apple's format is well-documented), Cisco IOS, Junos. Classifier takes `platform` hint from `Firmware.os_info` / `device_metadata` JSONB.
6. **License** — qtestsign is GPL-2.0, Wairz is AGPL-3.0. AGPL is GPL-compatible upstream; confirm before vendoring. Fallback options: subprocess or reimplement ~200 LOC header parser.

## Performance Notes

- Magic-byte sniff: 64 bytes per file max
- File size filter: skip <512 bytes and >128 MB
- Hard cap: 10K candidate files per image
- Run as `asyncio.create_task` (non-blocking on unpack completion)
- Benchmark target: 30 seconds for 5 GB image

## Campaign Tracking

Campaign-sized work. Recommend:
- Dedicated campaign file: `.planning/campaigns/hardware-firmware-detection.md`
- Phases 1-5 → campaign phases
- Use `/archon` to orchestrate end-to-end, or `/autopilot` to process phase by phase
- Each phase ships independently with value
