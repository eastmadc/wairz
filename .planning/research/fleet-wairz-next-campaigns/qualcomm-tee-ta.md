# Qualcomm TEE / Trusted Application Parser — Research Brief

> Scout: fleet-wairz-next-campaigns / qualcomm-tee-ta
> Date: 2026-04-17

## Summary

High viability. Wairz already has 80% scaffolding — `qualcomm_mbn.py` parses ELF + hash/sig/cert segments, `elf_tee.py` extracts OP-TEE `.ta_head` UUID, classifier catches `TRUS` (MCLF). Three concrete gaps: (1) interpret MBN `image_id` to split QSEOS (`tz.mbn`) from TAs (`keymaster.mbn`, `widevine.b00/.mdt`), (2) parse OP-TEE `shdr` wrapper (currently only `.ta_head` is read), (3) new MCLF parser for Kinibi with UUID at `0x18`. Two parser edits + one new parser + eight YAML entries + one MCP tool — ~2 sessions.

## Format Reference

### QSEE Trusted Application (Qualcomm)

ELF shared object + Qualcomm program-header segments. Distinguished from `tz.mbn` (QSEOS kernel) by MBN `image_id` (openpst `MbnImageId`):

| `image_id` | Meaning | File hint |
|---|---|---|
| `0x19` (kMbnImageTz) | QSEOS/TZ kernel | `tz.mbn`, `tzbsp.mbn` |
| `0x15`/`0x13`/`0x07`/`0x17`/`0x1A`/`0x1B`/`0x1F` | OS/BL/RPM/misc | sbl1, appsboot, mba, ... |
| other | **Trustlets** | `keymaster.mbn`, `cmnlib*.mbn`, `widevine.b00/.mdt` |

Per arXiv 2507.08331, QSEE TAs ship **split**: `<name>.mdt` carries ELF header (arch at `0x04`, seg-count at `0x2C`/`0x38` for 32/64-bit); `<name>.b00..bNN` hold segments. QC program-header flag mask `0x07000000`: `0x02`=hash, `0x04`=sig, `0x05`=cert — already extracted in `qualcomm_mbn.py`.

**Extractable beyond current parser**: entry function (`CElF_fileinvoke`), command-handler strings (`*_cmd_handler`, `OEMCrypto_*`, `drmprov_*`, `tzcommon_*`, `qsee_app_*`) from ELF strings/`.dynsym`.

### OP-TEE TA (`shdr` wrapper)

Wairz handles only the `.ta_head` ELF-section form. REE-FS-loaded `.ta` files are prefixed by **`struct shdr`**:

```
0x00 u32 magic    = 0x4F545348 ("SHDR" le)
0x04 u32 img_type  0=TA 1=BOOTSTRAP_TA 2=ENCRYPTED_TA 3=SUBKEY
0x08 u32 img_size
0x0C u32 algo      (RSASSA_PKCS1_V1_5_SHA256 = 0x70414930 common)
0x10 u16 hash_size
0x12 u16 sig_size
0x14 hash[hash_size] + sig[sig_size]
```

For `BOOTSTRAP_TA`: `uint8_t uuid[16]` + `uint32_t ta_version` follow. For `ENCRYPTED_TA`: `enc_algo`, `flags`, `iv_size`, `tag_size`.

### Kinibi MCLF (Samsung Exynos / MediaTek legacy)

Detected but **not parsed**. Header (`mclfHeaderV2_t`):

```
0x00 u32 magic = "MCLF" (0x4D434C46 BE)
0x04 u32 version (major=2, minor<5)
0x08 u32 flags          0x0C u32 memType
0x10 u32 serviceType    0=ILLEGAL 1=DRIVER 2=SP_TRUSTLET 3=SYSTEM_TRUSTLET 4=MIDDLEWARE
0x14 u32 numInstances
0x18 u8  uuid[16]       <-- primary extract
0x28 u32 driverId       0x2C u32 numThreads
0x30 8B  text seg       0x38 8B  data seg
0x40 u32 bssLen         0x44 u32 entry
0x48 u32 serviceVersion
0x4C u32 permittedSuid  0x50 u32 permittedHwCfg  (v2.3 only)
```

V1=72B, V2=76B, V2.3=128B. Typically `<uuid>.tlbin` under `mcRegistry/`.

### TEEGRIS (Samsung post-Kinibi, S10+)

No public spec. ELF-like; `.tzapp` or `.elf` under `/vendor/tee/`, `/system/tee/`. Extract filename-UUID + ELF imports only; flag `format=teegris_ta` with low confidence.

## Recent Vulnerability Research (2024-2026)

- **arXiv 2507.08331** (Jul 2025): QSEE TA emulator (LIEF + Unicorn). Rediscovers CVE-2021-0592 OOB write in `decrypt_CTR_unified` via command-handler fuzzing. Code: `github.com/hanhan3927/usenix2025-qualcomm-trusted-application-emulation-for-fuzzing-testing`. Reusable: `.mdt`/`.b0x` merge logic, cmd-handler string heuristic.
- **CVE-2025-47372** (Qualcomm Dec 2025): critical boot-ELF OOB write; `image_size` unvalidated. Cheap heuristic: `image_size > file size`.
- **CVE-2025-47373**: TEE buffer overflow on TA-invocation shared-mem IPC (invalid length).
- **CVE-2025-47325**: TrustZone untrusted pointer deref.
- **CVE-2025-47319**: TA-to-TA interfaces leaked to HLOS (CWE-497).
- **CVE-2020-11298/11306/11284/11304**: QTEE TOCTOU, RPMB integer overflow, boundary errors, DRM OOB-read. Common in pre-2021 firmware.
- **Check Point 2019** "Road to Qualcomm TrustZone Apps Fuzzing": canonical QSEE harness reference; confirms `qsee_load_and_auth_elf_image` + `tzbsp_pil_init_image`.
- **Quarkslab Samsung deep-dive Part 1+2**: confirms MCLF layout.

## OSS Tooling

1. **qtestsign** (msm8916-mainline, GPL-2.0, Python): validates our `_QC_SEG_*` constants. Logic-only reference.
2. **openpst/libopenpst** (`include/qualcomm/mbn.h`, BSD-ish, C): canonical `MbnImageId` enum (0x00–0x1F). **Transcribe** into `qualcomm_mbn.py` as dict.
3. **OP-TEE/optee_os** (`core/include/signed_hdr.h`, BSD-2): `shdr` struct reference. **Transcribe layout**; do not vendor.
4. **NeatMonster/mclf-ghidra-loader** + **ghassani/mclf-ida-loader**: MCLF loaders; use for cross-checking offsets.
5. **hanhan3927/usenix2025-…**: arXiv companion code, license unclear. **Re-implement** `.mdt`/`.b0x` merge heuristic; don't vendor.
6. **sbaresearch/mbn-mcfg-tools**: MCFG-only. **Skip**.
7. **quarkslab/QBDL**: generic dynamic linker despite the "QBDL" name — **not** a QSEE tool. **Skip**.
8. **enovella/TEE-reversing**: link index only. **Cite as docs**.

## Integration into Wairz

All paths under `/home/dustin/code/wairz/`.

**Session 1 — parsers (~300 LOC):**

- `backend/app/services/hardware_firmware/parsers/qualcomm_mbn.py` (+60 LOC): add `_MBN_IMAGE_ID_NAMES` dict (0x00–0x1F); set `metadata["image_id_name"]` + `metadata["is_trustlet"] = image_id not in {0x07,0x13,0x15,0x17,0x19,0x1A,0x1B,0x1F}`. Scan ELF strings/`.dynsym` for `*_cmd_handler`, `OEMCrypto_*`, `qsee_app_*`, `widevine_*`; store up to 32 in `metadata["ta_handlers"]`.
- `backend/app/services/hardware_firmware/parsers/elf_tee.py` (+80 LOC): pre-check SHDR magic `0x4F545348` at offset 0; parse `img_type`/`img_size`/`algo`/hash/sig sizes; for BOOTSTRAP_TA pull UUID + `ta_version`; slice past header and reparse remainder as ELF. Emit `metadata["optee_img_type"]`, `metadata["signed_wrapper"]="shdr"`.
- `backend/app/services/hardware_firmware/parsers/kinibi_mclf.py` (new, ~120 LOC): parse 72/76/128B header; extract UUID (0x18), service_type, version, entry, text/data segs. Register for `kinibi_mclf`.
- **Do not** create `qualcomm_qsee_ta.py`; specialization is a metadata flag only.

**Session 2 — classifier + YAML + MCP (~150 LOC):**

- `classifier.py` (+30 LOC): add `system/app/mcRegistry/`, `vendor/app/mcRegistry/`, `/system/vendor/tee/`, `/vendor/tee/` to `_FIRMWARE_PATH_SIGNALS`. Add SHDR-magic branch in `_classify_by_magic`. Return `"tee"` from `_category_from_qcom_name` for `widevine*`, `playready*`, `drmclearkey*`.
- `known_firmware.yaml`: add 7 entries below.
- New `backend/app/ai/tools/tee.py` (~100 LOC): MCP tool `analyze_ta_security`; runs new YARA rules (`backend/app/services/hardware_firmware/data/ta_rules.yar`) over TA blobs; reports handlers + `image_id_name` + protections.

**Total**: ~500 LOC, 1 YAR file, 1 MCP tool, 2 sessions. No schema migrations.

## New YAML CVE Families Proposed

```yaml
- name: Qualcomm TEE TA-invocation buffer overflow (Dec 2025)
  vendor: qualcomm
  category: tee
  cves: [CVE-2025-47373]
  severity: high
  cvss_score: 8.4
  notes: |
    Qualcomm Dec 2025 bulletin. Memory corruption when TA
    validates buffer lengths during invocation. Broad impact.

- name: Qualcomm TA-to-TA HLOS exposure (Dec 2025)
  vendor: qualcomm
  category: tee
  cves: [CVE-2025-47319]
  severity: medium
  cvss_score: 6.7
  notes: |
    CWE-497. TA-to-TA interfaces reachable from HLOS.
    Info disclosure across TrustZone boundary.

- name: Qualcomm TrustZone untrusted pointer deref (2025)
  vendor: qualcomm
  category: tee
  cves: [CVE-2025-47325]
  severity: medium
  cvss_score: 6.5

- name: Qualcomm Secure Boot ELF OOB write (2025)
  vendor: qualcomm
  category: bootloader
  cves: [CVE-2025-47372]
  severity: critical
  cvss_score: 9.8
  notes: |
    Boot-time ELF image_size unvalidated; oversized image
    causes OOB write pre-verified-boot. Detect heuristically
    by image_size > file size in MBN header.

- name: QTEE early-era cluster (2020)
  vendor: qualcomm
  category: tee
  cves:
    - CVE-2020-11298  # TOCTOU
    - CVE-2020-11306  # RPMB integer overflow
    - CVE-2020-11284  # boundary error
    - CVE-2020-11304  # OOB read in DRM content protection
  severity: high
  cvss_score: 7.8
  notes: |
    Qualcomm Jan 2021 bulletin set. TOCTOU, integer overflow,
    boundary errors in QTEE. Affects pre-2021 firmware widely.

- name: QSEE Widevine decrypt_CTR OOB (rediscovered 2025)
  vendor: qualcomm
  category: tee
  version_regex: "(?i).*widevine.*"
  cves: [CVE-2021-0592]
  severity: high
  cvss_score: 7.8
  notes: |
    OOB write in decrypt_CTR_unified(). Reached via Widevine
    TA command handler. Rediscovered by arXiv 2507.08331
    emulation fuzzer (2025).

- name: Kinibi TA exploitation cluster
  vendor: samsung
  category: tee
  version_regex: "(?i).*(kinibi|mobicore|trustonic|mclf).*"
  cves: [CVE-2019-20566, CVE-2018-13903]
  severity: high
  cvss_score: 7.5
  notes: |
    Synacktiv + Blue Frost 2019. Pre-TEEGRIS Samsung /
    Mediatek. Matches MCLF blobs in mcRegistry paths.
```

## Dead Ends

- **QBDL** — generic dynamic linker, not a QSEE tool. Skip.
- **TEEGRIS full parser** — undocumented; do filename-UUID only until format reference exists.
- **Merging `.mdt`+`.b0x` pre-parse** — doubles classifier complexity. Parse each independently; correlate by stem in UI.
- **SHDR signature verification** — needs per-device OP-TEE pubkey; mark `signed=claimed` without crypto-verify.
- **Reusing `scan_with_yara` as-is** — existing rules target Linux userland; build small TA-specific ruleset.

## Confidence

**High** for QSEE `image_id`, OP-TEE `shdr`, MCLF — canonical sources (openpst, optee_os, Trustonic). **Medium** for TA command-handler extraction (OEM string heuristics). **Low** for TEEGRIS. Scope matches Phase-3 MediaTek/Awinic expansion; no DB schema migration needed.

## References

1. https://arxiv.org/abs/2507.08331 — Fan/Chang/Shie, Qualcomm TA Emulation for Fuzzing (Jul 2025)
2. https://arxiv.org/html/2507.08331v1 — HTML version with `.mdt`/`.b0x` format details
3. https://research.checkpoint.com/2019/the-road-to-qualcomm-trustzone-apps-fuzzing/ — Check Point, canonical QSEE harness reference
4. https://bits-please.blogspot.com/2016/04/exploring-qualcomms-secure-execution.html — Beniamini, QSEE internals
5. https://raw.githubusercontent.com/OP-TEE/optee_os/master/core/include/signed_hdr.h — OP-TEE `shdr` struct
6. https://raw.githubusercontent.com/openpst/libopenpst/master/include/qualcomm/mbn.h — openpst MbnImageId enum
7. https://raw.githubusercontent.com/Trustonic/trustonic-tee-user-space/master/common/MobiCore/inc/mcLoadFormat.h — MCLF layout
8. https://blog.quarkslab.com/a-deep-dive-into-samsungs-trustzone-part-1.html — Samsung TEE deep-dive
9. https://blog.quarkslab.com/a-deep-dive-into-samsungs-trustzone-part-2.html — Samsung TEE Part 2
10. https://github.com/msm8916-mainline/qtestsign — qtestsign (signing tool, GPL-2.0)
11. https://github.com/NeatMonster/mclf-ghidra-loader — MCLF Ghidra loader
12. https://github.com/enovella/TEE-reversing — TEE reversing resource index
13. https://docs.qualcomm.com/securitybulletin/december-2025-bulletin.html — Dec 2025 security bulletin (CVE-2025-47319/25/72/73)
14. https://www.synacktiv.com/en/publications/kinibi-tee-trusted-application-exploitation — Synacktiv Kinibi exploitation
15. https://raelize.com/blog/qualcomm-ipq40xx-analysis-of-critical-qsee-vulnerabilities/ — IPQ40xx QSEE analysis
