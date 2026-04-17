# Android Hardware Firmware — Tool & Library Shortlist

> Extracted: 2026-04-16
> Source: Session 40 research scout 2 (parsing tools & libraries)
> Used by: `feature-android-hardware-firmware-detection.md` intake

## Final Shortlist

### Pip-installable (no subprocess)

1. **`fdt`** (molejar/pyFDT) — pure-Python DTB parsing, Apache-2.0, active. **Highest ROI.**
2. Vendor **`qtestsign` MBN module** from [msm8916-mainline/qtestsign](https://github.com/msm8916-mainline/qtestsign) — ~500 LOC Python, GPL-2.0, relicense-check for AGPL-3.0 compat
3. Vendor **`avbtool.py`** from AOSP external/avb — Apache-2.0, safe to vendor. Canonical AVB 2.0 parser.
4. Kaitai-generated **`broadcom_trx.py`** (MIT) — for .trx containers

### Subprocess tools (add to `backend/Dockerfile`)

1. **`pil-squasher`** (apt `pil-squasher` on Debian) — converts `.mdt + .bXX` → single `.mbn`. 200 LOC C, GPL-2.0. Use before LIEF.
2. **`device-tree-compiler`** (apt) — `dtc` fallback for exotic DTBs
3. **`payload-dumper-go`** (Go single binary, Apache-2.0) — fastest OTA extraction
4. **`Firmware_extractor`** ([AndroidDumps/Firmware_extractor](https://github.com/AndroidDumps/Firmware_extractor)) — shell, handles Android-specific containers (OZIP, UPDATE.app, sin, ruu)

### Ghidra extensions

1. **`ghidra-hexagon-sleigh`** ([CUB3D/ghidra-hexagon-sleigh](https://github.com/CUB3D/ghidra-hexagon-sleigh)) — SLEIGH spec, MIT. **Unlocks Qualcomm DSP/modem/TZ decompilation** via existing `ghidra_service.py`.

### Reference-only / detect-and-flag

- **TEEGRIS, Kinibi (MCLF)** — format recognition only, no open parsers
- **FirmWire** ([FirmWire/FirmWire](https://github.com/FirmWire/FirmWire)) — emulator, link in findings
- **Shannon BTL logs** — link research

## Per-Category Tool Details

### 1. Qualcomm Firmware (MBN/MDT/.bXX)

| Tool | License | Language | Integration |
|---|---|---|---|
| [linux-msm/pil-squasher](https://github.com/linux-msm/pil-squasher) | GPL-2.0 | C | subprocess (200 LOC) |
| [remittor/qcom-mbn-tools pil-splitter.py](https://github.com/remittor/qcom-mbn-tools) | MIT-ish | Python | vendor (~300 LOC) |
| [laginimaineb/unify_trustlet](https://github.com/laginimaineb/unify_trustlet) | - | Python | reference |
| **[msm8916-mainline/qtestsign](https://github.com/msm8916-mainline/qtestsign)** | GPL-2.0 | Python 3 | **Most Python-friendly — parse MBN v3/v5/v6 headers** |
| [sbaresearch/mbn-mcfg-tools](https://github.com/sbaresearch/mbn-mcfg-tools) | - | Python | Modem Configuration (MCFG) segments |
| LIEF (already in Wairz) | Apache-2.0 | Python | ELF skeleton only (misses QC hash segment + cert chain) |

**Hexagon DSP (QDSP6) decompilation:**

| Tool | Notes |
|---|---|
| [programa-stic/hexag00n](https://github.com/programa-stic/hexag00n) | Python 2/3, BSD, stale (~2018), functional |
| [darkparticlelabs/hexagon_disasm](https://github.com/darkparticlelabs/hexagon_disasm) | Python, dumps Hexagon code |
| **[CUB3D/ghidra-hexagon-sleigh](https://github.com/CUB3D/ghidra-hexagon-sleigh)** | **Best option — Ghidra ext, MIT** |
| [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) | IDA-only, not useful |

**Extractable metadata:** MBN header version, image_id (maps to `sbl1`/`tz`/`modem`/`adsp`/etc.), signature algorithm, cert chain (X.509 DER), hash segment SHA-256s, entry point, load addresses.

### 2. TrustZone / TEE

**QSEE (Qualcomm `tz.mbn`):**
- Signed ELF + QC hash segment — same path as §1
- TAs are nested ELFs in `/firmware/image/*.mdt` — extract with pil-squasher + LIEF
- Reference: [Gal Beniamini "Bits, Please!"](http://bits-please.blogspot.com/2015/08/exploring-qualcomms-trustzone.html), [Check Point 2019 QSEE paper](https://research.checkpoint.com/2019/the-road-to-qualcomm-trustzone-apps-fuzzing/)

**Trustonic Kinibi** (older Samsung/MediaTek/Huawei):
- MCLF (Mobicore Loadable Format) — proprietary
- No Python parser — reimplement ~100-byte header struct via `kaitai-struct` spec
- Reference: [Azeria Labs Kinibi](https://azeria-labs.com/trustonics-kinibi-tee-implementation/)

**Samsung TEEGRIS** (S10+): proprietary 64-bit, no public parser. **Detect-and-flag only.** Reference: [Quarkslab Samsung TrustZone](https://blog.quarkslab.com/a-deep-dive-into-samsungs-trustzone-part-1.html), Blackhat 2019 Peterlin.

**OP-TEE** (ARM reference): ELF + signed `.ta` files. Parse with LIEF + small TA-header reader.

**Master reference:** [enovella/TEE-reversing](https://github.com/enovella/TEE-reversing) — curated list of ALL TEE RE resources.

**Integration plan:** `tee_service.py`:
1. Detect flavor by FS heuristics (`tz.mbn` → QSEE; `tzar`/`teegris` → TEEGRIS; `mobicore*` → Kinibi; `tee-supplicant`/`optee` → OP-TEE)
2. QSEE + OP-TEE: extract TA list, LIEF-parse each
3. Kinibi/TEEGRIS: metadata only + finding with research link

### 3. Device Tree Blob (DTB)

| Lib | PyPI | License | Status |
|---|---|---|---|
| **`fdt`** (molejar/pyFDT) | `fdt` | Apache-2.0 | **Recommended — active, Python-pure, dtb↔dts roundtrip, dict tree access** |
| `pyfdt` (superna9999) | `pyfdt` | ISC | Stale (2016) |
| `pydevicetree` (sifive) | `pydevicetree` | Apache-2.0 | Parses DTS source, not DTB |
| libfdt Python bindings | bundled with dtc | GPL-2.0+ | C-binding install pain |

**Driver → firmware mapping:** Walk nodes, collect `compatible` + `firmware-name` + `fsl,*-fw` vendor properties. These map directly to `.bin` files in `/lib/firmware/` or `/vendor/firmware/`. **Highest-value metadata layer.**

```python
import fdt
dtb = fdt.parse_dtb(open("platform.dtb", "rb").read())
# dtb.root.nodes[0].props → compatible strings, reg addresses, firmware-name
```

CLI fallback: `dtc` (apt `device-tree-compiler`).

### 4. Modem / Baseband

**Posture: detect, extract strings, link to research — don't try to fully parse.**

- **[FirmWire](https://github.com/FirmWire/FirmWire)** — Python 3, BSD-3, active (NDSS '22). Full-system emulator for Shannon + MediaTek. Has `modkit/` scripts that parse modem.bin. **Integration: subprocess for parsing only** — import `firmwire.loader.shannon` + `firmwire.loader.mtk` as libs.
- **[ShannonBaseband](https://github.com/grant-h/ShannonBaseband)** — Python + Ghidra. Raw modem.bin extraction scripts + BTL parser. **Vendor the extraction script.**
- `shannon_modem_loader` — IDA 8/9 only
- MediaTek: `mtk_fw_tools` handles packaging only; FirmWire's MTK loader for modem.img
- Quectel/Huawei/ZTE: no general-purpose parser — fingerprint inside archive, dispatch

**Without full parsing:** strings sweep for version tags (`Shannon`, `S5000AP`, `MOLY.LR13`), timestamps, carrier profile names.

### 5. Wi-Fi / Bluetooth Firmware

- **[Nexmon](https://github.com/seemoo-lab/nexmon)** — C + Python, GPL-2.0. Patching framework for Broadcom/Cypress Wi-Fi. Reference for firmware layouts per chipset.
- **[InternalBlue](https://github.com/seemoo-lab/internalblue)** — Python 3, GPL-2.0. Parses Broadcom/Cypress BT firmware (ROM + patches + HCI logs). **Import `internalblue.fw` modules.**
- **[qca-swiss-army-knife](https://github.com/qca/qca-swiss-army-knife)** — Python, ISC. Encodes/decodes Atheros `ath10k`/`ath11k` Wi-Fi firmware + board-data. **Subprocess.**
- `mt76` firmware: no OSS extractor beyond linux-firmware. Strings only.
- Broadcom .trx: [Kaitai Struct spec](https://formats.kaitai.io/broadcom_trx/python.html) — generates pure-Python parser

### 6. Kernel Modules (.ko)

**Already solved with libraries Wairz uses.** Pure Python, no subprocess:

```python
from elftools.elf.elffile import ELFFile
with open("driver.ko", "rb") as f:
    elf = ELFFile(f)
    modinfo = elf.get_section_by_name(".modinfo").data()
    pairs = [kv.decode() for kv in modinfo.split(b"\x00") if b"=" in kv]
    firmware_deps = [v.split("=", 1)[1] for v in pairs if v.startswith("firmware=")]
```

`.modinfo` is always `key=value\0` pairs. Extract: `firmware=`, `license=`, `version=`, `srcversion=`, `depends=`, `vermagic=`, `alias=`. LIEF works equivalently.

### 7. Generic Firmware Identification

Wairz already covers this with binwalk3 + unblob. Context:
- **unblob** is better active project — Rust backend, 78+ formats
- **binwalk v3** has wider magic coverage, narrower extraction quality
- **EMBA** — orchestration only, don't integrate (scope overlap)
- **[Firmware_extractor](https://github.com/AndroidDumps/Firmware_extractor)** — fills Android gaps (OZIP, UPDATE.app, sin, ruu)
- **[payload-dumper-go](https://github.com/ssut/payload-dumper-go)** — fastest OTA `payload.bin` extractor (Go)

### 8. Signature / Verification

- **[AOSP avbtool.py](https://android.googlesource.com/platform/external/avb/)** — Python 3, Apache-2.0. **Canonical** AVB 2.0 parser. **Vendor into Wairz.**
- **[avbroot](https://github.com/chenxiaolong/avbroot)** — Rust, GPL-3.0. A/B OTA re-signer.
- Qualcomm sig check: qtestsign decodes hash segment + cert chain but does NOT verify against QC roots (proprietary)
- MediaTek BROM sigs: no OSS verifier
- X.509 extraction from signed sections: LIEF + `cryptography` (`x509.load_der_x509_certificate`)

### 9. Metadata Extraction Matrix

| Vendor | Version | Build timestamp | Chipset | Signature | CVE |
|---|---|---|---|---|---|
| Qualcomm MBN | qtestsign header | strings | image_id | LIEF + qtestsign cert chain | CPE `qualcomm:*` from image_id |
| Samsung Shannon | FirmWire loader (TOC) | embedded strings | device model in TOC | proprietary | MOLY version → CVEs |
| MediaTek preloader | strings (`MT67xx`, `BUILD_TIME`) | strings | direct | proprietary BROM | CPE `mediatek:*` via chipset |
| DTB | n/a | n/a | `model`, `compatible` | unsigned | `compatible` → driver CVEs |
| .ko | `.modinfo version=` | `.modinfo srcversion=` | `.modinfo vermagic=` | module sig appendix (CMS) | `depends=` for kernel CVE chains |
| AVB vbmeta | descriptor | n/a | partition names | avbtool verify | rollback_index |
| OP-TEE TA | UUID in header | build tag | n/a | signed via TA key | TA UUID → advisory |

## Wairz Hook Points

- **DTB parsing** → new `dtb_service.py`, invoked from `unpack_android.py` + `firmware_metadata_service.py`
- **MBN/Hexagon** → extend `binary_analysis_service.py` with Qualcomm path; extend `ghidra_service.py` to load Hexagon extension
- **VBMeta** → new `avb_service.py`, hooks into `update_mechanism_service.py` / `manifest_checks.py`
- **Kernel `.ko` modinfo** → already possible with pyelftools; add MCP tool `get_kernel_module_info`
- **Android containers (OZIP/UPDATE.app/payload.bin)** → extend `unpack_android.py` to try `Firmware_extractor` + `payload-dumper-go` before/after unblob
