# MediaTek Firmware Parsing — OSS Tool Shortlist

> Extracted: 2026-04-17
> Source: Session 41 research scout 1 — MediaTek-specific tooling
> Used by: `feature-hw-firmware-phase2-enrichment.md` intake
> Context: first real Android upload (MediaTek MT6771 / Helio P60) produced 244 blobs with Vendor=None and 0 CVEs. This scout surveys MediaTek-specific OSS that fills those gaps.

## Top 3 High-ROI Integrations

### A. NCC Group `mtk_bp` + Kaitai structs (md1img / md1dsp / debug info)
- Repo: https://github.com/nccgroup/mtk_bp — GPL-3.0
- Contains `md1_extract.py`, `md1rom_info.py`, and `.ksy` files (`md1img.ksy`, `mtk_dbg_info.ksy`, `mtk_img.ksy`).
- Emits per-section `addr`, `size`, `name` for `md1rom`, `md1drdi`, `md1dsp`, certs, debug sections.
- **Approach:** vendor the `.ksy` files, compile to Python via `kaitai-struct-compiler` (~400 LOC generated; Kaitai runtime is MIT, clean license). New service `backend/app/services/hardware_firmware/parsers/mediatek_md1img.py`.
- **License:** GPL-3 → AGPL-3 compatible if we vendor scripts; Kaitai compiled output is cleaner.

### B. `md1imgpy` pip dependency (md1img parsing with library API)
- Repo: https://github.com/R0rt1z2/md1imgpy — GPL-3.0, pip-installable
- `pip3 install git+https://github.com/R0rt1z2/md1imgpy` — CLI + Python library. Handles gzip/xz compressed sections.
- **Approach:** add to `pyproject.toml`, ~50 LOC wrapper to emit `{section_name, offset, size, compression}` tuples.
- **Gotchas:** no `md1dsp.img` support (use `mtk_bp` for DSP).

### C. mt76 driver header structs for Wi-Fi firmware (WIFI_RAM_CODE_*)
- Source: https://github.com/openwrt/mt76 + `drivers/net/wireless/mediatek/mt76/` — GPL-2.0
- `_hdr`-suffix files carry structured headers (build timestamp, build identifier, version string, size/offset table). Non-`_hdr` files are raw NDS32 payloads.
- **Approach:** reference-only — write ~150 LOC native Python parser based on `mt7615/mcu.h`, `mt7921/mcu.h`, `mt792x.h`. Copying struct layouts is fair use.
- **Per-chip variation:** MT7615 "ROM patch", mt7915-style "firmware_trailer", mt7921/7961/7925 "connac2_fw_trailer". Non-`_hdr` raw files → filename→chipset lookup only.

## Reference-Only

| Project | License | Use |
|---|---|---|
| bkerler/mtkclient | GPL-3.0 | Port ~100-200 LOC of `mtk_preloader.py` GFH parsing; don't import full tree (pyusb, capstone, keystone). |
| cyrozap/mediatek-lte-baseband-re | GPL-3.0 / CC-BY-SA-4.0 | Vendor `SoC/mediatek_preloader.ksy` + `SoC/mediatek_download_agent.ksy` (~200 LOC generated). Canonical GFH/preloader layout. |
| u-boot/tools/mtk_image.c | GPL-2.0 | Canonical reference for GFH_FILE_INFO, GFH_BL_INFO, GFH_BROM_CFG, LK header. Validate fields; don't vendor. |
| linux-firmware mediatek/ tree | per-file | Known-good samples for pattern-matching + golden version strings. |
| Awinic aw88xxx ACF | GPL-2.0 | Kernel `sound/soc/codecs/aw88*/` has `aw_dev_load_cfg_by_hdr()` / `aw_dev_load_cfg_by_hdr_v1()`. Port ~80 LOC for chip profile + sample rate + version. |

## Dead Ends

- **FirmWire** (BSD-3) — targets modem emulation, not offline introspection.
- **MTK-bypass/bypass_utility** (MIT) — pure BROM exploit, no file-format knowledge.
- **AndroidDumps/Firmware_extractor** (GPL-3.0) — shell-driven OEM archive unpacker; no MediaTek-specific extractors beyond top-level archive detection.
- **payload-dumper-go** — A/B OTA payload.bin only.
- **BT_FW.cfg / connfem.cfg** — no public OSS parser. Parse as heuristic key=value.

## WIFI_RAM_CODE_6759 — specific finding

"6759" in `WIFI_RAM_CODE_6759` names the **MT6759 connectivity combo** (Wi-Fi/BT/FM/GPS WMT block), NOT the application processor. The MT6759 connsys is paired with APs: MT6763, MT6765, MT6771 (Helio P60), MT6779. Our test device (MT6771) uses MT6759 connectivity.

On-disk format: raw NDS32 code/data segments, obfuscated, no structured header. EFUSE-decrypted by BROM. `_hdr`-suffixed siblings carry ASCII build timestamp (14-digit YYYYMMDDHHMMSS) at 0x20-0x40 from EOF.

**Recommended Wairz behavior:** emit `{chipset: "MT6759", role: "wifi_rom_patch", ap_family: "MT6771/MT6763/MT6765/MT6779", format: "raw NDS32, obfuscated"}`; scan for embedded ASCII build timestamps + strings; mark as opaque with chipset attribution.

## Estimated Build Time

| Task | Effort |
|---|---|
| Vendor cyrozap `.ksy` → compiled Python (preloader + GFH) | 1 day |
| Add `md1imgpy` OR vendor nccgroup/mtk_bp (md1img/md1dsp) | 1 day |
| Native mt76 header parser + chipset map for non-`_hdr` | 2 days |
| LK header parser (LK_PART_MAGIC 512-byte records) | 2 hours |
| AWINIC ACF parser (port kernel ASoC logic) | 1 day |
| **Total** | **~5 days** |

## Key Sources

- [nccgroup/mtk_bp](https://github.com/nccgroup/mtk_bp)
- [R0rt1z2/md1imgpy](https://github.com/R0rt1z2/md1imgpy)
- [cyrozap/mediatek-lte-baseband-re](https://github.com/cyrozap/mediatek-lte-baseband-re)
- [cyrozap/mediatek-wifi-re](https://github.com/cyrozap/mediatek-wifi-re)
- [openwrt/mt76 driver](https://github.com/openwrt/mt76)
- [u-boot mtk_image.c](https://github.com/u-boot/u-boot/blob/master/tools/mtk_image.c)
- [linux-firmware mediatek tree](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/mediatek)
- [Awinic AW883xx driver patches](https://patchew.org/linux/20230106032835.141918-1-wangweidong.a@awinic.com/)
- [bkerler/mtkclient](https://github.com/bkerler/mtkclient)

## Notable

Public unblob does NOT ship MediaTek/Qualcomm preloader/MBN handlers — those are in OneKey's closed proprietary layer. **Wairz would contribute to the SOTA by open-sourcing MediaTek handlers here.**
