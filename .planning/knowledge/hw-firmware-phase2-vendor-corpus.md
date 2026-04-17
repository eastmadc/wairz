# Filename-to-Chipset Mapping — OSS Corpora

> Extracted: 2026-04-17
> Source: Session 41 research scout 3 — vendor chip ID corpora
> Used by: `feature-hw-firmware-phase2-enrichment.md` intake
> Context: Phase 1 classifier hand-rolled ~14 regexes → 244 blobs, 0 vendors resolved. This scout finds data-driven sources to replace hard-coded patterns.

## Top 3 Data Sources

### 1. linux-firmware WHENCE file (authoritative, machine-readable)
- URL: `https://gitlab.com/kernel-firmware/linux-firmware` (upstream; replaced GitHub/kernel.org mirror in 2024)
- Plain text, one block per driver:
  - `Driver:` — driver name
  - `File:` — firmware filename(s)
  - `Version:` — build version if known
  - `Info:` — freeform description
  - `Licence:` — redistribution terms
- **License:** Mixed per entry; WHENCE itself is freely parseable. Redistribution of metadata is fine.
- **Coverage:** native for mt76xx, mt7601u, iwlwifi, rtl8xxx, brcmfmac, qcom/venus, ath10k/11k. Weak on Android vendor-specific blobs (WIFI_RAM_CODE_*, aw88*, goodix_*, pn553_* live in AOSP vendor trees, not upstream).

### 2. Linux kernel `Documentation/devicetree/bindings/vendor-prefixes.yaml`
- URL: https://raw.githubusercontent.com/torvalds/linux/master/Documentation/devicetree/bindings/vendor-prefixes.yaml
- License: `GPL-2.0 OR BSD-2-Clause` (explicitly redistributable)
- ~2000 entries: `awinic` → "Shanghai Awinic Technology Co., Ltd.", `goodix` → "Shenzhen Huiding Technology", `invensense`, `bosch`, `sensortek`, `himax`, `focaltech`, `elan`, `nxp`, `ti`, `cypress`, `realtek`, `broadcom`, `mediatek`, `qcom`, `samsung` — all normative.
- This is exactly what Wairz's `VENDORS` set should be, sourced upstream.

### 3. LineageOS `proprietary-files*.txt` corpus — Android-specific gap-filler
- URL: hundreds of `https://github.com/LineageOS/android_device_*` repos, e.g. `android_device_google_lynx/proprietary-files-vendor.txt`
- License: Apache-2.0 on the manifest files themselves
- Format: `path/to/blob.bin` with `# Category` comments (Firmware, Radio, NFC, Camera, Audio, Sensors)
- Covers the Android-vendor blobs WHENCE is missing: WIFI_RAM_CODE_*, camera ISP, audio SmartPA (aw*), fingerprint/touch, NFC (pn5*, sn1*). Cross-referencing 50-100 of these files gives a crowd-sourced filename→category mapping per chipset family.

## Concrete Recommendation — Two-Layer YAML

Replace hand-rolled regexes in `backend/app/services/hardware_firmware/classifier.py` with:

```
backend/app/services/hardware_firmware/data/
  vendor_prefixes.yaml        # mirrored from kernel vendor-prefixes.yaml, slimmed
  firmware_patterns.yaml      # hand-curated + auto-generated from WHENCE + Lineage
```

`firmware_patterns.yaml` schema (prefix-match, ordered, first-wins):

```yaml
- pattern: "^aw88[0-9a-z]+_.*\\.bin$"
  vendor: awinic
  product: "AW88xxx Smart PA audio amplifier"
  category: audio
  source: awinic-driver/aw883xx_patch
- pattern: "^WIFI_RAM_CODE_MT([0-9]+).*"
  vendor: mediatek
  product_template: "MT${1} Wi-Fi firmware"
  category: wifi
  source: cyrozap/mediatek-wifi-re
- pattern: "^mt66[0-9]{2}_(fm|bt|wmt)_.*\\.(bin|cfg)$"
  vendor: mediatek
  product: "MT66xx connectivity combo (WiFi/BT/FM/GPS)"
  category: wifi
- pattern: "^bmi(160|260|270)_.*\\.ko$"
  vendor: bosch
  product: "BMI${1} IMU / accelerometer"
  category: sensor
- pattern: "^icm(426|427)[0-9]{2}_.*\\.ko$"
  vendor: invensense
  product: "ICM-${1}xx 6-axis IMU"
  category: sensor
- pattern: "^stk3x1x.*\\.ko$"
  vendor: sensortek
  product: "STK3x1x ambient light / proximity sensor"
  category: sensor
- pattern: "^pn5(53|57|60|61)_.*"
  vendor: nxp
  product: "PN5${1} NFC controller"
  category: nfc
- pattern: "^(tps65987|ccg[0-9]+).*"
  vendor: ti
  product: "USB Type-C PD controller"
  category: usb
- pattern: "^mali_kbase_mt([0-9]+)_.*\\.ko$"
  vendor: arm
  product: "Mali GPU kbase (on MediaTek MT${1})"
  category: gpu
- pattern: "^camera_dip_isp[0-9]+\\.ko$"
  vendor: mediatek
  product: "MediaTek ISP (DIP) camera subsystem"
  category: camera
```

A ~100 LOC bootstrap script scrapes WHENCE + 50-100 LineageOS `proprietary-files*.txt` → auto-generated portion. Hand-curated head for long-tail chipsets (sensors, touch, PD) where WHENCE is silent.

**There is no "firmware zoo with labeled metadata"** — FirmAE (1124 images) and WUSTL-CSPL datasets label whole images by vendor/arch, not per-blob by chipset. BugProve/EMBA don't publish training corpora. LineageOS trees are the best aggregate.

## Walkthrough: `aw883xx_acf.bin`

1. Lowercase filename, strip path
2. Iterate `firmware_patterns.yaml`; `^aw88[0-9a-z]+_.*\.bin$` matches
3. Return `{vendor: "awinic", product: "AW88xxx Smart PA audio amplifier", category: "audio", confidence: "high"}`
4. Cross-reference `vendor_prefixes.yaml`: `awinic` → "Shanghai Awinic Technology Co., Ltd."
5. `_acf` suffix (stored in optional `variant_suffixes` table) flags as "acoustic calibration file," distinct from `_fw.bin` boot firmware

## Repos & Licenses

| Source | URL | License |
|---|---|---|
| linux-firmware WHENCE | https://gitlab.com/kernel-firmware/linux-firmware | per-entry |
| DT vendor-prefixes | https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/vendor-prefixes.yaml | GPL-2 OR BSD-2 |
| LineageOS device trees | https://github.com/LineageOS/android_device_* | Apache-2.0 |
| Awinic drivers | https://github.com/awinic-driver/aw883xx_patch | GPL-2.0 |
| MediaTek Wi-Fi RE | https://github.com/cyrozap/mediatek-wifi-re | BSD / research |
| android-prepare-vendor | https://github.com/anestisb/android-prepare-vendor | GPL-3.0 |
| J's Android Device DB | https://newandroidbook.com/ddb/ | Mixed / attribution |

## Wairz Files Touched

- `backend/app/services/hardware_firmware/classifier.py` — replace regexes with YAML lookup
- NEW `backend/app/services/hardware_firmware/data/firmware_patterns.yaml`
- NEW `backend/app/services/hardware_firmware/data/vendor_prefixes.yaml`
- NEW `backend/app/services/hardware_firmware/patterns_loader.py` — parses YAML, builds compiled regex tree once at import
- `VENDORS` set → derive from `vendor_prefixes.yaml` rather than hard-coded
