# Android Hardware Firmware — File Formats & Filesystem Layout

> Extracted: 2026-04-16
> Source: Session 40 research scout 1 (file formats & locations)
> Used by: `feature-android-hardware-firmware-detection.md` intake

## Firmware Categories in Android Device Images

20-40 distinct hardware firmware blobs per typical Android image. They run on dedicated embedded cores (modem subsystem, DSPs, Wi-Fi MAC, Bluetooth controller, GPU command processor) and generally come from the SoC vendor (Qualcomm, MediaTek, Samsung LSI) or peripheral vendor (Broadcom, Cypress, NXP).

| Category | Purpose | Typical filenames |
|---|---|---|
| Bootloader (BL1/PBL/SBL) | First-stage DRAM bringup + next-stage loader | `sbl1.mbn`, `xbl.elf`, `xbl_config.elf`, `preloader.bin` (MTK), `bl1.bin`, `bl2.img` (Exynos) |
| ABL / Android Boot Loader | A/B-aware bootloader | `abl.elf`, `aboot.mbn`, `lk.bin` |
| Modem / Baseband | Cellular stack on modem subsystem (e.g. Hexagon Q6) | `modem.mbn/.mdt/.b0X`, `NON-HLOS.bin`, `cbd`/`modem.bin` (Shannon), `md1img.img` (MTK) |
| TrustZone / TEE | Secure-world OS at EL3/S-EL1 | `tz.mbn`, `tzbsp.mbn`, `hyp.mbn`, `qseelog`, `km4.mbn`, `mcRegistry/*.tlbin` (Kinibi), `trusty.bin`, `beanpod.bin` |
| Wi-Fi firmware | Wi-Fi MAC/baseband | `wlanmdsp.mbn`, `athwlan.bin`, `wcnss.mdt`, `brcmfmac*.bin` + `.txt` NVRAM + `.clm_blob`, `rtl8xxx_fw.bin`, `WIFI_RAM_CODE_MT*` |
| Bluetooth firmware | BT controller patches/firmware | `crnv*.bin`, `BCM*.hcd`, `bcm4355*.hcd`, `rtl_bt/rtl8761*_fw.bin`, `mt7662_patch_e*_hdr.bin` |
| GPU firmware | GPU command processor microcode | `a530_zap.elf`, `a650_sqe.fw`, `a660_gmu.bin` (Adreno); `mali_csffw.bin` (Mali CSF) |
| Audio DSP (aDSP / Hexagon) | Audio pipeline on Hexagon | `adsp.mbn/.mdt/.b0X`, `adspso.bin`, `audio_dsp.bin` (MTK SCP) |
| Compute DSP (cDSP) | General compute on Hexagon (FastRPC) | `cdsp.mbn/.mdt` |
| Sensor DSP (SLPI / SSC) | Always-on sensor hub | `slpi.mbn`, `sensor_hub.img` |
| Camera / ISP | ISP firmware | `ispmain.bin` (MTK), `camera_fw.elf`, often embedded in `cdsp.mbn` on Snapdragon |
| Display / DPU | Display controller microcode + calibration | `dpu.bin`, panel timing blobs under `vendor/firmware/disp_*` |
| PMIC / PMI | Power-management IC config | `pmic.elf`, `pm*.bin`, `battery_config.dtb` fragments |
| WCNSS / WCN3990 / WCN6750 | Qualcomm Wireless Connectivity SubSystem | `WCNSS_qcom_wlan_nv.bin`, `WCNSS_qcom_cfg.ini`, `wlanmdsp.mbn` |
| Venus / video codec | H.264/HEVC/VP9 hw codec | `venus.mbn`, `video-firmware.elf` |
| IPA (IP Accelerator) | Network-path offload | `ipa_fws.elf`, `ipa_uc.elf` |
| RPM (Resource Power Manager) | Power-rail MCU | `rpm.mbn`, `rpm.elf` |
| MBA (Modem Boot Authenticator) | Small TZ-signed PIL loader authenticating modem | `mba.mbn` |
| NFC controller | NCI firmware (NXP PN5xx/NQ2/NQ3, Qualcomm QN9) | `libpn54x_fw.so`, `libsn100u_fw.so`, `nfc_fw.ncd` |
| Fingerprint sensor | FPS firmware (Goodix, Synaptics, Qualcomm Sense ID) | `goodix_fp_*.bin`, `silead_*.bin`, embedded in TAs |
| Touchscreen controller | TP firmware patch (Synaptics, FocalTech, Himax, Goodix) | `synaptics_*.img`, `ft_*.bin`, `himax_*.bin`, `goodix_*.bin` |
| USB-PD / Fast-charge | Type-C PD controller (TI TPS65987, Cypress CCG) | `usbpd_*.bin`, `ccg*.fw` |
| Device Tree | Hardware description consumed by kernel | `dtb.img`, `dtbo.img`, individual `.dtb`/`.dtbo` files |

## File Formats and Magic Bytes

### Qualcomm PIL/MBN split-ELF (most common format)

PIL ("Peripheral Image Loader") splits a signed ELF into sibling files so each segment can be DMA'd directly.

- **`.mdt`** — metadata file: ELF header + program headers + Qualcomm hash-table segment (SHA-256 of each `.bNN`) + signature + cert chain. A complete-but-truncated ELF.
- **`.b00`** — usually the Qualcomm hash segment (`PT_LOAD` with `p_flags & 0x07000000 == 0x02000000`)
- **`.b01`** — signature segment
- **`.b02`** — certificate chain (attestation CA → sub-CA → image-signing cert)
- **`.b03`-`.b0F`** — code/data segments

**Magic:** Standard ELF `\x7fELF` at offset 0. Distinguishing marker: `p_flags` bits `0xFF000000` (Qualcomm segment-type field). Typically ELF class 32 for older Hexagon (`e_machine = 164 QDSP6`) or AArch64 for TZ. Hash segment on newer images has magic `0x844bdcd1` at offset 0 of `.b00` (MBN v5/v6) or Qualcomm `sbl1` magic `0x73d71034`.

**Signed:** Yes — RSA-2048/3072 over hash table; cert chain to QC root (stored in QFPROM eFuses).

**Reassembly trick:** cat `.mdt` + `.b01` + `.b02` + `.b03` + ... in program-header order yields the original signed ELF.

### Qualcomm single-file signed ELF

Newer platforms (SM8xxx) ship single `.mbn` files — concatenated PIL split. `xbl.elf`, `tz.mbn`, `hyp.mbn`, `abl.elf`, `aop.mbn` commonly distributed this way.

### Qualcomm SBL1/MBN v3 raw header

`sbl1.mbn` on older MSM uses a 40-byte MBN header rather than ELF: codeword `0x844bdcd1`, magic `0x73d71034`, image_id, flash_parti_ver, etc.

### MediaTek

- **`preloader.bin`** GFH magic `MMM\x01\x38\x00\x00\x00` (0x014d4d4d marker)
- **`lk.bin`** MTK image header magic `\x88\x16\x88\x58`
- **`md1img.img`** (modem), **`md1dsp.img`**: MTK modem firmware with header `0x58881688` LE

### Samsung Exynos modem (Shannon)

- **`modem.bin` / `cbd`** have Shannon TOC ("Table of Contents") at offset 0: magic `TOC\x00` (`0x00434f54`) followed by 12 entries (name, file_offset, load_addr, size, crc, entry_id)
- **Signed:** yes (Samsung Secure Boot key)

### Broadcom / Cypress Wi-Fi / BT

- **`brcmfmac*.bin`** — raw ThumB/ARMv7 code, no ELF header. Heuristic: filename match kernel `MODULE_FIRMWARE()`, paired `.txt` (NVRAM) + optional `.clm_blob` (regulatory)
- **`BCM*.hcd`** — Bluetooth HCI Command Download. First bytes: HCI command `4c fc` (vendor-specific Write RAM)
- **Unsigned** — loaded over SDIO/PCIe with no on-chip attestation (why BroadPwn / BleedingTooth / Frankenstein work)

### Device Tree Blobs (DTB / DTBO)

- **Magic:** `0xd00dfeed` (big-endian) at offset 0
- **Android container:** `dtb.img`/`dtbo.img` wrap one+ DTBs using Android DTB/DTBO header: magic `\xd7\xb7\xab\x1e` (BE `0xd7b7ab1e`), version, entry table

### Kernel modules (.ko)

Standard ELF relocatable (`ET_REL`):
- `e_type = 1` (ET_REL), `e_machine` matches SoC arch
- Section `.modinfo` has NUL-separated strings: `license=`, `vermagic=`, `depends=`, and critically `firmware=<name>` per `MODULE_FIRMWARE()` call
- Section `__versions` has symbol CRC entries
- Section `.note.gnu.build-id`

### Qualcomm QSEE Trusted Applications

Individual TAs are themselves MBN ELFs: `/firmware/image/keymaster.mbn`, `cmnlib.mbn`, `widevine.mbn`, etc.

### Kinibi / Trustonic TEE

Used on Samsung Exynos. Secure OS: `t-base-*.bin` or embedded in `sboot.bin`. TAs are `.tlbin` in `/system/app/mcRegistry/` or `/vendor/app/mcRegistry/`. Magic: `TRUS` (`0x53555254` LE) — MCLF header (MobiCore Load Format).

### Trusty (Google AOSP TEE, Pixel)

Used on Pixel 3+. ELF (AArch64) signed with Google key. TAs at `/vendor/firmware/tee/`.

### Realtek Wi-Fi / BT

`rtw88_*.bin`, `rtl8xxxu_*.bin`, `rtl_bt/rtl8761*_fw.bin`. Proprietary header. Unsigned.

## Filesystem Layout

| Path | What's there |
|---|---|
| `/vendor/firmware/` | Most kernel-loaded firmware: Wi-Fi, BT, touch, fingerprint, NFC, camera calibration |
| `/vendor/firmware_mnt/image/` | Qualcomm `modem`/`firmware` partition mount — all PIL files |
| `/vendor/firmware_mnt/verinfo/` | Version metadata per image |
| `/firmware/image/` | Older single-partition Qualcomm layout (pre-Treble) |
| `/vendor/etc/firmware/` | Vendor overrides |
| `/system/etc/firmware/` | Pre-Treble legacy |
| `/system/vendor/firmware/` | Symlinked into `/vendor/firmware/` under Treble |
| `/odm/firmware/` | ODM-specific overrides |
| `/odm/etc/firmware/` | Same |
| `/lib/firmware/` | Linux standard path; on Android usually symlink chain |
| `/vendor/app/mcRegistry/` | Kinibi Trusted Applications (`*.tlbin`) |
| `/vendor/lib/modules/` | Kernel modules (`*.ko`) |
| `/vendor/dsp/` | FastRPC shared libraries for cDSP |
| `/vendor/rfs/msm/` | Modem Remote File System (NV items, calibration) |

**Raw partitions** (to extract with `boot.img` / `vbmeta` tooling):
`boot.img`, `vendor_boot.img`, `init_boot.img`, `dtb.img`, `dtbo.img`, `modem.img`, `tz.img`/`tz_a`/`tz_b`, `hyp.img`, `abl.img`, `xbl.img`, `aop.img`, `devcfg.img`, `cmnlib.img`, `keymaster.img`, `persist.img`, `qupfw.img`, `uefi_sec.img`.

## Driver ↔ Firmware Mapping (reconstructible statically)

1. **`.modinfo` section of every `.ko`.** `readelf -p .modinfo driver.ko` — each `firmware=<name>` line declares a runtime `request_firmware()` path.
2. **`request_firmware()` string references in vmlinux.** For built-in drivers, grep decompressed kernel for ASCII paths ending in `.bin`, `.fw`, `.mbn`, `.hex`, `.ucode`, `.nvm`, `.ncd`.
3. **Device Tree `compatible` strings.** DTS nodes declare `compatible = "qcom,wcn3990-wifi"`; drivers match via `of_device_id`. Path: DT compatible → driver → `.modinfo` firmware.
4. **`modules.dep` and `modules.alias`.** `/vendor/lib/modules/<kver>/modules.dep` for full dependency chains; `modules.alias` maps PCI/USB/platform IDs to modules.
5. **`ueventd.rc` rules** for non-standard firmware load paths.
6. **vintf manifests** (`/vendor/etc/vintf/manifest.xml`) declare HALs.

## Vendor Chipset Indicators

| Vendor | Indicators |
|---|---|
| Qualcomm | `/vendor/firmware_mnt/`, `*.mbn`/`*.mdt`, `xbl.elf`, `tz.mbn`, strings `msm_`/`qcom,`/`qseecom`, `ro.soc.manufacturer = QTI`, SoC models MSM8xxx/SDM/SM6xxx-SM8xxx |
| MediaTek | `preloader.bin`, `lk.bin`, `md1img.img`, SoC MT67xx-MT68xx + Dimensity D700-D9000, `ro.hardware.chipname = mt6xxx` |
| Samsung Exynos | `sboot.bin`, `cp_*.bin`, `modem.bin`, `/vendor/bin/cbd`, `/vendor/firmware/cp/`, SoC Exynos 7420-2400, strings `shannon`/`sipc`/`cpif` |
| Broadcom / Cypress | `brcmfmac*.bin/.txt/.clm_blob` in `/vendor/firmware/brcm/`, `bcm*.hcd`, drivers `brcmfmac.ko`/`bcmdhd.ko` |
| Realtek | `rtl8xxx_fw.bin`, `rtl_nic/rtl*.fw`, `rtw88/rtw8822c_fw.bin`, drivers `rtl8xxxu.ko`/`rtw88.ko` |
| HiSilicon (Kirin) | `teeos.img`, `mcu_image.bin`, balong references, SoC Kirin 650-9000, strings `hisi_`/`balong_` |
| Unisoc / Spreadtrum | `prodnv.img`, `sml.bin`, `teecfg.bin`, `pm_sys.bin`, `sipc_`, SoC SC9832E/SC9863A/T610-T700, UMS512 |

## Key Sources

- Qualcomm PIL: [linux-msm/pil-squasher](https://github.com/linux-msm/pil-squasher), [remittor/qcom-mbn-tools](https://github.com/remittor/qcom-mbn-tools), [msm8916-mainline/qtestsign](https://github.com/msm8916-mainline/qtestsign), Linaro pil-squasher, [kernel mdt_loader.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/soc/qcom/mdt_loader.c)
- MediaTek: [bkerler/mtkclient](https://github.com/bkerler/mtkclient), [MTK-bypass/bypass_utility](https://github.com/MTK-bypass)
- Shannon: Grant Hernandez research series, [grant-h/ShannonBaseband](https://github.com/grant-h/ShannonBaseband), Comsecuris ShannonEE papers
- TrustZone: Gal Beniamini Project Zero series, [quarkslab/samsung-trustzone-research](https://github.com/quarkslab)
- Broadcom: [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon), InternalBlue, BrakTooth/Frankenstein papers
- Android DTBO: [source.android.com/docs/core/architecture/dto](https://source.android.com/docs/core/architecture/dto)
- Android boot image: [source.android.com/docs/core/architecture/bootloader/boot-image-header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header), [osm0sis/mkbootimg](https://github.com/osm0sis/mkbootimg)
- postmarketOS wiki — device-specific firmware-path notes per SoC
