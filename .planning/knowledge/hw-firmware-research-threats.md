# Android Hardware Firmware — Threat Model & CVEs

> Extracted: 2026-04-16
> Source: Session 40 research scout 3 (threat model & known vulnerabilities)
> Used by: `feature-android-hardware-firmware-detection.md` intake, Phase 4 CVE matcher

## Executive Summary

Android hardware firmware — modem/baseband, TEE/TrustZone, Wi-Fi/BT chipsets, GPU/DSP, boot chain — is a privileged, under-audited layer beneath the Linux kernel, often with direct hardware access, its own MMU, and shared memory with the AP. A decade of research (Project Zero, Quarkslab, Comsecuris, Gal Beniamini, Amat Cama) shows these are consistently the weakest link: over-the-air RCE in basebands (CVE-2020-11292, CVE-2023-24033), universal root via TEE drivers (Qualcomm QSEE, Samsung TEEGRIS), Wi-Fi chip pivots (BroadPwn, BleedingTooth), boot-ROM exploits enabling persistent implants (MediaTek Preloader, Qualcomm EDL).

**Scanner threat model is three-layered:**
1. **Known-vulnerable version matching** — map firmware build strings to CVEs (Qualcomm advisories, Samsung SMR bulletins, Broadcom CVEs)
2. **Structural weakness detection** — unsigned/weakly-signed segments, missing stack canaries, debug symbols in production, fallback to legacy unsigned firmware
3. **Secret/IoC extraction** — hardcoded keys, DRM material, AT command tables, test modes, backdoor strings

Wairz already has userspace CVE matching (Grype), crypto scanning, ELF protection checks — the **incremental value is chipset-specific parsers + curated CVE feed indexed by vendor firmware string rather than CPE.**

## Vulnerability Catalog by Component

### Modem / Baseband

Separate RTOS (Qualcomm REX/AMSS, Samsung Shannon, MediaTek ThreadX) running L1–L3 cellular stacks. Parses attacker-controlled RF traffic with no kernel isolation, historically ships without ASLR/DEP/stack canaries.

- **CVE-2020-11292** "Snapdragon modem" — heap overflow in QMI voice service, remote via VoLTE signaling (Checkpoint Research Aug 2020). Impacted ~40% of Android handsets.
- **CVE-2023-24033 / CVE-2023-26496 / CVE-2023-26072 / CVE-2023-26073 / CVE-2023-26074** — Samsung Exynos Shannon RCEs, Project Zero March 2023. Exploitable OTA with only phone number (VoLTE IMS). Affected Pixel 6/7, Galaxy S22, Vivo, wearables.
- **CVE-2022-21744** — Samsung Shannon integer overflow in SDP parsing (Amat Cama / TASZK). Preceded by years of research: BlackHat 2018 "Exploitation of a Modern Smartphone Baseband" (Cama), Comsecuris "Breaking Band" (Golde/Komaromy 2016).
- **CVE-2021-30351, CVE-2020-3714** — MediaTek MT6xxx modem stack, RRC/NAS buffer overflows (Check Point 2021 "MediaTek-reaver").
- **LTEFuzz (USENIX Security 2019)** — 36 new vulns across Qualcomm + Samsung.
- **5Ghoul (Dec 2023)** — 14 5G firmware bugs across Qualcomm + MediaTek NR modems; CVE-2023-33042 cluster (DoS → possible RCE).
- **Known pattern CVE families**: CVE-2016-10229 (Qualcomm WAN_HMAC), CVE-2019-10580 (QMI), CVE-2022-25664 (Shannon).

### TEE / TrustZone

S-EL1 code (QSEE, Kinibi, TEEGRIS, Trusty) with access to device-unique keys + attestation secrets. Single memory corruption = permanent root + bootloader unlock + DRM bypass.

- **Gal Beniamini "Trust Issues" series** (laginimaineb, 2015–2016) — QSEEOS full chain; **CVE-2015-6639 / CVE-2016-2431** (Widevine QSEE app) — Widevine L1 keybox extraction.
- **CVE-2019-14040 / CVE-2019-14041** — Qualcomm QSEE buffer overread, privileged info disclosure.
- **Samsung TEEGRIS** — **CVE-2021-25337 / 25369 / 25370** (Project Zero Maddie Stone, Nov 2022 "A Very Powerful Clipboard"): chained vulns from unprivileged app to arbitrary R/W. CVE-2023-21434 and follow-ups in 2023–2024 SMR bulletins.
- **CVE-2021-39793** — Trusty (Pixel) info disclosure.
- **"CLKscrew" (USENIX Security 2017, Tang et al.)** — voltage-glitch fault attack on ARM big.LITTLE DVFS to break TrustZone sig verification. AES key extraction from TrustZone, breaking Qualcomm Secure Boot.
- **Widevine L3 software-only keybox extraction** (David Buchanan, 2021) — widespread key compromise.
- **MediaTek TEE (GenieZone / TEEI)** — **CVE-2020-0069** "MediaTek-SU" — command injection in TEE driver, root persistence. Actively exploited ITW for ~2 years.

### Wi-Fi / Bluetooth Firmware

Wi-Fi/BT controllers run own ARM or Tensilica cores parsing 802.11 frames DMA-adjacent to host memory.

- **CVE-2017-9417 "BroadPwn"** (Nitay Artenstein, BlackHat USA 2017) — stack overflow in Broadcom BCM43xx Wi-Fi firmware while parsing WME IE. RCE on chip without user interaction, pivot to host via ring buffer. iOS 0-click precursor.
- **KRACK (CVE-2017-13077..13088, Vanhoef 2017)** — protocol-level, but firmware implementations (Broadcom, MediaTek) required patches; many OEMs never fixed.
- **"FragAttacks" (Vanhoef, CVE-2020-24586..24588 et al., 2021)** — 802.11 fragmentation parsing bugs in chipset firmware.
- **CVE-2019-11516** — Broadcom BCM4355 OOB write, exploitable via BT pairing (Quarkslab).
- **"BleedingTooth" (CVE-2020-12351 / -12352 / -24490, Andy Nguyen Google 2020)** — Linux BT stack + firmware RCE.
- **InternalBlue (Seemoo Lab TU Darmstadt)** — Broadcom BT firmware framework; dozens of CVEs 2018–2022 (CVE-2018-19860, CVE-2019-11516, CVE-2022-20429).
- **"Frankenstein" (Seemoo Lab, USENIX 2020)** — fuzzing Broadcom/Cypress Wi-Fi+BT; CVE-2019-15063, CVE-2019-11516, CVE-2019-13916.
- **Cypress "Kr00k" (CVE-2019-15126, ESET 2020)** — all-zero encryption key after disassociation.
- **MediaTek "NAME:WRECK" / "WiBLE"** — MT76xx Wi-Fi firmware RCE 2021–2023.

### GPU / DSP

- **Qualcomm Hexagon aDSP / cDSP / mDSP** — CVE-2020-11201..11209 (Check Point "Achilles" 2020): >400 vulns in Hexagon SDK/skeletons. CVE-2022-25718 (mDSP). Attractive because apps can load DSP shaders without root via FastRPC.
- **Adreno GPU** — CVE-2020-11179, CVE-2023-33063 (Project Zero, exploited ITW), CVE-2023-33106, CVE-2023-33107 (Qualcomm October 2023 actively-exploited trio, kernel driver → GPU firmware).
- **ARM Mali** — CVE-2022-38181, CVE-2022-22706, **CVE-2023-4211**, CVE-2023-48409 (Project Zero Jann Horn). Exploited ITW, enabled Android sandbox escapes (Samsung, Pixel). Mali CSF firmware scheduling bugs.
- **Pixel Camera ISP** — CVE-2021-0920, CVE-2022-20421 (Project Zero "Mind the Gap" 2022) — exploited as part of ITW chain against activists.
- CVE-2022-22057 / Qualcomm Video / CVE-2022-33264 (MediaTek audio DSP).

### Boot Chain

- **Qualcomm EDL (Emergency Download)** — signed "firehose" programmers per OEM; leaked OEM programmers (Xiaomi, Nokia) enabled permanent unlock + implant. Aleph Security 2017–2018. **CVE-2017-18159**.
- **MediaTek Preloader / BROM** — "kamakiri" / "mtkclient" exploit (chaosmaster 2020): unauthenticated USB command injection in BROM, universal for MT67xx/MT68xx. **Never patched** — mask-ROM bug.
- **Samsung Odin mode** — CVE-2019-10574 bootloader, PIT parsing; ShannonBaseband identified command injection.
- **Verified boot bypasses** — AVB rollback (CVE-2020-0215), vbmeta stripping (unpatched Xiaomi pre-2021), dm-verity signature downgrade.
- **CVE-2022-31704 / Pixel 6 GS101 bootloader** — fastboot command parsing.

## Common Patterns (What a Scanner Should Fingerprint)

1. **No stack canaries / NX / ASLR on RTOS images.** Shannon, REX, ThreadX historically ship flat address space, RWX, no canary. Detect: absence of `__stack_chk_fail` imports, segment permissions RWX in MDT/MBN headers.
2. **Unsigned or weakly signed "loader" stages.** Early Qualcomm PIL segments (hash table, metadata) signed with SHA-1 / RSA-1024 well into 2020. MD5 documented pre-2015.
3. **Fallback to legacy unsigned firmware.** Broadcom Wi-Fi honored unsigned RAM patches ("clm_blob") post-boot — BroadPwn-class pivot vector.
4. **Debug symbols / build strings in production.** Shannon exposes function names; Qualcomm modem MBN has `DEBUG=1` flag in MDT attributes; Broadcom firmware leaks internal paths `C:\swbuild\...`.
5. **Hardcoded keys + test material.** Widevine keyboxes in QSEE apps; Samsung "factory keys" in recovery; Realtek Wi-Fi shipped with hardcoded WPA test PSK.
6. **Hidden AT command tables.** Samsung/LG AT+COPS, AT+CFUN extensions — factory reset, NVRAM read, IMEI write. "ATtention Spanned" (USENIX Security 2018) enumerated 3500+ hidden AT commands on 11 OEMs.
7. **Test/debug commands over USB/serial.** MediaTek Preloader USB commands, Qualcomm Sahara/DIAG, "diag" port exposure on retail (CVE-2017-11041).
8. **Stale CVE exposure.** OEMs ship 2-year-old Qualcomm/Samsung firmware on new mid-range devices; 2024 budget Androids shipping Wi-Fi firmware with 2020 CVEs unpatched.
9. **CVE attribution mismatch.** Qualcomm CVE advisories reference internal bug IDs + chipset lists, not device build strings.

## Secrets in Firmware

- **DRM**: Widevine L1 keybox (device-unique 3DES/AES key), PlayReady certs, Netflix service keys
- **Device-unique keys**: Qualcomm HLOS HWKEY / QFPROM shadow, Samsung TEEGRIS unique key, attestation keys for Play Integrity
- **OEM signing keys**: Multiple cases documented — LG "rel_key" leaked in recovery, Samsung platform signing keys leaked 2022 enabling malicious APK signing as `android.uid.system`
- **Operator data**: IMEI, MSL unlock codes, SIMLOCK data in NVRAM partitions
- **Backdoors**: Samsung "Shannon RFS" modem filesystem backdoor (Replicant 2014) — baseband could read/write arbitrary AP filesystem via remote RFS command. ZTE/Huawei hardcoded root creds recurrent
- **URLs/IPs**: OTA/telemetry endpoints often cleartext

## Supply Chain

SoC vendor → ODM → OEM → Carrier → User. Each link holds signing keys + can insert blobs. The "golden image" from SoC vendor is reviewed by small chipset security team; OEM custom drivers rarely audited; carrier adds branding/bloatware.

**NVD coverage sparse**: only ~30% of Qualcomm Security Bulletin entries have CVE IDs within a year of disclosure. MediaTek bulletin tracking worse. OEM customization CVEs (Samsung SMR, Xiaomi Mi Security) not systematically mirrored to NVD/CPE.

**Compliance angle:** EU CRA (full 2027), FCC compliance, right-to-repair, GPL violation concerns (kernel drivers depending on proprietary blobs).

## Detection Signal Shortlist — Top 10 for Wairz

1. **Known-vulnerable build string** — parse Qualcomm MBN `QC_IMAGE_VERSION_STRING`, Samsung Shannon `CP_VERSION`, Broadcom `fw_version`; match curated CVE database
2. **Unsigned / weakly-signed PIL segments** — parse MDT attributes (hash/signed flag in pflags), flag SHA-1/MD5, RSA <2048, missing cert chain
3. **Missing stack canaries / NX on RTOS** — ELF check for `__stack_chk_fail`; flag RWX segments
4. **Debug build indicators** — MDT `debug=1`, Shannon debug symbols, Broadcom `DEBUG_BUILD` string, Qualcomm `QDI_DEBUG`
5. **Hidden AT command tables** — string match against ATtention Spanned corpus (AT+FACTORY, AT+SWITCHDEV, AT+USBDEBUG, carrier-specific factory verbs)
6. **Hardcoded crypto material** — extend existing crypto scanner: Widevine keybox magic, PlayReady header, X.509 in unexpected offsets
7. **Exposed debug ports / DIAG / Sahara** — config blobs; EDL programmer presence
8. **Firmware-to-chipset mismatch** — parse chipset ID (Qualcomm MSM-ID, MediaTek chipcode), compare to device model claimed by `build.prop`
9. **Legacy unsigned fallback paths** — Broadcom `clm_blob` unsigned loading, Qualcomm "PBL bypass" references
10. **Suspicious URLs/IPs/backdoor strings** — HTTP (not HTTPS) in modem/TEE, hardcoded IPv4 outside RFC1918, known backdoor strings (Samsung RFS, ZTE fixed creds)

## Seed CVE Families for `known_firmware.yaml`

Phase 4 curated YAML should seed with:

| Family | CVE | Match pattern |
|---|---|---|
| BroadPwn | CVE-2017-9417 | Broadcom BCM43xx firmware version 7.35.x / 7.112.x |
| Snapdragon modem RCE | CVE-2020-11292 | Qualcomm modem build with QMI voice service version X |
| Exynos Shannon RCE cluster | CVE-2023-24033 (+26496/26072/26073/26074) | Shannon TOC version S5xxx pre-March 2023 |
| Samsung TEEGRIS "Powerful Clipboard" | CVE-2021-25337/25369/25370 | TEEGRIS version pre-security patch Nov 2022 |
| Mali GPU exploit | CVE-2023-4211 | Mali CSF firmware version pre-patch |
| MediaTek-SU | CVE-2020-0069 | MediaTek TEE/GenieZone pre-patch |
| Hexagon Achilles | CVE-2020-11201..11209 | Hexagon SDK skeleton version X |
| MediaTek-reaver | CVE-2021-30351 | MT67xx modem stack version pre-patch |
| Kr00k | CVE-2019-15126 | Cypress Wi-Fi firmware pre-patch |
| BleedingTooth | CVE-2020-12351/12352/24490 | Linux BT + firmware versions |
| QSEE Widevine keybox | CVE-2015-6639 / CVE-2016-2431 | Pre-2017 Qualcomm Widevine TA |
| kamakiri BROM | CVE-TBD (no CVE, SoC-level) | MT67xx/MT68xx BROM (detect chipset family, advise "unpatchable BootROM vuln") |
| Qualcomm EDL | CVE-2017-18159 | Known leaked OEM firehose programmers |
| FragAttacks | CVE-2020-24586/24587/24588 | Broadcom/MediaTek Wi-Fi pre-patch |

## Key Research Sources

### Talks / Papers
- Amat Cama, BlackHat USA 2018 — "Exploitation of a Modern Smartphone Baseband"
- Gal Beniamini (laginimaineb), 2015–2016 — "Trust Issues: Exploiting TrustZone TEEs"
- Golde & Komaromy, 2016 — "Breaking Band: Reverse Engineering and Exploiting the Shannon Baseband"
- Nitay Artenstein, BlackHat USA 2017 — "BroadPwn"
- Maddie Stone, Project Zero 2022 — "A Very Powerful Clipboard"
- Tang/Sethumadhavan/Stolfo, USENIX Security 2017 — "CLKscrew"
- USENIX Security 2019 — "LTEFuzz"
- Ruge/Classen/Gringoli/Hollick, USENIX Security 2020 — "Frankenstein"
- Vanhoef, CCS 2017 "KRACK"; 2021 "FragAttacks"
- Tian et al., USENIX Security 2018 — "ATtention Spanned"
- Check Point Research 2020 — "Achilles: Small Chip, Big Peril"
- Natalie Silvanovich, Project Zero 2023 — "Exynos Baseband Vulnerabilities"
- Jann Horn, Project Zero — Mali GPU series 2022–2023
- Google TAG 2022 — "Mind the Gap"
- 5Ghoul (ASSET SUTD) 2023 — "5Ghoul: Unleashing Chaos on 5G Edge Devices"
- Aleph Research 2017 — "Exploiting Qualcomm EDL Programmers"
- chaosmaster 2020 — mtkclient / kamakiri BROM
- David Buchanan 2021 — Widevine L3 Keybox Extraction

### Primary CVE sources
- Qualcomm Security Bulletin: docs.qualcomm.com/product/publicresources/securitybulletin
- Samsung Mobile Security (SMR): security.samsungmobile.com
- MediaTek PSIRT: corp.mediatek.com/product-security-bulletin
- Broadcom / Cypress / Infineon CVE feeds
- Android Security Bulletin (monthly AOSP rollup)

### Research blogs
- Google Project Zero: googleprojectzero.blogspot.com (filter "modem", "TEE", "Mali", "Broadcom")
- Quarkslab: blog.quarkslab.com (TEE, TrustZone, modem)
- Comsecuris: comsecuris.com/blog (baseband archive)
- Seemoo Lab (TU Darmstadt): github.com/seemoo-lab/internalblue, frankenstein
- GrapheneOS: grapheneos.org/features#attack-surface-reduction
- 0xdea (Marco Ivaldi): github.com/0xdea
- firmware.re (EURECOM)
- VUSec (VU Amsterdam): vusec.net/projects
