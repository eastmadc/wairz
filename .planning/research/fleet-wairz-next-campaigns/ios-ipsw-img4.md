# iOS IPSW / IMG4 Firmware Support — Research Brief

> Scout: fleet-wairz-next-campaigns / ios-ipsw-img4
> Date: 2026-04-17

## Summary

iOS/macOS firmware support bolts onto the existing Wairz parser/unpack framework if we adopt `blacktop/ipsw` (MIT, Go, v3.1.664 Mar 2026 [1][2]) as subprocess backend for the hard parts (IMG4 DER, dyld_shared_cache, SEP/iBoot). Pure-Python IMG4 headers are ~150 LOC; DSC + kernelcache LZFSE are not worth re-solving. Kernelcache → Ghidra works; SEP and baseband are classify-only. Distributing IPSW content is illegal; parsing user-uploads is fine.

## Top OSS Tools

| Tool | URL | License | Maintenance | Role for Wairz |
|---|---|---|---|---|
| **blacktop/ipsw** | https://github.com/blacktop/ipsw [1] | MIT | Very active, v3.1.664 Mar 2026; solo maintainer + ~50 contributors | Primary subprocess backend for DSC, SEP, IMG4, kernel extract |
| **tihmstar/img4tool** | https://github.com/tihmstar/img4tool [3] | LGPL-3.0 | Sporadic; C++/OpenSSL | Legacy IMG4 parser; reference only |
| **h3adshotzz/img4helper** | https://github.com/h3adshotzz/img4helper [4] | MIT | Low activity | Lighter IMG4 reference implementation |
| **malus-security/iExtractor** | https://github.com/malus-security/iExtractor [5] | BSD | Archived (pre-iOS 15) | Historical LZSS kernel decompressor — superseded by `ipsw` |
| **0x36/ghidra_kernelcache** | https://github.com/0x36/ghidra_kernelcache [6] | Apache-2.0 | iOS 12–15; stale post-16 | Optional Ghidra script bundle for KEXT splitting |
| **hack-different/apple-baseband** | https://github.com/hack-different/apple-baseband [7] | MIT | Research-only | Baseband `.bbfw` reference (Intel XMM / Qualcomm Hexagon) |
| **autodecrypt** + **theapplewiki.com** | https://github.com/matteyeux/autodecrypt [8] | GPL-3.0 | Maintained | Firmware key lookup via TheAppleWiki API (`wikiproxy`) |
| **img4-dump** (Rust) | https://crates.io/crates/img4-dump [9] | MIT | Minor | Possible pure-Rust alt if we ever want to drop `ipsw` |

**Decision: adopt `blacktop/ipsw`.** Self-contained Go binary, MIT, Homebrew/Snap/Scoop, provides `extract`, `img4`, `fw sep`, `fw iboot`, `dyld`, `kernel`, `macho` — the exact MCP-tool surface. Size ~60–90 MB in-container. Skip the `ipswd` REST daemon; shell out to `ipsw` CLI directly.

## Format Reference

### IPSW archive
ZIP containing `BuildManifest.plist`, `Restore.plist`, `*.dmg` (APFS rootfs), and `Firmware/*.im4p` [10][11]. Rootfs DMG is often FileVault-encrypted (key from BuildManifest ticket, iOS 10+); `ipsw extract --dmg fs` handles it.

### IMG4 (DER-encoded ASN.1)
Three siblings [10][12]:
- **IM4P (payload)**: `SEQUENCE { "IM4P", type4cc, description, payload, [KBAG], [compression-info] }`. `type4cc`: `ibot`, `illb`, `ibec`, `ibss`, `krnl`, `rkrn`, `sepi`, `rsep`, `rdsk`, `dtre`, `aop`, `ane`, `rtos`.
- **IM4M (manifest)**: Apple-signed; payload SHA, ECID binding, security domain (Secure Boot ticket).
- **IM4R (restore info)**: APNonce anti-replay blob.

`ipsw img4 im4p extract` decrypts with IV+key from TheAppleWiki (A6–A10). A11+ is keybagged per-device — **cannot decrypt offline**.

### Kernelcache
iOS 12+: IM4P-wrapped, LZFSE or LZSS Mach-O [6][13]. `ipsw kernel extract` produces a standalone arm64e Mach-O that loads in **Ghidra's native Mach-O loader directly**. It's a "fileset" Mach-O with all KEXTs; `ipsw kernel extract --kext` splits them, or use `0x36/ghidra_kernelcache` scripts.

### dyld_shared_cache (DSC)
Monolithic multi-GB cache of system dylibs. Since iOS 15/macOS 12 it's **split into 2+ slices**, which breaks older Ghidra [14][15]. Options: `ipsw dyld extract` (pure Go, anywhere), `ipsw dyld split` (calls Apple's `dsc_extractor.bundle`, Darwin-only). Ghidra 11.x loads split DSC natively but quality varies; extracted dylibs load cleanly as plain Mach-O.

### SEP firmware
Opaque ARM Mach-O + ftab RTKit [16]. `ipsw fw sep` extracts; decryption needs per-device KBAG keys (jailbroken dev units only, A11+). Hexacon 2025 [17] confirms active research. **Classify-only for MVP.**

### Baseband (`.bbfw`)
ZIP-in-ZIP [7][18]. Qualcomm (iPhone XS+): Hexagon DSP, `.msm` trustlets. Intel XMM (iPhone 7–X): proprietary x86 ROM [19]. ~200 LOC; classification only.

## Apple CVE Data Sources

**No machine-readable feed from Apple.** [20][21] Index at `support.apple.com/en-us/100100` links per-release HTML pages (e.g. `.../126347` = iOS 18.7.5) with consistent `<h3>Component</h3>` + `<p>CVE-YYYY-NNNNN</p>` — scrapeable.

Options: (1) **NVD/OSV indirect** — 24–72h lag, `Apple` on OSV is NVD passthrough [22]; acceptable for our matcher. (2) **Scrape `support.apple.com`** — ~30–50 pages/year, stable DOM, ~150 LOC. (3) Third-party mirrors `cvedetails.com` / `opencve.io` [23][24].

**Recommendation:** add a 6th matcher tier — monthly scrape of the Apple index into a Redis `(product, build) → [CVEs]` map, with NVD as detail fallback.

## Integration into Wairz

**File-level changes (~6 files, est. 2–3 sessions for MVP):**

| File | Status | LOC | Purpose |
|---|---|---|---|
| `backend/app/workers/unpack_ios.py` | new | ~300 | IPSW ZIP open → BuildManifest parse → iterate `.im4p` files → classify + unpack DMG (subprocess `ipsw extract --dmg fs`) |
| `backend/app/services/hardware_firmware/parsers/apple_img4.py` | new | ~180 | DER/ASN.1 IM4P/IM4M header parser (Python stdlib only — `asn1crypto` or manual DER walk). Emits `firmware_type`, `target_4cc`, `compression`, `is_encrypted` |
| `backend/app/services/ios_ipsw_service.py` | new | ~250 | Subprocess wrapper for `ipsw` CLI: `extract_kernel()`, `split_dyld()`, `parse_sep()`, `fw_iboot()` with 30-KB truncated outputs |
| `backend/app/services/hardware_firmware/parsers/__init__.py` | modify | +1 line | Register `apple_img4` in `PARSER_REGISTRY` alongside the existing 11 parsers |
| `backend/app/workers/unpack.py` | modify | ~30 | Detect IPSW by magic (ZIP + `BuildManifest.plist`) and dispatch to `unpack_ios` |
| `backend/app/ai/tools/firmware_apple.py` | new | ~400 | MCP tools: `extract_ios_kernelcache`, `split_dyld_cache`, `analyze_img4`, `extract_sep_firmware`, `list_ipsw_components` |
| `backend/app/ai/__init__.py` | modify | +2 lines | Register Apple tool category |
| `backend/app/services/firmware_classifier_service.py` | modify | ~40 | Classifier rules for `iBoot`, `iBEC`, `LLB`, `SEPFirmware`, `AppleKernelcache`, `AppleANE`, `AppleAOP`, `AppleBaseband` |
| `Dockerfile` (backend) | modify | +6 | Install `ipsw` via `snap` OR download release tarball (~60MB) — prefer tarball for determinism |
| `alembic/versions/<next>_ipsw_support.py` | new | ~40 | No schema change required; `analysis_cache` already handles arbitrary JSON |

**Total: ~1,200 LOC new + minor modifications across 5 files.** Matches Android (Phase 5) sizing.

**Session plan:** (1) IMG4 parser + classifier, (2) `unpack_ios.py` end-to-end with IPSW-in-container, (3) MCP tools wrapping `ipsw` CLI, (4) Apple CVE scraper (optional — can defer to follow-up campaign).

## Licensing Gotchas

1. **IPSW files are Apple-copyright** [25]. Never ship IPSW samples, never bundle them in Docker, never auto-download from Apple's CDN in CI. User-upload-only (same model as Android stock ROMs).
2. **Beta IPSWs have taken DMCA** (BetaProfiles.com shut down; Apple DMCA'd tweets linking to ipsw.dev [26]). Do NOT expose `ipsw download` as an MCP tool.
3. **TheAppleWiki keys** are community-RE'd AES keys — widely distributed 10+ years without Apple action. `ipsw` fetches from `wikiproxy` at runtime; we inherit the posture.
4. **`ipsw` is MIT** [1]. Apache-2 (`ghidra_kernelcache`) and LGPL-3 (`img4tool`) are stack-compatible; avoid GPL-3 (`autodecrypt`) as a hard dep.
5. **`dsc_extractor.bundle`** (Darwin-only, Apple-licensed) is used only if `ipsw dyld split` runs on macOS. Our Linux stack uses `ipsw dyld extract` (Go, no license issue).

## Dead Ends

- **Pure-Python-everything.** Fine for IMG4 headers; LZFSE + DSC splitting is 3+ sessions — use `ipsw`.
- **`malus-security/iExtractor`** [5] — archived, iOS-14 LZSS only.
- **Apple's official dyld drop** — 6–12mo lag, macOS-only build.
- **Offline A11+ iBoot/SEP decryption** — keybags are device-bound; jailbroken dev units only.
- **`ipswd` REST daemon** — extra long-running service; shell out instead.
- **Apple scrape as sole CVE source** — rate-limited, DOM drift risk; keep NVD fallback.

## Confidence

**Medium-high.** `blacktop/ipsw` being MIT + actively maintained + covering 90% of needs is the single biggest de-risker. Main uncertainty: SEP/baseband analysis depth (those are active-research areas — expect "classify but don't decompile" for MVP). Kernelcache + DSC + IMG4 paths are well-trodden.

## References

1. blacktop/ipsw — https://github.com/blacktop/ipsw
2. ipsw releases — https://github.com/blacktop/ipsw/releases
3. tihmstar/img4tool — https://github.com/tihmstar/img4tool
4. h3adshotzz/img4helper — https://github.com/h3adshotzz/img4helper
5. malus-security/iExtractor — https://github.com/malus-security/iExtractor
6. 0x36/ghidra_kernelcache — https://github.com/0x36/ghidra_kernelcache
7. hack-different/apple-baseband — https://github.com/hack-different/apple-baseband
8. matteyeux/autodecrypt — https://github.com/matteyeux/autodecrypt
9. img4-dump (Rust) — https://crates.io/crates/img4-dump
10. IMG4 File Format (TheAppleWiki) — https://theapplewiki.com/wiki/IMG4_File_Format
11. ipsw extract guide — https://blacktop.github.io/ipsw/docs/guides/extract/
12. Parse Img4 — https://blacktop.github.io/ipsw/docs/guides/img4/
13. NowSecure iOS kernel reversing — https://www.nowsecure.com/blog/2017/04/14/ios-kernel-reversing-step-by-step/
14. Parse dyld_shared_cache — https://blacktop.github.io/ipsw/docs/guides/dyld/
15. Ghidra DSC iOS 15+ issue — https://github.com/NationalSecurityAgency/ghidra/issues/3345
16. AppleSEPFirmware notes — https://github.com/mwpcheung/AppleSEPFirmware
17. Inside Apple SEP 2025 (Hexacon) — https://2025.hexacon.fr/slides/inside_secure_enclave_processor_in_2025.pdf
18. Baseband Firmware (TheAppleWiki) — https://theapplewiki.com/wiki/Baseband_Firmware
19. Baseband Attacks USENIX WOOT'12 — https://www.usenix.org/system/files/conference/woot12/woot12-final24.pdf
20. Apple security releases index — https://support.apple.com/en-us/100100
21. Sample per-release CVE page — https://support.apple.com/en-us/126347
22. OSV schema — https://ossf.github.io/osv-schema/
23. cvedetails Apple — https://www.cvedetails.com/vulnerability-list/vendor_id-49/Apple.html
24. OpenCVE Apple — https://app.opencve.io/cve/?vendor=apple
25. Apple IPSW legal discussion — https://discussions.apple.com/thread/5624023
26. IPSW beta DMCA context — https://iphonewired.com/news/458132/
27. ipsw Walkthrough (8kSec) — https://8ksec.io/ipsw-walkthrough-part-2-the-swiss-army-knife-for-ios-macos-security-research/
