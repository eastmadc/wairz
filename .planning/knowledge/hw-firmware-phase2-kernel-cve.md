# Kernel Module CVE Attribution — OSS Approach

> Extracted: 2026-04-17
> Source: Session 41 research scout 2 — kernel module CVE attribution
> Used by: `feature-hw-firmware-phase2-enrichment.md` intake
> Context: Phase 1 detected 236 .ko kernel modules with `vendor=None, version=None` (or noisy `.modinfo` like "1.8", "V2.0", "Time:"). CVE match returned 0. This scout finds the lowest-effort path to real CVE attribution.

## Key Finding — We Already Have the Join Key

`backend/app/services/hardware_firmware/parsers/kmod.py` already extracts `vermagic` from `.modinfo`. For this firmware: `vermagic="6.6.102-android15-8-maybe-dirty-4k SMP preempt mod_unload modversions aarch64"`. The **kernel version** (`6.6.102`) is the join key. No new parsing needed.

## Top 3 Data Sources

### 1. kernel.org `vulns.git` — authoritative Linux kernel CNA feed (BEST)
- Repo: `https://git.kernel.org/pub/scm/linux/security/vulns.git` (~100 MB clone)
- Since Feb 2024, the Linux kernel is its own CVE CNA. Each CVE ships as structured JSON at `cve/published/YYYY/CVE-YYYY-NNNNN.json` with:
  - `programFiles` — list of touched source files (e.g. `net/bluetooth/smp.c`, `drivers/gpu/arm/midgard/mali_kbase.c`)
  - Git commit ranges (`version` → `lessThan`)
- **No API key, no rate limit** (git clone).
- **Integration:** nightly `git pull`; index `programFiles` → subsystem/driver prefix → match against `.ko` basename.
  - `bluetooth.ko` → `net/bluetooth/`
  - `mali_kbase*.ko` → `drivers/gpu/arm/`
  - `cfg80211.ko` → `net/wireless/`
  - `nfc.ko` → `net/nfc/`
  - `fuse.ko` → `fs/fuse/`
- A 50-line basename→subsystem dict covers ~80% of Android vendor trees.

### 2. OSV.dev — Debian/Ubuntu kernel ecosystem (free, no key)
- `POST https://api.osv.dev/v1/query` with `{"package":{"name":"linux","ecosystem":"Debian:12"},"version":"6.6.13-1"}` returns 855 upstream CVE hits for a single kernel version.
- Pick the Debian/Ubuntu kernel source closest to vermagic base (6.6.102 → Debian 12 6.6.x).
- Covers LTS backport status (which NVD CPEs don't).

### 3. syft + grype — lowest-effort win (we already have grype)
- **syft has a kernel module cataloger**: `syft/pkg/cataloger/kernel/parse_linux_kernel_module_file.go`.
- Produces `pkg.LinuxKernelModulePkg` + a synthesized `linux-kernel` package with CPE `cpe:2.3:o:linux:linux_kernel:<version>:*`.
- **Grype matches the `linux-kernel` package via stock CPE matcher** — no kernel-specific matcher needed. Individual modules won't match (driver-internal versions like "1.8"), but the synthesized kernel package will.
- **Action:** `syft dir:<extracted_root> -o syft-json | grype` in the existing grype service. Confirm syft's kernel cataloger runs (parses `.ko` by ELF `.modinfo` section — same bytes we already read).

## Zero-Dep Quick Wins (TODAY)

1. **Parse kernel semver out of vermagic** (`6.6.102` from `6.6.102-android15-8-...`) in `kmod.py` and store as a first-class column.
2. **Feed that kernel version to grype** as a synthetic SBOM component with CPE `cpe:2.3:o:linux:linux_kernel:6.6.102`. Grype already handles this CPE.
3. **NVD keyword seed for subsystem:** `GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=linux+kernel+bluetooth&virtualMatchString=cpe:2.3:o:linux:linux_kernel:6.6.102`. Works without API key (5 req / 30s).
4. **Static subsystem dict:** 50-entry `.ko basename → kernel_subsystem_path` map.

## Dead Ends

| Source | Why skip |
|---|---|
| LVFS | UEFI capsule service, not kernel SBOM |
| cve-search (self-hosted Mongo) | ~10 GB mirror of NVD; same data direct |
| vulners.com | Commercial API key; kernel.org is the same primary source |
| kernelsec.org / nluedtke/linux_kernel_cves | Unmaintained since 2022; worse than kernel.org CNA |
| Android Security Bulletin JSON feed | Doesn't exist; only HTML at source.android.com — scrape if needed |
| Per-`.ko` PURL CVE matching | `.ko version=` fields are vendor-local; no CVE coverage |
| CycloneDX "kernel module" type | Doesn't exist as first-class; syft uses `pkg:generic/` |

## Recommended Pipeline

```
.ko → existing kmod parser → vermagic → semver extract (6.6.102)
                                     ↓
  [1] Inject pkg CPE cpe:2.3:o:linux:linux_kernel:6.6.102 into grype SBOM
  [2] Nightly clone kernel.org vulns.git; index programFiles→subsystem
  [3] For each .ko: basename→subsystem dict → local vulns index → CVEs
      touching that subsystem within version range
  [4] Intersect (1) and (3) for high-confidence hits
      (1) alone = medium-confidence
```

## Wairz Files Touched

- `backend/app/services/hardware_firmware/parsers/kmod.py` — already extracts vermagic; add semver extraction
- `backend/app/services/grype_service.py` — inject synthetic kernel SBOM component
- `backend/app/services/hardware_firmware/cve_matcher.py` — add kernel.org vulns.git index lookup tier
