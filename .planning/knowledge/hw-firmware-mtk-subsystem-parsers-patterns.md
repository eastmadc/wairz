# Patterns: MTK subsystem parsers + CVE precision (2026-04-17 session)

> Extracted: 2026-04-17
> Campaign: (no formal campaign file — extracted from session commits)
> Commits: 431e3ec, 9e1de6c, 7ab35b5
> Postmortem: not written (informal campaign)

This captures lessons from a single-session body of work that shipped three
features: EDAN encrypted-partition diagnostic + zImage arch fallback (bug
investigation on a DPCS10/RespArray-family upload), MediaTek LK name-field
classifier dispatch + CVE aggregate dedup (three-bug fix on DPCS10), and
per-role subsystem parsers (ATF / GenieZone / tinysys) with a ship-ready
CVE-2025-20707 fingerprint. ~2,200 LOC net, ~100 new tests, all live-verified
on real DPCS10 blobs.

## Successful Patterns

### 1. Empirical on-disk verification before writing parser code
- **Description:** Every new parser was preceded by a `docker compose exec
  backend python3 -c "..."` script that read the real blob bytes and
  verified the hypothesised layout (magic offsets, sub-image chain, version
  banners, vector tables). Research reports from sub-agents proposed the
  format; on-disk inspection confirmed or corrected the proposal before any
  Python struct code was written.
- **Evidence:** Three specific corrections surfaced this way —
  (a) outer LK header is 512 bytes, not 48 as the research initially claimed
  (confirmed via walking sub-images: primary + cert2 pattern only works with
  0x200 header);
  (b) the "MMM\x01" GFH inner chain hypothesised by research doesn't exist
  on DPCS10 — only an 0x58891689 LK_FILE_INFO marker at offset 0x30;
  (c) the `file_info_offset` at 0x04 is nonsense on stubs (modem.img has it
  = 1), which became the stub-detection signal.
- **Applies when:** Writing any binary-format parser. Treat research briefs
  as starting hypotheses, not specifications — read the bytes first. A one
  docker-exec round-trip saves a reverted commit.

### 2. Ship vulnerability fingerprints inline with parsers
- **Description:** The GenieZone parser embeds a hard-coded CVE-2025-20707
  check: regex-extract the `GZ_hypervisor: <ver>, Built: <date>` banner,
  flag as vulnerable if version < 3.2.2.x OR build-date < 2026-02-01.
  Result lands in `device_metadata["known_vulnerabilities"]` without
  touching the CVE matcher, bulletin YAML, NVD, or any external feed.
- **Evidence:** Live-verified on DPCS10's gz.img (3.2.1.004, Dec 12 2025) —
  flagged immediately. Three regression tests cover the fingerprint:
  vulnerable-by-version, patched-by-version, patched-by-date. Zero
  infrastructure dependencies.
- **Applies when:** A CVE has a well-known version/date threshold AND the
  affected binary carries an extractable banner. Shipping the fingerprint
  inline with the parser gives zero-configuration CVE detection for
  single-session users; the CVE matcher's YAML remains the right home for
  broad coverage. Hybrid is cheap.

### 3. Name-field dispatch over magic-byte-only classification
- **Description:** MediaTek's LK magic (0x58881688) wraps every subsystem
  blob — bootloader, TEE, hypervisor, modem, camera VPU, power mgmt. Magic
  alone is ambiguous. The 8-byte partition-name field at offset 0x08
  (compact variant) or 32-byte field at 0x20 (legacy) is the real
  classification key. Extracted ~35 canonical names from U-Boot
  `tools/mtk_image.c` + bkerler/mtkclient + AOSP device trees + MediaTek
  security bulletins into a single `_MTK_PARTITIONS` lookup table in
  `mediatek_gfh.py`.
- **Evidence:** Before fix — 12/12 DPCS10 MTK blobs tagged
  `bootloader/mediatek/mtk_lk` with nonsense `partition_size: 1.9GB`
  values. After — 7 correct categories (bootloader, tee, camera, dsp, mcu,
  modem, display), each with the right component tag. The lookup table
  also feeds subcomponent tagging for future CVE precision work.
- **Applies when:** A vendor wraps every component type in the same
  container magic. Don't classify by magic alone — dispatch on the
  embedded metadata (name, type, role field). Cataloging the ~30 known
  names from authoritative sources (vendor-internal headers, leaked BSPs,
  OSS tools that ship with the right dispatch) pays for itself across
  every future firmware.

### 4. Header-variant probing by ASCII-name sanity check
- **Description:** MTK has two LK header layouts (legacy 512-byte with name
  at 0x20, compact 16-byte with name at 0x08) that share the same magic.
  Research suggested "disambiguate by `magic_version`" — but that field
  doesn't exist in compact (those bytes are part of the name string). The
  working dispatch instead probes offset 0x08 for a valid ASCII name
  (matching `^[A-Za-z][A-Za-z0-9_\-]{0,30}$`). If it looks like a name,
  use compact; otherwise fall through to legacy.
- **Evidence:** `parse_lk_header()` correctly handles both variants with a
  single regex check. Tests cover real DPCS10 bytes (compact) and a
  synthesised legacy-layout header.
- **Applies when:** Multiple header variants share a magic. Pattern-match
  on the structural consequence of each layout (what's at offset X) rather
  than trusting a "version" field that may not mean what you think.

### 5. Hybrid data-source strategy for legally-constrained feeds
- **Description:** MediaTek's Product Security Bulletin is the only source
  with full `(CVE, subcomponent, chipset, CWE)` triples — but their ToS
  prohibits derivative works and redistribution. Designed a hybrid:
  (a) Android Security Bulletin (CC-BY, safe to redistribute) as primary
  data committed to the repo; (b) local MTK PSB scraper that populates a
  gitignored runtime-only YAML per deployment; (c) NVD description regex
  (`"In <subcomponent>,"`) as authoritative for the subcomponent tag even
  when no structured data is available. Three-tiered, each layer safe at
  its scope.
- **Evidence:** Research track 1 surfaced the ToS issue before any scraper
  code was written. Plan accepted and banked for Phase C5.
- **Applies when:** Designing any feature that ingests a vendor's public
  data into a distributable tool. Check ToS alongside robots.txt — they
  say different things. Paid-feed partnerships (Exiger / VulnCheck model)
  are worth considering as a third path when the data is high-value and
  the tool ships commercially.

### 6. Three-track parallel research, then empirical consolidation
- **Description:** Each Phase of work spawned 2-3 parallel background
  research agents before implementation: Phase B (EDAN encryption + zImage
  detection + Wairz integration points), three-bug fix (MTK scatter/GFH
  format + subsystem RE tooling + CVE match explosion), Phase C (MTK
  bulletin index + ATF/GenieZone/tinysys on-disk + CVE precision
  architecture). Research returned in ~2-5 minutes each while the
  implementer prepared the code substrate.
- **Evidence:** Every commit landed with all research consolidated into
  the plan before any file was edited. The empirical disk-inspection step
  (pattern #1) corrected research errors rather than going back for more.
- **Applies when:** Work spans >1 knowledge domain or has structural
  unknowns (legal, format, algorithm). Three parallel tracks is the sweet
  spot — more fragments attention; fewer leaves unknowns on the table.

### 7. Run tests via project venv inside the container, commit docs
- **Description:** `docker compose exec backend sh -c 'cd /app &&
  .venv/bin/python -m pytest ...'` is the only working form. System Python
  has no deps; `pytest` CLI isn't on PATH; the venv must be explicitly
  invoked from `/app`. This is the second session to rediscover this.
- **Evidence:** Session-start `pytest` invocation failed with "executable
  not found"; `python -m pytest` failed with "No module named pytest";
  `.venv/bin/python -m pytest` from `/app` worked first try and every
  subsequent time.
- **Applies when:** Any test/script invocation on the wairz backend
  container. Already proposed as a CLAUDE.md addition in the
  classifier-patterns postmortem — the fact this session rediscovered it
  is evidence it should have landed there already.

### 8. Distinct-CVE dedup at the aggregate boundary, preserve rows at the DB
- **Description:** Tier 4 of the CVE matcher mirrors each linux-kernel CVE
  onto every kernel_module blob by design — O(CVEs × modules) rows. The
  aggregate "found N matches" number was `len(rows)` = 185,260 on DPCS10.
  Fix: dedup by distinct CVE ID at the router response, preserve rows in
  the DB so per-blob queries still work. Row count still available in the
  response as an explicit `rows` field for power users.
- **Evidence:** DPCS10 aggregate dropped 185,260 → 1,193 distinct CVEs
  with the full breakdown split into `hw_firmware_cves` vs `kernel_cves`
  vs `kernel_module_rows`. No database churn; no loss of drill-down.
- **Applies when:** A system produces deliberately-exploded projection
  rows for drill-down but displays an aggregate to users. Dedup at the
  display boundary, not at the persistence layer. Preserve the row count
  as a separate field for transparency.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Three role-specific parsers instead of extending `mtk_lk` | ATF, GenieZone, tinysys have genuinely different payload formats (MTK TEE wrapper, raw AArch64, Cortex-M vector table). One parser would be a switch statement masquerading as a module. | Correct — each parser is ~150 LOC, focused, testable. Classifier dispatches by name. Future additions (cam_vpu Xtensa, modem) slot in trivially. |
| CVE-2025-20707 fingerprint lives in the parser, not in bulletin YAML | Parser has the version/date values at hand; fingerprint is a tiny (≤20 LOC) version comparison; zero infrastructure dependencies. Bulletin YAML is the right home for broad coverage (hundreds of CVEs) but wrong for single-CVE version-pin work. | Correct — ships a concrete vulnerability flag on real firmware on day one, before Phase C5's bulletin ingester lands. |
| Pseudo-CPE namespace for MTK subsystems (`cpe:2.3:a:wairz-derived:...`) | NVD doesn't accept subsystem CPE submissions via API. Making the non-authoritative nature explicit in the CPE string prevents downstream consumers from treating these as official. | Deferred to Phase C — scaffolding ready in `extract_subcomponent()`. |
| Subcomponent stored in JSONB `metadata.mtk_subcomponent`, not a new column | Avoids schema churn. The matcher already reads metadata values in Tier 3; adding another key costs nothing. Column would be premature normalization. | Correct — no migration needed; metadata is flexible enough for the whole confidence-scoring feature. |
| Kernel-tier CVE projection kept, confidence downgraded to "low" | Per-blob drill-down needs the projection; removing it would break a working feature. But it shouldn't be in the headline aggregate. Confidence tag lets UI tier it into a "Dismissed" bucket without losing data. | Correct — preserves functionality, removes noise from default view. |
| Stub detection over parse-error for 528-byte md1rom | Emitting `partition_size: 1.9GB` is worse than emitting nothing. Small files with known "stubbable" partition names (md1rom, md1dsp on modem-less SKUs) get a dedicated `stub_descriptor=true` flag and a note explaining where real payload would live. | Correct — user sees "partition placeholder — no firmware payload" instead of garbage numbers. |
| Sub-image walker uses 16-byte alignment, not 0-pad | Empirical observation on SCP (loader at 0x0 size 0x438, next header at 0x640 = aligned up from 0x638). Every MTK container respects 16-byte alignment between sub-images. | Correct — walker handles every DPCS10 blob without per-format special cases. |

## Applicability note

The shape of this session's work repeats well:

1. **Observation → hypothesis → on-disk verification → parser.** Each new
   format started with user-visible symptoms (nonsense metadata, missing
   CVEs, partial extraction), then research proposed a structure, then a
   ~20-line docker-exec verification read real bytes, then the parser
   implemented the confirmed structure.
2. **Parallel research tracks (2-3) while preparing the substrate.**
   Three tracks is enough to cover format + integration + data-feed
   concerns simultaneously; the primary session handles planning and
   on-disk verification.
3. **Vulnerability fingerprints in the parser when the signal is extractable
   and the threshold is pinned.** The CVE matcher's YAML is for breadth;
   parsers are for depth — when a single CVE has a precise version
   threshold you can test in the binary, ship it inline.
4. **Live-verify against the real firmware that revealed the bug.** Every
   commit in this session ran `detect_hardware_firmware()` on DPCS10 before
   being committed. Tests are good; end-to-end runs catch integration bugs
   tests miss.

Next session (Phase C4) will execute the confidence scoring + UX tiering
that Track 3 designed — research already banked in `.planning/knowledge/`.
