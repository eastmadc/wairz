# Anti-patterns: MTK subsystem parsers + CVE precision (2026-04-17 session)

> Extracted: 2026-04-17
> Commits: 431e3ec, 9e1de6c, 7ab35b5

Failure modes and pitfalls encountered during this session's three-commit
body of work on MediaTek hardware firmware parsing + CVE matching precision.
Most were caught during empirical verification; the session shipped clean
because they were corrected before code landed.

## Failed Patterns

### 1. Trusting vendor magic alone for classification when one magic wraps many roles
- **What was done:** Prior state of the MTK classifier matched magic
  `0x58881688` and returned `bootloader/mediatek/mtk_lk` for every such
  blob — treating the magic as a unique identifier for the LK bootloader.
- **Failure mode:** MediaTek's LK container format wraps every subsystem
  firmware — ATF (TEE), GenieZone (hypervisor), SCP (sensor co-processor),
  SSPM/SPMFW (power), modem stubs, camera VPU, logo. All share the same
  magic. Result on DPCS10: 12 blobs in 1 category, when they should have
  been in 7 categories with subcomponent-specific parsers.
- **Evidence:** User-visible bug ("13 of 24 blobs are tagged
  bootloader/mtk_lk but by filename they're clearly NOT bootloaders"),
  confirmed in the DB: `SELECT category,count(*) FROM
  hardware_firmware_blobs WHERE format='mtk_lk'` → 12 bootloader / 0
  anything else.
- **How to avoid:** When a magic number wraps multiple roles, treat the
  magic as a format-family identifier only; dispatch the actual category
  on the embedded role field (partition name, component tag, container
  type). If the wrapper format doesn't expose the role in the first N
  bytes the detector reads, widen the magic-read buffer for that
  specific magic rather than shipping ambiguous classifications.

### 2. Reading structure fields without bounds-checking against file size
- **What was done:** The legacy `mediatek_lk.py` parser read u32 fields
  (`file_info_offset`, `size`, `magic_version`) from offsets 0x04, 0x08,
  0x0C and dumped them verbatim into metadata.
- **Failure mode:** On newer MTK SoCs (MT8788 / Genio 700), the header
  layout is compact — the partition name lives at offset 0x08–0x10. The
  parser interpreted the ASCII name bytes as integer fields, emitting
  `partition_size: 1915839597` (~1.9 GB) from a 528-byte file. Silent
  corruption of DB rows for every MTK blob on every modern firmware.
- **Evidence:** DPCS10 blob table showed every `mtk_lk` blob with a
  partition_size field orders of magnitude larger than its actual file
  size. Ghidra-looking numbers (0x72316d64 = 1.9GB) turned out to be
  "md1r" as ASCII.
- **How to avoid:** Any struct field that claims to be a size, offset, or
  count MUST be sanity-checked against the file's actual size before
  being emitted. If `struct_field > file_size` or `struct_field < header_size`,
  suppress the field entirely with a diagnostic flag rather than
  emitting obviously-wrong data. Trust the user/UI less, suppress more.

### 3. Cartesian CVE projection displayed as "distinct match count"
- **What was done:** Tier 4 of `cve_matcher.py` mirrors each linux-kernel
  CVE onto every kernel_module blob for per-blob drill-down. Router
  returned `{"count": len(matches)}` — the cartesian row count.
- **Failure mode:** 1,193 kernel CVEs × 149 kernel_module blobs = 177,939
  rows. UI displayed "Found 185,260 matches" as the headline figure.
  Users selecting individual blobs saw "No CVE matches" because the
  modem.img they clicked correctly had 0, while the aggregate counted
  kernel projections elsewhere. Trust-destroying UX: big number nobody
  can triage, and the number doesn't add up from the per-blob clicks.
- **Evidence:** User observation: "185,260 matches is implausible...
  when I click modem.img it shows 'No CVE matches'". Root cause traced
  to `hardware_firmware.py:167` returning `len(matches)`.
- **How to avoid:** When a system persists deliberately-exploded
  projection rows for drill-down, never display the row count as the
  aggregate. Dedup by the identity-bearing key (cve_id here) at the
  response boundary. Expose the row count as an explicit separate field
  (`rows`) for power users. Never hide the denominator — "1,193 CVEs
  across 149 modules" is honest; "185,260 matches" is not.

### 4. Suggesting deep-offset magic checks that don't fit the detector's read buffer
- **What was done:** Research briefs for iMX-RT Cortex-M firmware proposed
  a `BOOT_DATA` magic check at offset 0x1000 (4 KB). Research briefs for
  MTK kernel images proposed parsing GFH chains at arbitrary offsets.
- **Failure mode:** The hardware firmware detector reads only 64 bytes of
  magic per file (hard-coded `_MAGIC_READ_BYTES = 64`). Any magic check
  beyond byte 63 is structurally impossible at the classifier layer —
  it has to move to the parser (which reads the whole file) or the
  detector's read buffer has to widen. Prior campaign (classifier-patterns)
  hit this too.
- **Evidence:** Second recurrence across two sessions of this exact
  mismatch — research proposes deep offset, classifier can't reach it,
  fix is always "move detection down to parser" or "rely on filename".
- **How to avoid:** Before accepting a research brief that proposes a
  magic-byte check, grep the detector's magic-read size constant and
  verify the offset is reachable. If not, explicitly note in the plan
  that the check has to move into the parser (where full-file reads are
  cheap) or name the widening as a prerequisite.

### 5. "MMM\\x01" GFH chain hypothesised without reading the bytes
- **What was done:** Sub-agent research proposed that MTK LK containers
  carry an inner "MMM\\x01" (0x4D4D4D01) GFH chain as the real metadata
  carrier, citing U-Boot `tools/mtk_image.c` and bkerler/mtkclient.
- **Failure mode:** On DPCS10 the MMM chain does not exist. Only the LK
  container header (0x58881688) + an LK_FILE_INFO marker (0x58891689) at
  offset 0x30 + 0xFF padding to 0x200. Implementing a MMM walker would
  have returned zero results on every real blob, masking format errors.
- **Evidence:** `data.find(b"MMM\\x01")` returned -1 on cam_vpu1.img during
  the empirical verification pass.
- **How to avoid:** Research briefs describe vendor specs and OSS tool
  expectations. Vendors ship different variants; firmware-in-the-wild
  rarely matches the spec exactly. Always read 256 bytes of the actual
  file and grep for the markers the research claims exist before
  writing a walker around them.

### 6. ToS-ignorant scraper designs
- **What was done:** Early draft of the MTK bulletin scraping plan focused
  on feasibility — URL structure, robots.txt, HTML stability — without
  reading the vendor's Terms of Use.
- **Failure mode:** MediaTek's ToU explicitly prohibits derivative works
  and redistribution. A scraper that commits extracted data to a public
  GitHub repo would violate ToS even though robots.txt allowed crawling.
  Robots.txt and ToS say different things.
- **Evidence:** Track 1 research surfaced this before any scraper code
  was written: "MediaTek's ToU prohibits derivative works + redistribution.
  ... paid-feed partnerships (Exiger/VulnCheck) apparently use paid feed
  partnerships or NVD + Android Security Bulletin, not raw MTK PSB
  scraping."
- **How to avoid:** When designing any data-ingestion feature, check
  vendor ToS alongside robots.txt. Hybrid sourcing (CC-BY primary +
  ToS-constrained gap-fill gitignored per-deployment) sidesteps
  redistribution issues. If the tool will be distributed commercially,
  flag the ToS concern to the user before writing code — it's a
  business question, not an engineering one.

### 7. Format-family parsing that assumes one-file-one-blob
- **What was done:** Initial sketch of the subsystem parsers treated each
  `.img` file as a single blob to parse end-to-end.
- **Failure mode:** Every MTK container observed on DPCS10 carries
  multiple sub-images — primary payload + trailing 1008-byte `cert2`
  signature + sometimes a secondary payload (`atf_dram`, `unmap2`,
  `tinysys-scp-CM4_A`). Treating the whole file as "the blob" would
  misread offsets, extract the wrong bytes for Ghidra, and silently miss
  the secondary payload (which is often the real content — the SCP
  loader is 1 KB, the real SCP image is 115 KB, inside the same file).
- **Evidence:** Empirical sub-image scan found 2-4 sub-images in every
  subsystem container. SCP file's "primary" sub-image is a tiny loader
  stub; the largest non-signature sub-image is the real payload.
- **How to avoid:** For any vendor container format, write a sub-image
  walker BEFORE writing role-specific parsers. The walker's output
  (`[(name, offset, size, is_signature)]`) is what role-specific parsers
  consume. "Select largest non-signature sub-image" is a common
  heuristic but not universal — name-based selection (`.*_CM4_A$`, etc.)
  is more reliable when the container carries a known loader/main split.

### 8. Emitting Ghidra import params without a "no_ghidra" escape hatch
- **What was done:** Early `mediatek_tinysys.py` sketch always emitted
  `ghidra_import_params` in metadata, on the assumption that every
  stripped payload would be Ghidra-importable.
- **Failure mode:** SPMFW isn't ARM code at all — it's MediaTek's
  proprietary PCM state-machine microcode ("2MPS" magic). Ghidra has no
  language spec for MTK PCM; trying to import would fail noisily or
  import as AArch64 and produce garbage disassembly.
- **Evidence:** Research track 2 flagged: "Ghidra shouldn't try to
  disassemble it with Ghidra — there is no Ghidra language spec for MTK
  PCM."
- **How to avoid:** When emitting downstream-tool integration params, ship
  an explicit `no_<tool>_import=true` flag for known non-disassemblable
  formats. Parsers should acknowledge their limits; consumers should
  check the flag before spawning expensive headless tooling.

### 9. Hot-patching containers via `docker compose cp` while claiming "done"
- **What was done:** During Phase C tests, a classifier bug surfaced (spmfw
  routed to `dsp` instead of `mcu`). Fixed on disk, then pushed the
  updated file into the running backend container via `docker compose cp`
  to re-run tests without a full rebuild. Tests passed. Committed.
  Claimed the session was "live across all of Docker."
- **Failure mode:** The worker container (and frontend, entirely) were
  still running the PRE-fix image. The `docker compose cp` mutates the
  live filesystem of ONE container, not the underlying image. Next
  container restart would revert to the stale image. Worker handles
  background detection jobs — user-facing firmware uploads would run the
  stale classifier and reproduce the bug I thought I'd fixed. Frontend
  was running a 21-hour-old build missing every UI change this session.
- **Evidence:** User observation: "are all changes live across all parts
  of docker?" Inspection showed backend classifier.py mtime was
  `18:35:25` (post-fix via cp) but worker's was `18:32:30` (pre-fix,
  from the last build). Image IDs diverged (`ee3c8719990c` vs
  `e33bc80b3115`) even though worker + backend share a Dockerfile.
  Frontend image creation time was `2026-04-16 21:29:28` — before any
  session work.
- **How to avoid:** CLAUDE.md rule #8 literally says "rebuild worker
  whenever you rebuild backend" — and this is the stricter version:
  **never** claim a change is live via `docker compose cp` unless the
  next step is a full rebuild. `cp` is for the iteration cycle only;
  the commit-ready state requires `docker compose up -d --build backend
  worker frontend` (or whichever services touched code). Verify with
  `docker compose ps --format "{{.Service}}\t{{.CreatedAt}}"` that all
  relevant services were recreated in the last minute. Meta-lesson: if
  you write a "run tests via .venv/bin/python" pattern into a knowledge
  file and then fail to rebuild before shipping, you've learned nothing.

### 10. Parser-detected CVEs that live only in blob metadata
- **What was done:** The GenieZone parser shipped an inline
  CVE-2025-20707 fingerprint that populates
  `blob.metadata["known_vulnerabilities"]`. Tests passed. Live
  verification confirmed the metadata made it to the DB.
- **Failure mode:** The UI's "CVE matches" panel reads from
  `sbom_vulnerabilities` (matcher output), not from blob metadata. So
  the fingerprint fired, persisted, and was completely invisible to the
  user until they clicked into the blob's raw "Parser metadata" JSON
  dump — the exact surface where they wouldn't think to look for a CVE.
  The aggregate CVE count didn't include it. The HBOM export didn't
  include it. Worse: the session's `/learn` output claimed live
  verification was a successful pattern.
- **Evidence:** User observation after the session shipped: "I don't
  see versions or CVEs" on the DPCS10 firmware view. The data was
  there; the rendering path didn't look for it.
- **How to avoid:** When a parser emits structured data that overlaps
  with an existing pipeline (CVE matcher → sbom_vulnerabilities → UI),
  thread the data through the EXISTING pipeline rather than parking it
  in metadata. For Phase C the fix is a new Tier 0 matcher that reads
  `blob.metadata.known_vulnerabilities` and emits `CveMatch` objects
  into the same flow as Tier 3/4/5 — zero UI changes needed. Lesson:
  visible state machines beat invisible ones. If your feature writes to
  a different table than the reader queries, the feature is broken even
  if the data is correct.

## Recurring themes

- **Research proposes, disk verifies.** Four of the eight anti-patterns
  above trace to accepting a research hypothesis without reading the
  actual bytes. The fix is structural (always do a ~20-line docker-exec
  byte-read before writing a parser) not cultural.
- **Silent data corruption > noisy failure.** The 1.9GB partition_size
  emission (#2), the 185,260 CVE count (#3), and the hypothetical
  MMM-walker-returns-empty (#5) all share the shape: parser/service
  doesn't crash, but emits numbers that look plausible until someone
  notices they don't add up. Fail loudly, suppress ambiguous output.
- **Don't ignore legal when designing data pipelines.** robots.txt is
  about load, not about redistribution. ToS and content licensing are
  separate questions that need separate checks.
