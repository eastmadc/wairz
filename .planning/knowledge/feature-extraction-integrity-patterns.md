# Patterns: Extraction Integrity Campaign

> Extracted: 2026-04-17
> Campaign: `.planning/campaigns/completed/feature-extraction-integrity.md`
> Postmortem: `.planning/postmortems/postmortem-feature-extraction-integrity-2026-04-17.md`
> Audit entries: 42 matched (campaign-period audit.jsonl)

## Successful Patterns

### 1. Stop-the-bleeding → architectural-fix → migration sequencing

- **Description:** Phase 1 fixed 6 upstream silent-drop sites purely in the extraction layer (no helper, no consumer changes). Phase 2 introduced the `get_detection_roots` helper. Phase 3a/3b migrated consumers. Each phase could have shipped standalone.
- **Evidence:** Commits 72a2049 → ceade9a → 0d11d07 → bbf92b1. No commit rolled back. Test counts monotonically increased 192 → 212 → 241 → 244.
- **Applies when:** Any campaign that combines "data is being lost upstream" with "consumers aren't handling what we give them." Sequencing matters because fixing consumers first gives them more to work with, but fixing bleeding first makes the data _correct_ before you spread it.

### 2. 4-scout research-fleet with ~1500-word briefs per angle

- **Description:** Spawned 4 parallel scouts (upstream gaps, downstream consumers, live DB audit, architectural fix design) before writing any code. Each produced a ~1500-word implementation-ready brief. Synthesized into REPORT.md.
- **Evidence:** `.planning/research/fleet-wairz-data-loss-audit/` — 6,000 words of briefs + REPORT.md that drove the intake file + campaign file + Archon delegation prompts.
- **Applies when:** The bug report is "narrow-sounding but might be systemic" — you need wide+deep investigation before committing to a scope. Cheap compared to mid-campaign scope changes.

### 3. Live DB audit as end-condition evidence

- **Description:** Scout 3 didn't just read code — it queried the production DB for every firmware row, compared on-disk file counts vs detected blob counts, and produced per-firmware projected deltas.
- **Evidence:** `live-db-audit.md` predicted +800 to +1,218 blobs; actual backfill delivered +296. The gap itself was informative (Phase 3a already absorbed most of it), turning "unclear success" into "quantified outcome."
- **Applies when:** A campaign promises to improve detection, enrichment, or coverage. Live DB audit gives measurable before/after.

### 4. Helper + JSONB cache > new schema column

- **Description:** Scout 4 evaluated 4 options (helper / new column / layout normalization / new table). Chose helper + JSONB cache because (a) no migration cost, (b) Wairz convention already favors `device_metadata` JSONB for derived state, (c) cache is invalidation-safe (each path validated for existence on read).
- **Evidence:** `architectural-fix-design.md`. Phase 2 delivered in ~250 LOC of helper + 300 LOC of tests. Zero migrations.
- **Applies when:** You need to add derived/computed state per-row to an existing ORM model, AND the computation is cheap enough to re-run on cache miss. Use a new column only when the value needs to be queryable or indexed.

### 5. Shallow-container rescue heuristic

- **Description:** When the primary-root resolution returns a container with ≤1 qualifying child, check the parent for raw firmware files (strict extensions at file level — non-recursive). If found, promote parent as an additional root rather than replacing.
- **Evidence:** Applied in `firmware_paths._compute_roots_sync`. On RespArray: rescued the 11 DTBs that would otherwise have been invisible. Added without breaking any DPCS10 tests (29/29 firmware_paths tests still pass).
- **Applies when:** The "obvious" primary path is a shallow shim (symlink dir, one archive dir, etc.) and the real content lives one level up. Safer than always climbing because gated by strict-extension file-level scan.

### 6. Mandatory grep check after migration phases

- **Description:** After each consumer-migration phase, grep the backend for remaining `firmware.extracted_path` reads. Classify each: legitimate-per-binary (keep) vs. needs-migration (fix now) vs. assignment (not a read). Any unclassified → finish before next phase.
- **Evidence:** Applied at end of Phase 3a and 3b. Caught 10+ remaining reads; classified into allowlist of 10 legitimate files + 3 MCP tools. Became the seed for the Phase 5 regression-guard test.
- **Applies when:** Any mass-migration phase where you're replacing a single API with a multi-value one across many call sites.

### 7. Integration test as end-condition

- **Description:** Phase 3a's acceptance gate was `test_mtk_parsers_fire_on_dpcs10_shape_fixture` — a fixture that reproduces the original DPCS10 shape, runs the detector, asserts the MediaTek parsers populate metadata. Not "it compiles," not "units pass" — "the original bug is actually closed."
- **Evidence:** The test distinguishes "refactor is syntactically done" from "refactor actually fixes the user-reported bug." Without it, Phase 3a could have shipped a half-fix.
- **Applies when:** The campaign is driven by a concrete user-reported bug. Always construct the fixture that reproduces the user scenario; make it the end-condition.

### 8. Live verification every ≥2 phases

- **Description:** After Phase 4 (backfill), manually triggered detection on the RespArray firmware to verify the campaign's fix was live. This discovered the multi-archive gap (commit 84d94ce) that unit tests hadn't anticipated.
- **Evidence:** The live-found fix commit is in the campaign history. The bug wouldn't have been caught by the 241-test suite.
- **Applies when:** Any campaign touching extraction, detection, or parsing of heterogeneous real-world inputs. Mocks cannot anticipate every vendor's quirks.

### 9. Regression-guard test via grep over allowlist

- **Description:** `test_no_new_direct_extracted_path_reads` walks backend/app/services + backend/app/ai/tools, greps for `firmware.extracted_path` reads outside a maintained allowlist. Fails if a new one appears.
- **Evidence:** Added in Phase 5. Paired with a harness quality rule that flags the same pattern at pre-commit time.
- **Applies when:** You've just migrated away from an anti-pattern and want to prevent its reintroduction. Cheap + explicit + self-documenting.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 4-scout fleet before any code | Bug sounded narrow but the intake suggested systemic; cheap to verify | Confirmed systemic; justified 5-phase campaign |
| Helper + JSONB cache (Option A) | Matches Wairz convention; no migration | No migration cost; 250 LOC helper |
| Store detection_roots in device_metadata JSONB | Invalidatable, cheap, preserves other metadata keys | Cache hits on re-backfill; no serialization issues |
| Per-binary services keep firmware.extracted_path | emulation/fuzzing resolve ONE binary for QEMU/AFL; not a walk | Allowlist documented; regression guard respects it |
| Recursive nested extraction after ZIP unzip | Multi-archive medical firmware (RespArray) pattern | Live fix commit (84d94ce) — caught another device class |
| Shallow-container rescue via parent promotion | RespArray's target/extracted/ had only 1 child | 0 → 11 blobs on live firmware |
| Keep _pick_detection_root alive (deprecated) | Callers still use it internally; Phase 5 cleanup scope | No breaking change; migration path documented |
| Skip Option B (new column) | 4+ session backfill cost + double-write hazard | Saved ~3 sessions |
| Skip Option C (layout normalization) | Breaks detect_architecture/os/kernel which assume unix rootfs | High regression risk avoided |
| Stamp detection_audit on every detection (not just backfill) | Observability without re-walking disk | Orphan rate visible via /audit |
| Scope-reduce NXP iMX RT classifier patterns to follow-up | Already a 5-phase campaign; keep it atomic | Follow-up intake queued (cf69b6c) |

## How to apply these patterns on the next campaign

- **For any "data loss" or "missing detection" bug:** run 4 scouts FIRST — upstream, downstream, live-DB-audit, architectural-fix-design. 1 session of research saves 2-3 sessions of false starts.
- **For any consumer-migration phase:** follow each migration with a grep over the backend to identify what's left. Classify residue into (a) truly done, (b) legitimate, (c) needs more work. Don't ship a half-migration.
- **For any extraction/parsing campaign:** construct a real-firmware fixture fitting the original user bug. Use it as an integration-test end condition. Then run live verification on actual production data.
- **Before introducing a new column:** try helper + JSONB first. Columns are forever; helpers evolve.
- **When adding a regression guard:** ship BOTH a test AND a harness quality rule — belt + suspenders for different enforcement timing.

---

## Follow-up learnings — discovered 2026-04-18 (24 hours post-campaign)

### 10. Container-as-detection-root is a logical extension of Pattern #5

- **Description:** The shallow-container rescue (#5) promotes a PARENT when
  a scan yields ≤1 qualifying child.  A sibling case surfaced 24h later:
  when Phase 1's `_relocate_scatter_subdirs` moves `.img`/`.bin` files OUT
  of the scatter subdir INTO the extraction container root, those files
  are at the container's top level — not inside a subdir.
  `_scan_container_for_roots` only examined subdirectories, so the
  relocated files were invisible to detection.  Fix: promote the
  container itself when `_dir_has_raw_image(container)` returns True.
- **Evidence:** DPCS10 firmware `0ed279d8` post-relocation lost 14 MTK
  blobs (lk / tee / gz / preloader / scp / sspm / spmfw / md1dsp /
  modem / cam_vpu×3 / dtbo). Fixed in `firmware_paths._compute_roots_sync`
  with `test_post_relocation_layout_includes_container` +
  `test_linux_rootfs_only_container_not_included` regression guards.
- **Applies when:** Any detection-root helper that scans SUBDIRECTORIES
  of an extraction container.  If the extraction pipeline can produce
  raw firmware files at the container's top level (relocation,
  single-binary uploads, certain tar layouts), the container itself
  must qualify too — gated by the same strict-extension file-level
  check that prevents over-inclusion for pure Linux rootfs cases.

### 11. User-data partitions are not firmware — skip before sparse→raw

- **Description:** Android factory images ship `userdata.img`
  (3+ GB of mostly-zero declared sparse), `cache.img`, `metadata.img`,
  `persist.img`, `misc.img` — none of which are firmware code.
  Converting them via simg2img inflates the extraction tree into
  multi-GB empty space that trips the extraction-bomb cap (default
  10 GB) while adding zero analytic value.  Skip them by base-name
  (plus A/B slot variants `_a`/`_b`) before any conversion.
- **Evidence:** DPCS10 (1.1 GB zip) was tripping
  `Extraction bomb detected: total size (10256MB) exceeds limit (10240MB)`
  because userdata alone expanded to 3072 MB and super.img.raw was
  retained at 9216 MB.  After skip + removal: extraction drops to
  ~5 GB total.  `_is_user_data_partition` helper + 9 tests shipped
  in `test_unpack_integrity.py`.
- **Applies when:** Any firmware-analysis pipeline processing Android
  OEM images.  Generalisable to other ecosystems where the image
  format carries a "factory-reset" partition alongside firmware code.

### 12. Super.img (LP2 container) is redundant once inner partitions extracted

- **Description:** After `_scan_super_partitions` successfully carves
  every detected inner partition (system, vendor, etc.) into
  `rootfs/partition_N_*/`, the original super.img.raw is an LP2
  container with no downstream parser.  The Phase 3 MediaTek parsers
  (mtk_preloader, mtk_lk, mediatek_modem) target LEAF partitions, not
  the super wrapper.  Keeping the raw (~9 GB on typical Android
  firmware) contributes nothing and double-counts against the bomb
  cap.  Remove only when extraction is COMPLETE (`extracted == total`);
  keep on partial extraction so corrupt inner partitions remain
  recoverable from the raw bytes.
- **Evidence:** `_scan_super_partitions` signature changed from
  `-> int` to `-> tuple[int, int]` so callers compare counts.  Caller
  in `_extract_android_ota` deletes super.img.raw on all-success,
  logs + retains on partial.  Saves ~9 GB per Android firmware.
- **Applies when:** Any container-format parser (LP2, DTB FIT, APEX
  modules, GPT disk images) where the container is purely structural
  and parsing targets the contents, not the wrapper.  Ask: "is there
  a downstream tool that reads the raw container bytes?"  If no, the
  raw is safe to drop once extraction succeeds.

### 13. Post-extraction bomb check shouldn't wipe a successful extraction

- **Description:** `check_extraction_limits` walking extraction_dir
  after the Android fast path caused `shutil.rmtree(extraction_dir)`
  on any breach — including 16-MB-over-cap cases where extraction had
  produced a complete rootfs + 8 super-partitions + all scatter
  blobs.  User-visible symptom: "Unpacking Failed" for a successful
  extraction.  Fix: reorder so `_analyze_filesystem` runs first; if
  it finds a rootfs, keep the extraction with a WARNING.  Only
  `rmtree` when analysis ALSO fails (true zip-bomb).  Applied to all
  four call sites in `unpack.py` (android / partition_dump_tar /
  linux_rootfs_tar / fallback chain).
- **Evidence:** Pre-fix: DPCS10 extraction wiped at line 588 after
  10256/10240 MB trip.  Post-fix: bomb-cap trip on successful
  extraction logs `WARNING: ... — extraction kept because filesystem
  analysis succeeded.` rather than rmtree'ing.
- **Applies when:** Any defensive cleanup coupled to a defence-in-depth
  budget.  The budget catches bombs; don't let it discard legitimate
  large work.  Separate the "budget tripped" signal from the
  "nothing usable was produced" signal.
