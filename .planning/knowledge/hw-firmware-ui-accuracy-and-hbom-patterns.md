# Patterns: HW Firmware UI Accuracy + HBOM Bloat Fix

> Extracted: 2026-04-17
> Session: `626b3752` (no formal campaign — direct execution under `/do continue`)
> Commits: `2428f9f` UI accuracy pass · `79e083e` HBOM dedup · `f8777b1` subtitle
> Companion: `.planning/knowledge/mtk-mcu-coverage-patterns.md` (earlier in same session)

## Successful Patterns

### 1. Take the screenshot at face value, then audit live data
- **Description:** Both fixes started from a single user observation pasted as
  a UI dump or a complaint ("CVEs (selected): 1" while reality was 27;
  "HBOM seems excessively large"). Before touching code, I always pulled
  the actual data: `curl /cve-aggregate`, `ls -la dpcs10-hbom.json` (222 MB),
  `python3 -c "json.load(...) | len(vulnerabilities)"` (177,130 entries).
  The user-visible symptom and the under-the-hood reality match well, but
  not perfectly — the screenshot says "1" because the label is per-blob,
  not because the matcher is broken.
- **Evidence:** UI dump showed gz.img with parser_version_pin CVE working
  fine; the complaint was about the AGGREGATE being mis-labeled. Without
  reading the page-component source, I'd have re-run the matcher
  unnecessarily. Without measuring the HBOM file directly, I'd have argued
  about "large" without a number to anchor against.
- **Applies when:** A user reports a UI/output anomaly. Pull the actual
  rendered HTML, the actual API response, the actual file size before
  forming a hypothesis. The bug is rarely where the user thinks it is.

### 2. Free-win bundle: validators surface adjacent bugs, fix in same commit
- **Description:** Running `check-jsonschema` against the deduped HBOM
  surfaced TWO pre-existing CycloneDX 1.6 violations
  (`type: "hardware"` not in v1.6 enum, `modelNumber` not allowed at
  component top-level). Neither was caused by this session's work. Both
  were ~5-LOC fixes in the same file. Bundled into the HBOM commit
  instead of leaving as a TODO or spawning a new ticket.
- **Evidence:** Commit `79e083e` ships dedup + spec-compliance fixes
  together. The dedup was the headline (95% size reduction); the
  spec-compliance fixes made the HBOM actually consumable by
  Dependency-Track and other CycloneDX-validating tooling. Both
  benefited the same downstream consumer.
- **Applies when:** A validator or test surfaces small scope-adjacent
  bugs while you're working on a related fix. If they're in the same
  file and < 30 LOC, fold them in. If they cross modules or are
  larger, spawn a separate ticket. Threshold: would a reviewer
  expect to see them split out?

### 3. Tier-priority over length-wins for "best representative" selection
- **Description:** When deduping HBOM vulnerabilities by `cve_id`, multiple
  rows may carry different descriptions (one per match tier). Research
  recommended "longest non-empty description wins". I used semantic
  tier-priority instead: `parser_version_pin > curated_yaml >
  kernel_subsystem > chipset_cpe > nvd_freetext > kernel_cpe`.
- **Evidence:** Test `test_hbom_picks_highest_priority_tier_for_description`
  asserts CVE-2025-20707 keeps the parser_version_pin text
  ("GZ_hypervisor 3.2.1.004 predates Feb 2026 PSB fix") instead of
  getting overwritten by a generic kernel_cpe description. Length-wins
  would have picked the verbose-and-generic kernel text. Tier-priority
  preserves the source we trust most for that CVE.
- **Applies when:** Deduplicating multi-source records into one
  canonical entry. If "most authoritative source" has a clear ordering,
  use it. If not, fall back to length or freshness.

### 4. Spec-citing commit messages with tool-comparison evidence
- **Description:** Commit `79e083e` body cites the canonical CycloneDX 1.6
  spec section URL, AND named two reference implementations (Trivy emits
  the canonical roll-up shape; grype emits the per-component shape with
  an acknowledged TODO in their source). The decision to converge on
  Trivy's shape isn't a judgment call — it's the spec.
- **Evidence:** Reviewer can verify the design in 30 seconds via the
  cited URLs without re-running the deep-research agent. Future authors
  who hit similar dedup questions have a precedent.
- **Applies when:** Implementing against a spec where multiple tools
  diverge. Cite the spec section URL AND the reference impl that matches.
  Saves 10-30 minutes per future reader.

### 5. Read-only aggregate endpoint sibling to write-side mutator
- **Description:** Frontend needed a firmware-wide CVE counter on every
  page load. Could have used `POST /cve-match` (which RUNS the matcher,
  ~14s on DPCS10) but that's wasteful and writes new rows. Added
  `GET /cve-aggregate` returning the counts of what's already persisted
  (~50ms read-only query). Kept `POST /cve-match` for explicit "rescan"
  intent.
- **Evidence:** Page header renders in <100ms instead of stalling on
  matcher run. Two endpoints with crisp semantics: GET = "what do we
  know", POST = "look harder". User can hit Refresh without thrashing
  the matcher.
- **Applies when:** Adding a frontend display of expensive computed
  data. Add a cheap GET sibling for display, keep the expensive POST
  for explicit user-triggered recompute. Don't conflate "show me what
  you have" with "go compute fresh".

### 6. Single GROUP BY decoration over N+1 per-row fetch
- **Description:** The list endpoint needed `cve_count` + `max_severity`
  per blob row. Naive: GET each blob's CVEs separately (260 round-trips).
  Fix: one `SELECT blob_id, COUNT(*), MAX(severity_rank) GROUP BY blob_id`,
  built into a dict, looked up O(1) when serializing each blob. The
  CASE-rank for severity MAX() is a small SQL trick — Postgres can MAX()
  on the integer rank, then we map back to the string label in Python.
- **Evidence:** `router.py:list_blobs` runs two queries total (blobs +
  rollup) regardless of blob count. Latency stays flat as N grows.
- **Applies when:** Decorating a list response with computed-from-related
  data. GROUP BY at the SQL layer beats per-row queries every time.
  Use CASE-rank for non-numeric MAX() needs.

### 7. CASE-rank for non-numeric column aggregation
- **Description:** Postgres `MAX()` doesn't natively understand "critical
  > high > medium > low". Used `case((sev=='critical',4),(sev=='high',3),...)`
  to project to integer ranks, MAX() the integers, then map back via
  `_RANK_TO_SEVERITY`. Lets a single GROUP BY return the highest severity
  per group without per-row Python aggregation.
- **Evidence:** `hbom_export.py` (already had _SEVERITY_RANK from prior
  work) and `routers/hardware_firmware.py:_severity_case()` both use this.
  Single query returns max severity per blob.
- **Applies when:** Aggregating string-enum columns where MAX() on the raw
  value would be alphabetic-not-semantic. The CASE injects the ranking
  the schema doesn't have natively.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Roll up HBOM vulns by cve_id with affects[] array | CycloneDX 1.6 spec canonical shape; Trivy emits this; grype is the outlier | 222 MB → 11 MB (95% reduction); validates clean against official schema |
| Tier-priority for canonical description | parser_version_pin descriptions are short+specific; length-wins would pick generic kernel text | CVE-2025-20707 keeps GZ_hypervisor description |
| Comma-joined `wairz:match_tiers` (single property) over duplicate-name properties | Simpler for JSON consumers; both forms are spec-valid | Loses per-blob tier mapping (acceptable — rolled-up entry doesn't claim per-blob attribution anyway) |
| Add GET /cve-aggregate sibling to POST /cve-match | GET = "what do we know" (fast), POST = "look harder" (slow); UI needs read on every page load | Header renders in <100ms; matcher only runs on explicit user action |
| Single SQL GROUP BY in list_blobs over N+1 per-blob fetch | 260 blob × 4ms RTT = 1s vs single 50ms query | List + badges in one round-trip |
| Bundle pre-existing hw-firmware files (vendor_prefixes, classifier_patterns_test) into MTK MCU commit | Working tree was messy from prior session; cleanup safer than floating diffs | Working tree clean after each commit |
| Force `format="elf"` when classifier matches ELF via YAML pattern | YAML pattern's default is "raw_bin" which would lie about the container; we already validated ELF magic | lib3a.ccu correctly shows format=elf |
| Translate cert2 sub-image presence → signed=signed in MTK parsers | walk_sub_images already saw the signature block; just propagate the verdict | DPCS10 "Not signed: 176→171" (5 false positives gone) |
| Use check-jsonschema against the official remote schema URL (not local cache) | Catches issues local tests miss (the type:"hardware" violation) | Caught two pre-existing CycloneDX violations in same pass |
| Treat the subtitle as truth-bearing copy | "three-tier" was wrong (six tiers exist); category list missed >half what's surfaced | Tighter phrasing names the major buckets without enumerating every category |

## The Validation Ladder (refinement of prior session's "empirical verification ladder")

This session formalized the verification rungs into a repeatable sequence:

1. **YAML/JSON parse** — local syntax check (`python -c "yaml.safe_load(...)"`)
2. **Pytest in container** — unit-level correctness against the rebuilt image
3. **Re-detect + re-match script** — data-flow correctness on real DB rows
4. **Production HTTP endpoint** — `curl POST /cve-match` returns expected aggregate
5. **Spec-validator** (NEW this session) — `check-jsonschema` against the
   official remote schema URL — catches things local tests miss

Rung 5 caught the `type: "hardware"` and `modelNumber` violations that all
prior rungs had missed (because no test had asserted spec validity). Worth
adding the spec-validation rung to the regression suite as a continuous
guard.

## Reusable Helpers Surfaced

- `_severity_case()` in `routers/hardware_firmware.py:51` — CASE-rank for
  Postgres MAX() on severity strings.
- `_RANK_TO_SEVERITY` / `_SEVERITY_RANK` map — share between matcher and
  exporter; consider promoting to a single constants module if a third
  consumer appears.
- `signed_from_subimages()` in `mediatek_gfh.py:330` — translates a
  walk_sub_images() output into a signed verdict; reusable from any future
  MTK parser that uses the LK container layout.
