# Independent review — `feat/pinned-nvd-cache`

**Reviewer:** independent second pair of eyes (adversarial). **Date:** 2026-07-25.
**Branch:** `feat/pinned-nvd-cache` @ `6c9d6079`, 10 commits ahead of `main`, unpushed.
**Scope:** pinned local NVD cache replacing live NVD queries during SBOM vuln scanning,
plus provenance surfacing so a missing/degraded cache cannot read as a clean scan.

**Verdict: MERGE-WITH-FIXES.** The core mechanism is sound and the `_cve_path` fix is
provably complete. The truthfulness guarantee holds for the three surfaces the branch
wired, but does **not** hold end-to-end: one demonstrated false-clean-verdict path
(D1, fixed here) and at least six unmigrated read surfaces (D2, left).

---

## 1. What I verified independently (not taken on trust)

| Claim | How verified | Result |
|---|---|---|
| Cache-first; miss returns `[]` without network | read `_lookup_sync` + `_query_nvd_for_component` | confirmed |
| Only `cache_unavailable` may live-fall-back, gated on `nvd_allow_live_fallback` | code read; `get_settings()` in running container reports `False` | confirmed |
| 369,356 CVEs on the volume | `MANIFEST.json` + full `os.walk` in container | 369,356 files, manifest agrees |
| `_cve_path` bucket fix is complete | **exhaustive oracle** (below) | complete — 0 defects |
| Rule #5 — reads off the event loop | `run_in_executor` in `lookup_cves_for_cpe` | confirmed |
| Migration applied | `\d firmware` → `vuln_scan_provenance | jsonb` | confirmed |
| Worker sees the volume | `docker compose exec worker` → MANIFEST present | confirmed |
| Honest-verdict summary | reproduced in-container (see D1) | confirmed **and broken** in one path |

### `_cve_path` exhaustive oracle (the leading-zero bug)

Not a sample — the whole cache, both directions, run inside the backend container:

```
index vendor_products: 171930   distinct cve ids: 306918
index-referenced CVE ids UNRESOLVABLE: 0
files on disk: 369356           path-mismatch: 0
```

Every one of the 306,918 index-referenced ids resolves to an existing file, and every
one of the 369,356 files on disk round-trips from its own id back to its own path.
Bucket-suffix shapes present in the real feed (`00xx`, `442xx`, `10000xx` for 7-digit
ids) all resolve. **The fix is complete.** The `~8%` loss is closed.

---

## 2. Defects, ranked

### D1 — HIGH — a raising CVE lookup reads as a **clean scan**. *(FIXED in this review, separate commit)*

`backend/app/services/nvd_cache_service.py:267-274` (pre-fix): the per-file guard was
`except (OSError, json.JSONDecodeError)` around the **read only** — nvdlib's
`CVE(...)` / `getvars()` construction sat *outside* the `try` entirely. Two reachable
escapes:

1. **Torn write.** `scripts/refresh-nvd-cache.sh:70-71` streams the feed in with
   `tar -x`. An interrupted extract leaves a file truncated mid-UTF-8 →
   `UnicodeDecodeError` (a `ValueError`, **not** a `JSONDecodeError`) → uncaught.
   This is precisely the half-populated-volume failure the branch's degrade
   detection was built for.
2. **Unexpected record shape.** `getvars()` raises `AttributeError` on a malformed
   record (reproduced in-container: `'str' object has no attribute 'cvssData'`).

Either aborts the **whole lookup** for that CPE. `vulnerability_service.scan_components`
(`:264-276`) swallows per-component exceptions — so the component vanished from the
scan **and** from the provenance histogram. With every lookup raising,
`self._nvd_provenance` stays `None`, and `summarise_nvd_provenance(None)` returns:

```json
{"enrichment_status": "not_applicable", "warning": null, "lookups": 0}
```

**Reproduced end-to-end in the backend container** — truncated one real CVE mid-`é`:

```
RAISED from lookup: UnicodeDecodeError 'utf-8' codec can't decode byte 0xc3 ...
scan_components would SWALLOW: UnicodeDecodeError
resulting scan verdict: {"enrichment_status": "not_applicable", "warning": null, "lookups": 0}
```

That stamp persists to `firmware.vuln_scan_provenance`; REST returns
`nvd_enrichment_warning: null` with `total_vulnerabilities_found: 0`, and the MCP tool
prints *"No findings auto-created (no components with critical/high CVEs)."* — a false
clean verdict, the exact outcome the branch exists to prevent. The root flaw is that
`not_applicable` + `warning=null` conflates **"nothing to look up"** with
**"every lookup blew up"**.

*Not currently triggered by the pinned feed:* I ran all 30,000 randomly-sampled real
records through `CVE(...)/getvars()` — **0 failures** at pin `a1f3845`. The hole is
latent, not live; it opens on a torn extract, a feed schema change, or an nvdlib bump.

**Fix applied (separate commit):** move construction inside a deliberately-broad
per-record guard that counts the record as `skipped` (⇒ `degraded` ⇒ `cache_degraded`
⇒ `partial` + UNDER-REPORT warning), plus a backstop in `scan_components` that records
a degraded lookup when `_query_nvd_for_component` raises, so `lookups > 0` and
`not_applicable` becomes unreachable for an attempted component. 3 new canaried tests.

### D2 — HIGH — Rule #47 consumer enumeration is incomplete; the frontend still shows a bare `0`.

The branch wired **3 writers** (`_run_vuln_scan_background`, the post-SBOM auto-scan,
the MCP tool) and **2 readers** (REST `_build_vuln_scan_summary`, MCP
`run_vulnerability_scan`). Every other surface that renders a vulnerability verdict was
left unmigrated:

- **`frontend/src/pages/SbomPage.tsx:546`** — `Found {scanResult.total_vulnerabilities_found} CVEs across {…} components`. No warning, no provenance. **`frontend/src/types/index.ts:368`** was not extended with the three new response fields. **Zero frontend files are in the diff.** The most-visible consumer still presents an unenriched scan as a clean one. This alone means the guarantee does not hold end-to-end.
- `backend/app/ai/tools/sbom.py` — `list_vulnerabilities_for_assessment`, `assess_vulnerabilities`, `check_component_cves`, `get_sbom_components` all report counts with no provenance.
- `backend/app/services/export_service.py`, `hardware_firmware/hbom_export.py` — SBOM/HBOM/VEX exports emit "no vulnerabilities" with no enrichment marker. These are the artifacts that leave the building.
- `backend/app/services/cra_compliance_service.py` — regulatory surface; `run_vulnerability_scan` is listed as evidence for *"No known exploitable vulnerabilities"* (`:52-61`, `:218-227`). A cache-unavailable scan feeding a CRA compliance verdict is the highest-consequence version of this bug.
- `backend/app/services/assessment_service.py:359+` — logs the warning but does **not** propagate it into the assessment output the operator reads.

Note the brief already flagged one late-found writer; the *reader* side has the same
shape and was not swept. **Left unfixed** — too large for a reviewer's contained change.

### D3 — MEDIUM — Rule #37 is followed in shape, not in substance: there is no integrity gate.

Rule #37's mechanical rule requires *"computes SHA256, compares against the pinned hash,
exits non-zero on drift"*. Here:

- `MANIFEST.json`'s field is **named `sha256` but holds a git commit hash**
  (`a1f38452d7df90df6f6b27d5e4762e0f6b4c4a90`). The README is honest about this; the
  field name is not, and downstream readers will assume content integrity.
- **No content is ever verified.** `--apply` (`scripts/refresh-nvd-cache.sh:39-82`)
  pulls, populates, then **overwrites the pin with whatever HEAD is** — the pin is a
  *record*, never a *gate*. Nothing re-derives it from the volume's bytes.
- `backend/nvd-anchors/README.md` recommends a **weekly cron running `--apply`**, which
  auto-adopts upstream HEAD unreviewed. That directly contradicts Rule #37's *"Refresh
  is a deliberate, out-of-band operation … the operator reviews + commits + rebuilds."*
  The cron makes the pin a rubber stamp.
- Consequence within the branch's own threat model: a poisoned or rewritten feed can
  **remove** CVEs, and every downstream verdict reports `enrichment_status: complete`.

The only integrity signal is the `< 300000` file-count floor (`:51`) — a coarse
liveness check, not integrity. **Left unfixed** (design decision, not a code bug).

### D4 — MEDIUM — memory profile of a broad-CPE lookup is new and unbounded.

Measured in the running backend against the real cache:

```
linux_kernel lookup: 6.9s for 18635 candidates; peak RSS 738 MB
cpe_index memo: 171930 keys, RSS 20 -> 184 MB (resident for process lifetime)
```

`_lookup_sync` materialises **every** candidate `CVE` object into a list *before*
`_cpe_is_vulnerable_in_cve` filters. The old live-NVD path was API-paged and never had
this profile. 164 MB of index memo is resident permanently in **both** backend and
worker. Compose limits are 4096M each, so this is headroom-consuming rather than fatal
today — but a firmware with several broad components scanned concurrently with other
worker jobs is a plausible OOM. Filtering inside the loop (or yielding) would cut peak
by ~an order of magnitude. **Left unfixed.**

### D5 — MEDIUM — Rule #35b live canary missing for the new JSONB column.

CLAUDE.md: *"live canaries are required for value flow"*, and router-level persistence
tests must *"round-trip through the real ORM via `tests._live_db.make_live_db` and
SELECT the persisted row."* `grep make_live_db` over both new test files: **zero hits**.
Every persistence assertion uses `MagicMock()` for the `Firmware` row
(`test_nvd_cache_service.py:413`, `:434`, `:447`), so nothing proves
`fw.vuln_scan_provenance = stamp` actually lands in Postgres in the shape the
normaliser expects. The column exists in the live DB, so the canary is cheap to add.
The MCP tool handler `_handle_run_vulnerability_scan` — a *third* writer — has **no
test at all**. **Left unfixed.**

### D6 — LOW — `_cve_path` does not validate the year component (Rule #1).

`nvd_cache_service.py:102-114` checks `parts[0] == "CVE"` and `parts[2].isdigit()` but
**not** `parts[1].isdigit()`. `CVE-../../etc/passwd-123` splits into a 3-tuple that
passes every check and yields a path outside the cache root. Not exploitable today —
ids come only from the service-generated `cpe_index.json`, never from firmware content
(the attacker-influenced CPE string is used as a *dict key*, never as a path segment) —
but Rule #1 mandates `realpath` + prefix check on every file access, and this is a
one-line `parts[1].isdigit()` guard. **Left unfixed** (deliberately: not exploitable,
and I kept my diff minimal).

### D7 — LOW — a red test already on the branch.

`tests/test_sbom_router.py::TestListVulnerabilities::test_returns_paginated_vulns_with_component_metadata`
fails with `ValueError: not enough values to unpack (expected 4, got 3)` at
`routers/sbom.py:1249`. **Pre-existing** — I confirmed it fails with the branch's own
files stashed, and the branch's `sbom.py` diff does not touch that endpoint. Out of
scope, but a red test should not ride into a merge unremarked.

### D8 — LOW — smaller items

- `app/main.py:365-368` reads `os.environ.get("NVD_CACHE_PATH", "/opt/wairz/nvd-cache")`
  and re-parses `NVD_ALLOW_LIVE_FALLBACK` by hand, though `settings` is already in scope
  at `lifespan`'s first line. Two sources of truth for the same default (Rule #54 shape).
- `app/main.py:363` — `# noqa: ASYNC240 …` sits on **its own line** above the call it
  means to annotate. Ruff `noqa` must be on the offending line; it suppresses nothing.
  (Ruff is clean today, so the comment is inert, not harmful.)
- Module memos `_INDEX_CACHE` / `_INTEGRITY_CACHE` invalidate on **manifest sha only**.
  `build_cpe_index` pops them, but it runs in a *separate* one-shot container process,
  so long-lived backend/worker processes never see that pop. Repopulating at the **same**
  feed commit (repairing a corrupt volume, or `NVD_SKIP_PULL=1 --apply`) leaves a stale
  `degraded` verdict until restart. Fail-safe direction (over-warns), so LOW.
- `MANIFEST.json`'s `cve_count` is the **feed** count, not what landed on the volume —
  a partial extract over-reports.
- `.claude/harness.json` carries an unrelated `sessions_completed: 211 → 230` counter
  bump. Branch noise; drop before merge.

---

## 3. Canary evidence (Rule #46 — I neutralized production guards and observed RED)

| # | What I neutralized | Expected | Observed |
|---|---|---|---|
| 1 | Reintroduced the leading-zero bug: `bucket = f"CVE-{year}-{int(num) // 100}xx"` | path oracle RED | **5 failed, 28 passed** — `test_cve_path_matches_hand_written_feed_layout` (4 params) + `test_cve_path_never_strips_leading_zeros` |
| 2 | Forced `degraded = False` in `_lookup_sync` **and** `_integrity_sync` | degrade suite RED | **7 failed, 26 passed** — incl. `test_partial_cache_is_degraded_not_clean_miss`, `test_probe_not_ready_on_degraded_cache`, `test_summary_verdict_degraded_cache_says_under_report` |
| 3 | Reverted my own D1 fix (both files) | my 3 new tests RED | **3 failed, 33 deselected**; all green with the fix restored |

All guards restored; `git status` verified clean of canary residue after each.

**Are the tests real oracles?** Mostly yes, with one honest caveat the author documents:
the `_write_cve` fixture calls `_cve_path` to decide where to write, so every
cache-*hit* test is tautological — under canary 1 they all still passed. The
hand-written parametrized layout table (`:269-283`) is what actually caught it, and it
is a genuine independent oracle. That table is load-bearing; do not delete it.

**Vacuous-test check:** `test_healthy_cache_is_not_flagged_degraded` (`:211`) is the
correct companion — without it, "always report degraded" would satisfy the suite.

---

## 4. Learned-Rule assessment

**Satisfied:** #3 (MCP `flush()` not `commit()`), #5 (`run_in_executor` on all cache
reads), #12 (schemas in `schemas/`), #19 (revision-id collision checked before
authoring), #20 (Settings gained 2 fields; container restarted — verified live), #25
(10 clean per-slice commits, good messages), #29/#33 (no new sync long-op; existing
202+polling preserved; provenance omitted on the `cached` short-circuit rather than
overwriting a real manifest sha — a genuinely careful call), #35c (normaliser +
stamp + `SCHEMA_VERSION` + tests present; 834 normaliser tests green), #38 (absolute
paths), #46 (canaries present **and** they fire — proven above), #51 (endpoint already
on `TIER_A_LIGHT_ACK`; work got *faster*, so the tier is at worst over-restrictive).

**Violated / partial:**
- **#47 — VIOLATED.** Consumer enumeration covered writers, not readers. See D2.
- **#37 — PARTIAL.** Offline shape is right; the integrity gate does not exist and the
  recommended cron defeats the review step. See D3.
- **#35b — VIOLATED.** No live canary for the new JSONB column; all persistence
  assertions are `MagicMock`. See D5.
- **#1 — PARTIAL.** No `realpath` + prefix check in `_cve_path`; year unvalidated. D6.
- **#8 — OUTSTANDING.** A new alembic revision means `docker compose up -d --build
  backend worker migrator` before this is trusted for the next session. The migration
  is applied and the running containers carry the code, but no three-way rebuild has
  been observed. **Do this before merge.**

---

## 5. Does the truthfulness guarantee hold end-to-end?

**No — not before D1 and D2 are closed.**

- **Backend core: holds.** Cache-first, no network on miss, degrade detection is real
  (canary 2), provenance is sticky across components, the `cached` short-circuit
  correctly refuses to overwrite a real manifest sha, and NULL provenance reads as
  `unknown` **with** a warning rather than as `complete`. This part is well built.
- **D1 broke it** on the exception path: an unreadable/malformed record produced
  `not_applicable` + `warning: null` — an affirmative clean verdict for a scan that
  resolved nothing. Fixed here.
- **D2 still breaks it** at the surfaces an operator actually reads. The React SBOM page,
  the SBOM/HBOM/VEX exports, the CRA compliance evidence chain, and four MCP tools all
  still render `0` with no marker. The warning exists in the API response and is
  ignored by the client.

---

## 6. What I changed, and what I did not

**Fixed (separate commit on this branch):** D1 only — the false-clean-verdict on a
raising lookup. Contained: two production edits (a widened per-record guard with
construction moved inside it; a provenance-recording backstop in `scan_components`'s
existing `except`) plus 3 regression tests, all three confirmed RED without the fix.

**Left for the author:** D2 (frontend + 6 read surfaces — the largest remaining item),
D3 (integrity gate + cron semantics), D4 (memory), D5 (live canary + MCP handler test),
D6 (year validation), D7 (pre-existing red test), D8 (housekeeping).

---

## 7. Merge recommendation — **MERGE-WITH-FIXES**

Merge is defensible **after** these, in order:

1. **D2 frontend minimum** — extend `frontend/src/types/index.ts` with the three new
   fields and render `nvd_enrichment_warning` in `SbomPage.tsx` above the count.
   Without this the branch's central claim is false at the primary UI. *Blocking.*
2. **D5 live canary** — one `make_live_db` round-trip asserting the stamp persists and
   normalises. *Blocking* per house rules.
3. **Rule #8** — `docker compose up -d --build backend worker migrator`. *Blocking.*
4. D3 (at minimum: rename the manifest field, and change the documented cron to the
   no-flag drift check so `--apply` stays a human decision), D6, D8 — next PR.
5. D4 and D2's export/CRA surfaces — file as follow-ups; both are real, neither should
   hold the branch.

Not DO-NOT-MERGE: the mechanism is sound, the `_cve_path` fix is provably complete, and
the branch is a clear net improvement over live-NVD-at-scan-time. Not MERGE: shipping
D2 would mean shipping a truthfulness feature that the only GUI consumer ignores.
