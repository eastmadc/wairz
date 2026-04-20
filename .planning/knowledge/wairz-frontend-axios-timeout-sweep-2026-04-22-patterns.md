# Patterns: Wairz Frontend Axios Timeout Sweep (2026-04-22, session 7e8dd7c3, post-campaign-close cluster)

> Extracted: 2026-04-22
> Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Trigger: user report "generate SBOM times out too, wtf this thing is brittle as fuck" — `bug.har` untracked in working tree
> Commit range: `6814461..31f6003` (10 commits)
> Sibling patterns file: `wairz-intake-sweep-wave1-close-2026-04-22-patterns.md` (the campaign close itself — separate extraction)

## Context

The wairz-intake-sweep campaign closed earlier in this session. The user
then hit a real operational issue — `generateSbom` timing out in the UI —
and requested a systematic sweep of the rest of the frontend API layer
for the same bug class. One investigation commit + 8 fix commits across
the API layer + 1 harness-rule commit to ensure the class can't regress.

## Successful Patterns

### 1. Backend-logs-vs-UI-error confirmation before fixing

- **Description:** When a user reports a "failed" UI message on a
  long-running operation, FIRST confirm via backend logs whether the
  backend actually succeeded (slow + UI lied) or actually failed
  (real error). The fix shape is completely different:
  - Backend succeeded → client-side timeout; fix the axios timeout
    override.
  - Backend failed → real error; fix the backend bug, not the UI.
  The first 60 seconds of investigation should be
  `docker compose logs backend --tail 100 | grep -iE
  'sbom|timeout|error|traceback'` before reading any frontend code.
- **Evidence:** Session 7e8dd7c3 bug.har: user reported SBOM timeout.
  Backend log showed `{"event": "SBOM: component_dicts=495,
  firmware.os_info=True", "level": "info"}` — backend successfully
  built the component list. Confirmed client-side timeout; fixed in
  `frontend/src/api/sbom.ts` commit 6814461. Elapsed time from
  complaint → diagnosis: ~90 seconds.
- **Applies when:** Any user-reported timeout / "failed" / "error"
  on a long-running operation. Check backend log FIRST. If the user
  describes a generic "brittle" or "flaky" feel, a sweep of the
  frontend API layer for missing timeouts is usually the highest-ROI
  intervention.

### 2. Harness-rule-gap-analysis done inside the same fix commit

- **Description:** When a quality-rule-protected bug class nevertheless
  hits production (because the rule's regex missed some cases), the fix
  has two layers: (a) fix the bug sites, (b) fix the rule so it catches
  future regressions. Don't ship layer (a) without also doing layer (b)
  in the same cluster — otherwise the next person writing a
  long-running endpoint re-introduces the bug and the rule still won't
  catch it.
- **Evidence:** The existing `auto-frontend-long-op-no-explicit-timeout`
  rule had TWO defects: (i) its verb allowlist was
  `audit|scan|export|import|dump|auto-populate|cve-match` — missing
  `generate|triage|analyze|capture|decompile|bytecode|sast|
  cleaned-code|disasm|network-analysis|tools/run` (11 more verbs
  observed in the sweep); (ii) the regex had NO negative lookahead on
  `timeout:` — it fired on every long-op URL, whether or not the call
  already had a timeout override. That made the rule noisy (flagging
  correctly-annotated calls) AND toothless (not catching the actual
  missing-timeout bug). Commit `31f6003` replaced the regex with
  `apiClient\.(post|get|put|patch)(<[^>]+>)?\([^)]*`[^`]*/(audit|scan|
  export|import|dump|auto-populate|cve-match|generate|triage|analyze|
  capture|decompile|bytecode|sast|cleaned-code|disasm|
  network-analysis|upload-rootfs|apk-scan|tools/run)[^`]*`
  (?![^)]*\btimeout\s*:)[^)]*\)` — 11 new verbs + negative lookahead.
  Added a companion rule `auto-frontend-multipart-no-explicit-timeout`
  for FormData uploads.
- **Applies when:** Any bug-fix that uncovers a quality-rule gap.
  Keep the rule fix in the same cluster as the bug fixes. Include in
  the commit message: the defect analysis, the new regex, and the
  bug sites the old regex missed.

### 3. Endpoint-by-verb timeout tier taxonomy

- **Description:** Not every long-op endpoint deserves the same
  timeout. Establish a taxonomy so the fix is mechanical:
  - `SECURITY_SCAN_TIMEOUT = 600_000` (10 min) — security audit,
    CVE scan, SBOM generation/export, fuzzing analyze/triage, MCP
    tool dispatcher, FormData uploads up to MAX_UPLOAD_SIZE_MB.
  - `GHIDRA_ANALYSIS_TIMEOUT = 180_000` (3 min) — decompile,
    cleaned-code, any Ghidra-backed single-function call
    (config.GHIDRA_TIMEOUT default is 120s per call + 60s slack).
  - `RADARE2_ANALYSIS_TIMEOUT = 90_000` (90s) — functions, imports,
    disasm, binary-info (radare2 `aaa` is 10-30s cold + slack).
  - `DEVICE_BRIDGE_TIMEOUT = 300_000` (5 min) — device import/dump
    (multi-GB scatter ingest over host bridge).
  - `HASH_SCAN_TIMEOUT = 180_000` (3 min) — hash-lookup scans
    (virustotal, abusech, clamav, hashlookup — existing in
    `findings.ts`).
- **Evidence:** The sweep used all 4 tiers across 8 files + 18
  endpoints. Each file chose the matching constant based on the
  backend's actual latency profile (documented in the code comments
  above the constant). Pattern is self-documenting — a future author
  reading `frontend/src/api/analysis.ts` can see which tier each
  endpoint uses and why.
- **Applies when:** Any new long-op API client method. Look up the
  backend endpoint's expected latency first (grep for `timeout` in
  the service / router / config); match to the tier; cite the
  constant in a comment.

### 4. Inline-comment-cites-backend-log + shared constant per file

- **Description:** When a timeout override lives on a specific API
  call, put the timeout as a named constant at the top of the file
  (not a magic number on the call itself), AND write a comment
  above the constant that: (a) names the backend work the endpoint
  does, (b) cites the observed latency range, (c) points to the
  sibling-file pattern that already uses the same tier. This makes
  the constant obviously RIGHT at code-review time and gives the
  next author a ready template.
- **Evidence:** `sbom.ts` comment block:
  ```ts
  // SBOM generation walks the extracted firmware and runs every
  // SbomStrategy (syft, dpkg, opkg, ...). On firmware with hundreds
  // of components the call routinely takes 1-3 minutes; the default
  // axios 30s fires while the backend is still building
  // component_dicts. Matches SECURITY_SCAN_TIMEOUT tier used in
  // findings.ts / attackSurface.ts / craCompliance.ts for the other
  // long-running scans.
  const SECURITY_SCAN_TIMEOUT = 600_000
  ```
  This is the house-style established by `findings.ts` (original
  author of the pattern). All 8 fixed files follow it.
- **Applies when:** Any file with a timeout override. One constant
  per tier per file. Don't inline `600_000` in the options object —
  the comment is more valuable than the keystroke saved.

### 5. Agent-delegated systematic sweep with explicit judgment calls

- **Description:** When a bug class is known but scope is unclear,
  dispatch a sub-agent with: (a) the canonical fix example, (b) the
  file list to audit, (c) explicit judgment-call guidance for edge
  cases ("when in doubt, skip" vs "when in doubt, add"). The agent
  reports a fix-candidate table + shipped commits + skipped items
  with rationale. Main session reviews the table, accepts the
  commits, adopts the harness-rule-gap patch.
- **Evidence:** This session's audit agent:
  - Examined 19 API files in one pass
  - Shipped 8 commits (one per logical group)
  - Fixed 18 endpoints with 4 different timeout tiers
  - Skipped correctly: status polls, cancel endpoints, simple CRUD,
    URL builders, single-record reads
  - Returned a structured report with harness-rule-gap analysis
    including a ready-to-apply regex patch
  - All commits type-check clean per-commit
  - Delivered a Rule-17 canary confirmation proactively
  - Total duration: ~8 minutes wall-clock for the sweep
- **Applies when:** Any known-bug-class sweep across >5 files. The
  systematic file-by-file loop is exactly what sub-agents are good
  at; the main session coordinates + reviews + merges the harness
  rule update.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Fix the symptom site (sbom.ts) inline before dispatching the sweep | User was frustrated ("brittle as fuck"); shipping a working SBOM button in under 5 minutes before launching the wider audit gave an immediate win. Sweep dispatched in parallel afterwards. | User's specific complaint resolved first; comprehensive fix landed 8 minutes later. |
| Use `apiClient.(post\|get\|put\|patch)` in the new regex, not just `(post\|get)` | Old regex only covered POST/GET. Every long-op observed in the sweep was POST or GET, but PUT/PATCH long-ops are possible (e.g. bulk update). Cheap to include. | Rule now catches future PATCH-based bulk operations if they land long-running work. |
| Add the multipart-upload companion rule separately from extending the main rule | Upload endpoints (`/firmware`, `/kernels`, `/documents`) have bare paths — no verb keyword in the URL — so the verb-list regex can't catch them. A companion regex keyed on `'Content-Type': 'multipart/form-data'` is more robust for uploads. | Two rules, each simple. Easier to reason about than a single mega-regex trying to cover both cases. |
| Skip the `/unpack` endpoint (firmware unpack kickoff) | Per existing comment in `firmware.ts`: the endpoint returns 202 immediately and work runs via `asyncio.create_task`. The frontend polls status. HTTP call is fast by design. | Avoided noisy over-fix; polling pattern intact. |
| Skip emulation `exec`/`command` endpoints (caller-supplied timeout param) | These endpoints accept a `timeout` param (default 30s) as a server-side command-runtime bound. HTTP overhead is small. Default axios 30s is correct here. | Kept the caller's explicit per-call timeout semantics intact. |

## Applicability Notes

- **For future long-op additions:** the 4 timeout tiers + the
  comment-block-plus-constant pattern from `findings.ts` / `sbom.ts`
  are the template. Any new endpoint fitting one of those tiers
  should pick the matching constant.
- **For timeout-tier decisions:** backend latency is the ground truth.
  Check the service file's own timeout config (`GHIDRA_TIMEOUT` in
  `config.py`, `_DEFAULT_TIMEOUT` in mobsfscan parser, etc.) and
  round up with 50% slack for network + JSON serialization.
- **For the harness rule:** it now has a negative-lookahead on
  `timeout:`, so it's SILENT on correctly-annotated calls.
  Any trigger in a code review → a real missing-timeout site. The
  verb list will need occasional extension (this session added 11);
  anticipate one more extension every 6-12 months as new long-op
  endpoints land.

## Cross-references

- Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
- Campaign-close patterns: `wairz-intake-sweep-wave1-close-2026-04-22-patterns.md`
- Prior bug-fix-cluster patterns: `wairz-intake-sweep-bug-fixes-2026-04-19-patterns.md`
  (similar shape — earlier timeout-sweep that the first version of the
  harness rule was extracted from)
- Session handoff: `handoff-2026-04-22-session-7e8dd7c3-end.md`
- Commits: `6814461..31f6003` (10 commits)
