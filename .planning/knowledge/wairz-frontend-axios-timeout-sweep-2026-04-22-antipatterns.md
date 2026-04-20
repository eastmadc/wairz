# Anti-patterns: Wairz Frontend Axios Timeout Sweep (2026-04-22, session 7e8dd7c3, post-campaign-close cluster)

> Extracted: 2026-04-22
> Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
> Trigger: user complaint `bug.har` + "generate SBOM times out too, wtf this thing is brittle as fuck"
> Commits: `6814461..31f6003` (10 commits)

## Failed Patterns

### 1. Quality-rule regex that flags every hit instead of every missing-timeout

- **What was done:** The original `auto-frontend-long-op-no-explicit-timeout`
  rule (landed session 93a4948d) had the regex:
  ```
  apiClient\.(post|get)<[^>]+>\([^)]*`[^`]*(audit|scan|export|import|dump|auto-populate|cve-match)[^`]*`[^)]*\)
  ```
- **Failure mode:** Two bugs combined into one toothless rule:
  1. **No negative lookahead on `timeout:`** — the regex fires on
     every apiClient call matching the verb allowlist, WHETHER OR
     NOT the call already has an explicit timeout override. That
     makes the rule noisy (correctly-annotated calls trigger the
     same warning) AND toothless (the warning becomes wallpaper, so
     authors dismiss it and the rule fails to catch actual
     missing-timeout bugs).
  2. **Verb allowlist missed 11+ long-op endpoints** — `generate`,
     `triage`, `analyze`, `capture`, `decompile`, `bytecode`,
     `sast`, `cleaned-code`, `disasm`, `network-analysis`,
     `tools/run`. Every bug site found in this session's sweep
     was on a verb the rule didn't recognize.
- **Evidence:** The bug the user hit — `generateSbom` POSTing to
  `/projects/${id}/sbom/generate` — slid through because `generate`
  wasn't in the list. Re-running the ORIGINAL regex against the 18
  bug sites found: 0 matches. Zero-to-zero signal; the rule was
  protecting no one.
- **How to avoid:**
  - Every new quality rule that enforces "X must be present" (like
    `timeout:`) needs a negative lookahead, not just a positive
    match on the surrounding context. Template:
    `<positive match for site>(?![^)]*\b<required-key>\s*:)<close>`.
    Without the lookahead, the rule doesn't actually check anything.
  - Verb allowlists drift. When the rule is born, the author has
    a specific bug cluster in mind. As the codebase grows, new
    verbs appear that weren't covered. Maintain the list: when a
    new long-op endpoint lands, add its verb to the rule's regex
    in the same commit. Audit periodically (every ~25 sessions).

### 2. Inline "surely it'll be fast" assumption on operations that CAN be fast

- **What was done:** Endpoints like `/apk-scan/bytecode` (docstring
  says "~30 s") and `/analysis/functions` ("radare2 aaa: 10-30s
  cold") were originally written WITHOUT timeout overrides on the
  assumption that they'd sit comfortably under the default 30s
  axios ceiling.
- **Failure mode:** The "usually fast" assumption papers over the
  EDGE CASE where the operation IS slow: large binary, cold scanner
  cache, contended Docker host, concurrent scan traffic. A
  "usually 20s, occasionally 45s" endpoint will fake-fail 5% of the
  time with the default axios timeout — enough to make the app
  feel "brittle" without any specific repro.
- **Evidence:** `/analysis/decompile` Ghidra calls (config.py
  `GHIDRA_TIMEOUT = 120` per call) — the backend's own timeout is
  4× the axios default. Any decompile that ran longer than 30s
  would surface as a UI "failed" while the backend kept grinding.
  `/apk-scan/sast` budget is 180s (per
  `mobsfscan/pipeline.py:_PIPELINE_BUDGET_SECONDS`) — 6× axios
  default; guaranteed timeout on every real-world scan of a
  decently-sized APK.
- **How to avoid:**
  - **Backend side:** for any service that has an internal timeout
    config (Ghidra, mobsfscan pipeline, AFL fuzzing, binwalk), the
    frontend timeout on the corresponding REST call MUST exceed
    the backend timeout with ≥30s slack. Codify in the comment
    block: cite both numbers.
  - **Rule of thumb:** if the backend explicitly sets a timeout,
    the frontend's default-of-30s is wrong for this endpoint.
    Look at `config.py` / service-level timeouts first when
    auditing.

### 3. Bare multipart upload without timeout (default 30s vs 2 GB file)

- **What was done:** `firmware.ts:16`, `documents.ts:24`,
  `kernels.ts:26`, `firmware.ts:88` (rootfs upload) all posted
  `FormData` to their respective endpoints with no timeout
  override. `MAX_UPLOAD_SIZE_MB = 2048` (config.py default) means
  the backend accepts up to 2 GB uploads.
- **Failure mode:** A 2 GB upload over a 100 Mbps link takes ≥ 2.5
  minutes; at 10 Mbps (hotel wifi), ≥ 30 minutes. Default axios 30s
  fires mid-upload, surfacing "upload failed" even though the
  backend is still patiently receiving data. User then retries,
  re-uploading everything.
- **Evidence:** `firmware.ts:16` (upload endpoint), `documents.ts:24`
  (note upload), `kernels.ts:26` (kernel blob upload) all had no
  timeout. Fixed in commits `02d859c` + `f1fa224`.
- **How to avoid:** Any `apiClient.post` with `FormData` or
  `Content-Type: 'multipart/form-data'` MUST have
  `timeout: UPLOAD_TIMEOUT = 600_000` or equivalent. New harness
  rule `auto-frontend-multipart-no-explicit-timeout` added this
  session to catch future regressions.

### 4. Fake "scan failed" UX + bare catch swallow a silent backend-succeeds case

- **What almost happened this session:** User reported the
  generic "brittle as fuck" frustration. If the main session had
  JUST fixed the visible UI site (SBOM) without investigating the
  broader class, 17 other silently-broken endpoints would have
  remained. Each would continue to produce occasional
  fake-failures, training the user to distrust the app.
- **Failure mode:** Catch-swallow + fake-error-string rendering
  ("scan failed") + default-too-short timeout combine into a
  "this app is flaky" UX. None of the three individual pieces
  look bad in code review; the composite is corrosive to user
  trust.
- **Evidence:** The existing rule
  `auto-frontend-fake-scan-failed-error` (in harness.json) flags
  hardcoded "Scan failed" / "Security audit failed" error strings;
  the cluster of bare `catch (e)` → `setErrors([fakeMessage])`
  patterns were (partially) fixed in session 93a4948d's Stream β.
  Combined with the (still-broken) default axios 30s, users saw
  fake failures even after the catch-swallow fix. Closing the loop
  required this session's timeout sweep.
- **How to avoid:**
  - For ANY long-op surface, the timeout-check AND the
    catch-unswallow AND the real-error-propagation are joint
    requirements. Don't ship one without the others.
  - When a user reports "feels brittle" with no specific repro,
    audit the WHOLE failure-mode surface: timeouts, catches,
    polling intervals, response-shape mismatches. Multiple small
    issues compound into the "brittle" feel; fixing one may not
    move the needle.

## Not a failure this session (but worth noting)

### 5. Four TaskUpdate reminder-fires mid-cluster

Similar cadence to the earlier campaign-close work. Each fire
corresponds to a meaningful checkpoint (agent dispatched; agent
completed; harness committed). Not noise-worthy, but the reminder
hook is clearly mis-calibrated for cluster-work — it wants per-task
updates but the agent's 8 commits are a single logical cluster.
Might be worth a harness-side improvement (suppress the reminder
during active agent-delegation).

### 6. Skill-suggestion spam continues (3rd session in a row)

`/ouroboros:welcome` suggested on every UserPromptSubmit / task
notification, 6+ times this session alone. Continued ignoring per
the documented anti-pattern (sessions b56eb487 #2, 7e8dd7c3
handoff-observed-issues #3). Upstream Citadel hook misconfiguration;
not a wairz fix.

## Cross-references

- Parent campaign: `.planning/campaigns/completed/wairz-intake-sweep-2026-04-19.md`
- Sibling patterns: `wairz-frontend-axios-timeout-sweep-2026-04-22-patterns.md`
- Session handoff (pre-this-cluster):
  `handoff-2026-04-22-session-7e8dd7c3-end.md` (doesn't yet include
  the post-close timeout sweep; consider appending a section or
  adding a supplementary handoff at session end)
- Prior related bug-fix-cluster extraction:
  `wairz-intake-sweep-bug-fixes-2026-04-19-antipatterns.md`
  (the earlier timeout sweep that the first version of the harness
  rule was extracted from — that rule had the defects this session
  fixed)
