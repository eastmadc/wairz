# Anti-patterns: Bug-fix cluster (session 93a4948d, turn 2)

> Extracted: 2026-04-19
> Campaign: `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` (active)
> Companion file: `wairz-intake-sweep-bug-fixes-2026-04-19-patterns.md`

## Failed Patterns

### 1. Bare `catch {}` swallowing real exceptions into hardcoded "failed" state
- **What was done:** Handler wrote a fake domain object that CLAIMED the operation failed, even though the actual cause (axios timeout, 500, auth expiry) was discarded.
  ```tsx
  try {
    const result = await runSecurityAudit(projectId)
    setAuditResult(result)
  } catch {
    setAuditResult({ status: 'error', checks_run: 0, findings_created: 0, total_findings: 0, errors: ['Scan failed'] })
  }
  ```
- **Failure mode:** Every upstream error surfaces as "Scan failed" — the user cannot tell apart a timeout from a 401 from a genuine server-side crash. Backend is often running fine; UI says it failed. In session 93a4948d the actual cause was a 30s axios timeout against an 8-minute audit; the backend returned `status: success, checks_run: 48, findings_created: 4, errors: []` — the **exact opposite** of what the UI displayed.
- **Evidence:** `SecurityScanPage.tsx:96` (handleAudit), `SecurityScanPage.tsx:118` (handleYara), `ProjectActionButtons.tsx:55` (audit onClick), `ProjectActionButtons.tsx:75` (yara onClick). All four fixed in commit `b437095`.
- **Repeat sites found via survey** (not fixed yet — next-session work):
  - `frontend/src/pages/DeviceAcquisitionPage.tsx:89` — hardcodes `error: 'Failed to check bridge status'`
  - `frontend/src/pages/ComparisonPage.tsx:132` — hardcodes `error: 'Failed to load instruction diff'`
  - `frontend/src/pages/ComparisonPage.tsx:152` — hardcodes `error: 'Failed to load decompilation diff'`
  - `frontend/src/components/security/CraChecklistTab.tsx:71` — silently clears list (`setAssessments([])`)
  - `frontend/src/components/security/CraChecklistTab.tsx:87` — silently clears assessment (`setAssessment(null)`)
- **How to avoid:** Every `catch {}` binding-less block is a code smell. Bind the exception; pipe it through `extractErrorMessage(e, fallback)` from `utils/error.ts`. Silent-fallback patterns (`setAssessments([])`) are legitimate ONLY when the user has no business seeing the error — rare. Default should be: surface the real cause, fall back to a sensible message only if the error is malformed. The harness rule `auto-frontend-fake-scan-failed-error` (added this session) flags the exact string `errors: ['Scan failed']` in frontend code.

### 2. Default 30s axios timeout for scan / audit / export / import endpoints
- **What was done:** `apiClient` in `client.ts:6` sets `timeout: 30_000` globally. Most CRUD calls comply; but `runSecurityAudit`, `runYaraScan`, `runAbusechScan`, `runKnownGoodScan`, and several others invoked it on endpoints that routinely run for minutes, inheriting the 30s ceiling silently.
- **Failure mode:** Axios throws `Error: timeout of 30000ms exceeded` while the backend continues happily running the audit for another 7 minutes. Combined with anti-pattern #1 above, the UI shows a complete lie: "0 findings, 1 error" while the backend produces 4 findings with zero errors.
- **Evidence:** Session 93a4948d saw the exact contradiction: backend returned `{"status":"success","checks_run":48,"findings_created":4,"errors":[]}` to the no-timeout curl; frontend displayed `Audit complete: 0 findings from 0 checks (1 error)`. Root cause: 30s axios timeout, hardcoded `errors: ['Scan failed']` in catch.
- **Repeat sites found via survey** (not fixed yet):
  - `frontend/src/api/files.ts:101` `scanUefiModules` → `/security/uefi-scan` — no timeout
  - `frontend/src/api/sbom.ts:74` `runVulnerabilityScan` → `/sbom/vulnerabilities/scan` — no timeout
  - `frontend/src/api/hardwareFirmware.ts:127` `runCveMatch` → `/hardware-firmware/cve-match` — no timeout
  - `frontend/src/api/attackSurface.ts:74` `triggerAttackSurfaceScan` → `/attack-surface/scan` — no timeout
  - `frontend/src/api/craCompliance.ts:58` `autoPopulateCra` → `/cra/assessments/{id}/auto-populate` — no timeout
  - `frontend/src/api/device.ts:38` `startDump` → `/device/dump` — no timeout
- **How to avoid:** Every API function whose URL contains `/audit`, `/scan`, `/export`, `/import`, `/dump`, `/match`, `/auto-populate`, or whose semantics clearly involve walking a filesystem or hitting an external API at scale, must pass an explicit `{ timeout: N }` as the axios config — matching the tier constants used in `exportImport.ts`, `comparison.ts`, `findings.ts` (post-fix). Default axios 30s is for CRUD, not for async work masquerading as sync HTTP. The real long-term fix for the slowest of these is the arq-job pattern (see next-session candidate).

### 3. Frontend container not rebuilt after merging frontend/src changes
- **What was done:** Commit `3063283` (Zeta stream) added the critical `unwrap` helper to `frontend/src/api/projects.ts`. No `docker compose up -d --build frontend` followed. For 3h 30m the container served a pre-fix bundle against a post-fix backend — the exact window where the Page-envelope backend + pre-unwrap frontend collided.
- **Failure mode:** User-blocking runtime TypeError on `/projects` load. Source code looked correct to any reader; the served artifact was stale. Diagnosis required bundle-vs-commit-date reconciliation (pattern #2 in companion file).
- **Evidence:** Container CreatedAt `2026-04-19T14:47:15Z`; commit `3063283` landed `2026-04-19T17:14:53Z`. Bundle `/usr/share/nginx/html/assets/index-3kZyRoWG.js` mtime `Apr 19 14:40` (UTC, matches container).
- **How to avoid:** CLAUDE.md Rule #26 (landed this session) now makes the rebuild obligation explicit. `.mex/context/conventions.md` Verify Checklist mirrored per Rule #21. Harness rule `auto-frontend-rebuild-not-restart` flags `docker compose restart frontend` in docs/prompts. Mechanical tell: `docker compose images frontend` CreatedAt vs `git log --format='%ci' -1 -- frontend/` — if commit is newer, rebuild. Future sessions should run this check at start as a Verification Gate item. Companion to Rule #8 (backend+worker rebuild).

### 4. Synchronous HTTP call for minutes-long audit work
- **What was done:** `/api/v1/projects/{id}/security/audit` blocks the HTTP connection for the duration of the audit (8 min observed on a 1.3GB / 5K-file project). Same pattern for `/security/yara`, `/security/abusech-scan`, `/security/known-good-scan`, `/security/uefi-scan`, `/sbom/vulnerabilities/scan`, `/hardware-firmware/cve-match`, `/attack-surface/scan`, `/device/dump`, `/cra/.../auto-populate`.
- **Failure mode:** Every client-side timeout becomes a false negative. Proxies, load balancers, firewalls between browser and backend may also drop long-held connections (nginx default proxy_read_timeout 60s, etc.). Even with axios timeout extended to 10 min, the RespArray project's audit is borderline. Larger projects will exceed any realistic timeout ceiling.
- **Evidence:** `/security/audit` on project `00815038-cb0f-4642-b2bf-2f176fd807f7` took 8 min end-to-end; the no-timeout curl eventually succeeded (`checks_run=48, findings_created=4`). The firmware unpack path already uses arq-job + polling (POST returns 202 with job_id; frontend polls every 2s). The same pattern should apply to all the endpoints listed above.
- **How to avoid:** Refactor long-running audit/scan endpoints to the arq-job-plus-polling pattern. POST returns `202 Accepted` with `{job_id}`; frontend polls `/security/audit/{job_id}` until `status` transitions from `running` to `succeeded|failed`. Adopted deferred to next session per campaign scope control.

### 5. Intake scope based on a static file list
- **What was done:** The `backend-cache-module-extraction-and-ttl` intake listed 7 call sites. Running the acceptance grep at the start of the refactor found **10**. (Captured in the Phase-5 /learn extraction earlier this session — reproduced here because it's the same bug-pattern class as the stale-bundle incident: written-down-truth drifted from code-truth.)
- **Failure mode:** The refactor would have been 70% done. Missed sites would inherit the old bug-prone pattern indefinitely.
- **Evidence:** See `wairz-intake-sweep-phase-5-cache-refactor-antipatterns.md` anti-pattern #1 for the full trace. Included here as a cross-link because the generalisation — **written-down scope lies; re-derive at start** — applies identically to stale-container bugs, stale-intake-file-lists, and stale-acceptance-grep results.
- **How to avoid:** Always re-derive the acceptance grep at the start of any refactor. Written down truth is a snapshot, not a contract.
