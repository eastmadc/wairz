# Anti-patterns: Hardware Firmware Page — Usability Overhaul

> Extracted: 2026-04-18
> Campaign: `.planning/campaigns/completed/feature-hw-firmware-usability-overhaul.md`

## Failed Patterns

### 1. `RegExp.prototype.test()` on a `/g`-flagged regex after `String.split(regex)`

- **What was done:** Initial `highlightMatches` in `BlobTable.tsx` used
  `text.split(re)` to separate match / non-match segments and then
  `re.test(part)` to decide which index was a hit.
- **Failure mode:** `RegExp` with the `g` flag keeps a stateful
  `lastIndex`. Repeated `test()` calls on the same regex instance
  return false on strings that should match, so highlight would flash
  on / off inconsistently.
- **Evidence:** Caught during review before shipping. Fixed by
  switching to split-index parity: `split(/(...)/g)` returns
  alternating non-match / match at even / odd indices, so no re-test is
  needed.
- **How to avoid:** When using `split` with a capture group to find
  segments, trust the index parity. If you must re-test, either strip
  the `g` flag or reset `lastIndex` to `0` before every call. Don't
  assume `test()` is idempotent against a global regex.

### 2. Log monitor filter too broad for an internet-exposed backend

- **What was done:** The initial Monitor filter included `error`,
  `Failed`, `FAILED`, `Error `, `404`, etc. Backend binds
  `0.0.0.0:8000` so LAN scanners (Joomla / VMware IDM / ServiceNow
  probes) constantly hit 404 paths.
- **Failure mode:** Every scanner request fired a Monitor event,
  pushing irrelevant notifications into the agent context and
  obscuring the real extraction / detection signal.
- **Evidence:** Six scanner bursts from `10.51.28.10` tripped the
  monitor before it was stopped and considered for re-arming with a
  tighter filter.
- **How to avoid:** For any service exposed beyond localhost, scope
  monitor filters to internal patterns first — `/api/v1/` path
  fragments, worker-log markers, Python tracebacks — NOT generic HTTP
  status codes. If you must watch 4xx, exclude well-known scanner
  paths (`wp-admin`, `joomla`, `SAAS/API`, `administrator/`).

### 3. Fragment used as element-array wrapper inside `.map()` without Fragment key

- **What was done:** First pass of `CvesTab.tsx` used
  `rows.map(c => <>...<tr>...</tr>...</>)`. The outer empty-shorthand
  fragment can't take a `key` prop.
- **Failure mode:** React key warning at runtime when the row list
  changes; stable-key reconciliation breaks, causing loss of expanded
  state on re-render.
- **Evidence:** Caught during review. Fixed by importing `Fragment`
  explicitly and writing `<Fragment key={c.cve_id}>...</Fragment>`.
- **How to avoid:** `<>...</>` is fine for one-off wrapping but not
  inside a list `.map()`. Any fragment used in a list position MUST be
  the long form with `key`.

### 4. Trusting `tsc -b` silent exit as proof of success

- **What was done:** Frontend typecheck via `npx tsc -b` exited 0 with
  no output. Treated this as a pass signal without confirmation.
- **Failure mode:** `tsc -b` is an incremental build — with a clean
  cache and no changed source roots, it may skip real type-checking
  entirely. A silent success is indistinguishable from "didn't run."
- **Evidence:** Noticed suspicion after several silent runs; wrote a
  canary TS file with a deliberate type error and re-ran tsc to prove
  it actually reports errors.
- **How to avoid:** When a tool exits cleanly with no output on a
  non-trivial change, canary-check it: feed it a known-bad input and
  confirm the failure surfaces. If canary also passes silently, the
  tool is not running.

### 5. Initial intake with no YAML frontmatter status field

- **What was done:** Wrote the intake file as a plain Markdown brief
  with no `status: pending` frontmatter.
- **Failure mode:** Autopilot's SCAN step classifies items by status;
  an item with no status field falls through to the unknown-status
  path, which the protocol explicitly documents as "treat as pending."
  It worked, but relied on defensive behaviour rather than contract.
- **Evidence:** Autopilot completed the campaign despite the missing
  field, but there's no audit trail of a `briefed → built → verified`
  status transition on the file itself.
- **How to avoid:** When handing work to autopilot, include the
  frontmatter block the protocol expects. The status transitions are
  part of the handoff record.

### 6. Forgetting to reinstall test tooling after a container rebuild

- **What was done:** `docker compose up -d --build backend` replaces
  the image. Any packages installed with `pip install` into the
  previous container instance (pytest, pytest-asyncio) are gone.
- **Failure mode:** Immediately running `pytest` after a rebuild
  fails with `No module named pytest`, derailing the verify phase.
- **Evidence:** Happened twice in the session — once for the backend
  Python env, once for the frontend npm deps (different symptom).
- **How to avoid:** Either bake test deps into the Dockerfile
  (simplest), or wrap the test invocation in a helper that ensures the
  deps are installed first. Don't rely on "it was there last time."

### 7. Auto-expansion applied to one tree level only, not recursively

- **What was done:** The initial autopilot pass of
  `pickDefaultOpenPartitions` opened every partition containing a
  CVE-bearing blob.  `openVendors` was initialised to `new Set()`
  and only updated by text-search auto-expand.  Tests passed, the
  intake's "auto-expand CVE partitions" bullet was green.
- **Failure mode:** A partition header with CVE blobs opens, but
  the VENDOR subgroup inside it stays closed.  User sees the CVE
  count badge at the partition tier AND at the blob tier, but has
  to click every vendor to reach the blobs.  Described by the user
  as "the tree still doesn't fully expand."
- **Evidence:** User report ~1h after ship.  Fix added the
  vendor-tier mirror (`pickDefaultOpenVendors`) + an Expand-all
  toggle as escape hatch.  Commit `f5dc449`.
- **How to avoid:** For any N-tier tree with auto-open logic,
  the open-set computation should run at every tier whose children
  might contain the targeted items.  A single-tier helper is a
  code smell — either make it recursive or ship per-tier mirrors
  explicitly.  Also: pair any auto-expand feature with an
  Expand-all button the first time you ship it — covers the edge
  cases the auto-logic misses and costs ~15 LOC.

## Meta-pattern — "agent QA is not user QA"

Autopilot cleared all 13 items from the intake, 77/77 tests green,
live verification passed.  The Expand-all follow-up is a reminder
that the agent's verification scope is limited to what it can
observe programmatically.  User-reported UX defects surface within
minutes of a real human clicking around.  Budget ~10 minutes
post-autopilot for the user to actually exercise the feature; the
defects they find are usually tier/propagation bugs the tests
couldn't catch.
