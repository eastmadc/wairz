# APK Scan Deep Linking — Fix Required

**Priority:** Medium
**Status:** Completed
**Created:** 2026-04-15

## Current State

When clicking an APK finding's file path in the Findings page, it navigates to
`/security?tab=apk-scan&apk=<path>`. The APK Scan tab opens and results load
from cache, but several things don't work:

1. **APK selector shows wrong APK** — The display card shows the first APK
   (BuildManifest.apk) instead of the deep-linked one, even though results
   load for the correct APK.

2. **Finding not expanded** — The user expects to see the specific finding
   they clicked on, expanded with details visible. Currently all findings
   are collapsed.

3. **No scroll to finding** — Even if expanded, it doesn't scroll to the
   specific finding that was clicked.

4. **Stale persisted data** — Findings persisted before fixes still have
   temp paths in evidence (`/tmp/mobsfscan_xxx/sources/...`). Need force
   rescan or migration to clean up.

## What Deep Linking Should Do

1. Parse URL params: `tab=apk-scan&apk=<path>&finding=<rule_id>&line=<n>`
2. Switch to APK Scan tab
3. Set selectedApk to the APK from params (ensure selector visual matches)
4. Load cached results for that APK
5. Find the matching finding by rule_id
6. Expand that finding's group and the finding itself
7. Scroll to it

## Root Cause

The current implementation was built incrementally (8+ patches) instead of
designed holistically. The APK selector, results loading, and finding
expansion all happen in separate effects with race conditions between them.

## Suggested Approach

- Pass all deep-link params as props to ApkScanTab
- Handle them in a single coordinated effect after discovery completes
- Use refs to track "initial load complete" state
- Set selectedApk, load results, expand finding, and scroll in sequence
