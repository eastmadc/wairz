# Patterns: Unpack Escape-Symlink Fix (2026-04-18)

> Extracted: 2026-04-18
> Campaign: not a registered campaign — single-commit fix in session 59045370
> Bug source: user report on firmware 4e6da402-0437-4d25-b97b-0478c26c9894
>   (PowerPack_40.5.1_EGIA_EEA_Release.bin, 268 MB bare-metal medical firmware)
> Fix commit: 90ed79c
> Tests: backend/tests/test_extraction_escape_symlinks.py (10 scenarios)
> Postmortem: none — targeted enough for a single commit

## Successful Patterns

### 1. Reproduce the tool behavior before diagnosing the code

- **Description:** Before suspecting a Wairz bug, I ran `binwalk3 -e -C
  output_dir /tmp/test.bin` against a throwaway random file in the
  backend container to observe what output it produces. Saw the
  identity symlink `output_dir/test.bin -> /tmp/test.bin`.  Repeated
  with a file binwalk3 COULD extract (embedded gzip): saw the symlink
  AND a `test.bin.extracted/` sibling directory. This confirmed the
  trigger was in the external tool, not in Wairz — the fix could be
  at the cleanup layer, not inside binwalk3.
- **Evidence:** Shell repro in Bash("Test extractor behavior on a
  generic blob") — first invocation showed the lrwxrwxrwx entry that
  was the root cause.
- **Applies when:** A bug blames an external tool that Wairz wraps
  (binwalk, unblob, ghidra, grype, jadx, etc.). 30 seconds of direct
  invocation against dummy input clarifies whether the external is
  misbehaving or whether the wrapper is misinterpreting legitimate
  output. Do this BEFORE reading 500 lines of wrapper code.

### 2. Two-tier mental model of symlinks — top-level vs. rootfs-internal

- **Description:** The fix treats top-level symlinks differently from
  rootfs-internal ones.  Top-level symlinks in ``extraction_dir``
  whose target escapes the extraction root are always artifacts
  (binwalk3 leftover, broken dangling refs).  Rootfs-internal symlinks
  (``bin -> /usr/bin``, ``etc/alternatives/sh -> /bin/dash``) live in
  SUBDIRECTORIES and are legitimate firmware content — the sandbox's
  chroot emulator already handles them correctly by rewriting absolute
  targets as root-relative.  The fix scans only the top level, so the
  rule is both simple and safe.
- **Evidence:** `remove_extraction_escape_symlinks()` uses
  `os.scandir(extraction_dir)` not `os.walk()`.  Regression test
  `test_rootfs_internal_symlink_preserved` confirms a `bin ->
  /usr/bin` at `extracted/rootfs/bin` survives cleanup.
- **Applies when:** Any filesystem cleanup that walks an extracted
  firmware tree.  The Android scatter `_relocate_scatter_subdirs`
  pattern (CLAUDE.md rule #18) is the dual: it moves content INTO
  the top level; the escape-symlink cleanup removes noise FROM the
  top level.  Both are explicit about which layer they operate on.

### 3. Live verification against the broken production state

- **Description:** After wiring the fix, I ran the cleanup against
  the actual live ``extracted/`` directory of the affected firmware
  (in `/data/firmware/projects/bf422332.../`).  Before: ``os.listdir``
  returned one entry, ``find_filesystem_root`` returned the extraction
  dir (false success).  After: listdir empty, find_filesystem_root
  returned None.  End-to-end proof the fix takes effect on the same
  shape that surfaced the bug — not just synthetic fixtures.
- **Evidence:** Bash("Demonstrate fix against live PowerPack
  extraction dir") printed "BEFORE fix" / "AFTER fix" with
  find_filesystem_root return values.
- **Applies when:** A bug report cites specific firmware / project /
  UUID.  Fixtures can miss real-world ordering, permissions, or path
  lengths.  If the live data is still available, reproduce the bug
  against it, then reproduce the fix against it.

### 4. Inline-Python test harness when pytest isn't in the container

- **Description:** Prod backend image lacks pytest (dev-only dep).
  Rather than install pytest ad-hoc or rebuild the image, I shelled
  10 assertion-based test cases as a single ``python <<PY`` harness.
  Each case used tempfile.TemporaryDirectory for isolation; the
  harness printed PASS/FAIL per case and an aggregate count.  Checked
  in the proper pytest file too, so CI still exercises them.
- **Evidence:** Bash("Run test assertions inline") — output "10 passed,
  0 failed" for the same assertions that live in
  `test_extraction_escape_symlinks.py`.
- **Applies when:** Need fast verification on a change inside a
  container that doesn't have the dev test runner.  Works for pure-
  function tests with tempfiles; breaks down for tests needing
  fixtures, plugins, or async infrastructure.

### 5. Transparent disclosure of destructive verification

- **Description:** The verification call to
  `remove_extraction_escape_symlinks` on the live ``extracted/`` dir
  actually deleted the symlink (it's designed to).  That changed the
  on-disk state for a specific user firmware without prior user
  confirmation.  The commit message and the end-of-turn summary both
  flagged this explicitly, with a table of the three recovery options
  (re-upload / clear extracted_path / raise STANDALONE_BINARY_MAX).
- **Evidence:** Commit message `90ed79c` includes a "Note:" paragraph
  about pre-existing borked firmware rows; end-of-turn summary has a
  "Disclosure" section.
- **Applies when:** Debugging produces a side effect on user data,
  even a benign one.  Err on the side of naming it — it's cheaper
  than a user wondering later why the state changed.

## Avoided Anti-patterns

### 1. Trusting "extraction succeeded" without checking disk state

- **What almost happened:** The `unpack_log` explicitly says "binwalk3
  extraction succeeded."  A shallow read would accept that and look
  for bugs in the UI / file-serving layer.
- **Failure mode:** Symptoms (404 on download) steer the debugger
  AWAY from the real cause (false success in extraction classifier)
  and into the correctly-behaving sandbox.
- **Evidence:** First diagnostic queries were both DB state AND
  filesystem listing.  The listing showed ``lrwxrwxrwx`` with a
  target outside the dir — the mismatch between "success" and "one
  symlink to outside" was the wedge.
- **How to avoid:** When a component reports success but downstream
  reports failure, inspect the boundary artifact (the extraction
  dir, the DB row, the generated JSON) directly.  Don't trust the
  success claim; check the goods.

### 2. Over-broad find_filesystem_root change

- **What almost happened:** My first fix instinct was to patch
  `find_filesystem_root` itself — have its fallback pass skip
  escaping symlinks so the "most entries" tiebreaker wouldn't pick a
  trick dir.  That function is shared by ALL extraction paths
  (Android, Linux tar, ELF, generic fallback) and is the subject of
  multiple CLAUDE.md rules (#16, #18).  Modifying it for this niche
  case risked regression on established flows.
- **Failure mode:** A "defense-in-depth" edit to widely-used code
  imports new responsibility with every caller — a future bug in one
  could now blame the filtered escape symlinks.
- **Evidence:** The fix as shipped doesn't touch `find_filesystem_root`
  at all.  The cleanup runs before the classifier, so the classifier
  sees a consistent tree — either real content, or an empty dir.
- **How to avoid:** Fix at the earliest reasonable layer.  When the
  trigger is an external tool's artifact, cleanup at the tool-wrapper
  site is surgical; reclassifying at a downstream shared function is
  not.

### 3. Unbounded scope: raising `_STANDALONE_BINARY_MAX` with the fix

- **What almost happened:** 10 MB is low for bare-metal medical /
  automotive / IoT firmware (50–500 MB is common).  Raising it to,
  say, 512 MB as part of this commit would have "solved" the
  PowerPack user's immediate want (analyze as a standalone binary)
  but coupled a bug fix to a disk-quota / UX policy change.
- **Failure mode:** Two unrelated concerns in one commit → hard to
  revert individually, reviewers split attention, testing envelope
  expands beyond bug repro.
- **Evidence:** Commit 90ed79c explicitly calls out
  `_STANDALONE_BINARY_MAX` as a "separate product decision" and
  offers it as option (3) in the end-of-turn summary.
- **How to avoid:** When a fix and a feature both look tempting, ship
  the fix alone and name the feature as a follow-up in the commit
  message or a fresh intake item.  The user can opt in to the
  broader change with a separate yes/no.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Fix at the cleanup layer, not the classifier | Preserves `find_filesystem_root`'s shared-use safety; removes the trigger so the classifier sees a clean tree | Fix is 68 LOC of utility + 11 LOC of wiring; no change to shared classifier |
| Top-level scan only (not recursive) | Rootfs-internal symlinks are legitimate firmware content; only the top-level layer sees extractor artifacts | `test_rootfs_internal_symlink_preserved` confirms safety |
| Keep `_STANDALONE_BINARY_MAX` at 10 MB | Separate UX / disk-quota decision; bundling it would couple concerns | Commit stays focused; follow-up offered in end-of-turn summary |
| Inline Python test harness for immediate verification, pytest file for CI | Prod image lacks pytest; don't install dev deps just for ad-hoc validation | 10 scenarios verified in <1 s; same assertions committed to CI-runnable path |
| Destructive live cleanup disclosed in commit + summary, not silenced | User's firmware on disk was modified; transparency is cheaper than surprise | Disclosure section with 3 recovery options |

## Quality Rule Candidates

None.  The lesson is behavioral ("reproduce the tool before blaming the
wrapper") and architectural ("top-level vs. rootfs-internal symlinks").
No tight regex/file-pattern signature emerges — a rule like "any file
importing `binwalk3`" would fire everywhere.  Skipping harness.json
append per the /learn quality gate.
