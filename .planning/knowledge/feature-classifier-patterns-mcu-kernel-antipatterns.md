# Anti-patterns: Classifier patterns — NXP iMX-RT MCU + ARM zImage + vendor signed archives

> Extracted: 2026-04-17
> Campaign: .planning/campaigns/completed/feature-classifier-patterns-mcu-kernel.md

## Failed Patterns

### Quality rule (ADOPTED 2026-04-18)

Appended to `.claude/harness.json` as `auto-classifier-magic-offset-beyond-buffer` during the 2026-04-18 /learn re-run.  Pattern catches `magic[0x100...` and above (3+ hex digits beyond the 64-byte buffer cap) in the classifier file only.  Message points to the two safe alternatives: widen `_MAGIC_READ_BYTES` with a rationale OR route through a per-format parser in `parsers/`.

## Failed Patterns

### 1. Proposing a magic-byte check at an offset beyond the magic buffer
- **What was done:** Intake brief proposed an iMX-RT BOOT_DATA magic-byte check at file offset 0x1000 (4096 bytes). The classifier receives only the first 64 bytes of each file via `detector._MAGIC_READ_BYTES = 64`.
- **Failure mode:** If coded naively (`magic[0x1000:0x1004] == b"..."`), the check silently never fires — `magic` is too short. Worse, if someone widens the buffer reflexively, every file scan reads an extra 4KB with no throughput controls.
- **Evidence:** Spotted during research phase before any code was written — `_read_magic_and_hash` reads `_MAGIC_READ_BYTES` (64). Decision Log records the drop.
- **How to avoid:**
  - Before adding a magic gate, check the magic-buffer size hard cap (`detector._MAGIC_READ_BYTES`).
  - If the target offset is ≥ that cap, either (a) fall back to filename-only detection, or (b) add a parameterized read path keyed to filename-category hints. Don't quietly add an unreachable check.
  - When an intake proposes an offset, cite the cap in the campaign's Decision Log and either honor it or explicitly widen it with a rationale.

### 2. Assuming `pytest` or `python` in a Docker container includes the app's dependencies
- **What was done:** First test-runner invocation was `docker compose exec backend pytest …`. Second was `docker compose exec backend python -m pytest …`.
- **Failure mode:** First failed with "pytest: executable file not found". Second failed with "No module named sqlalchemy". The backend's system Python is stripped; app deps live in `/app/.venv`.
- **Evidence:** Two failed invocations before `find / -name sqlalchemy` revealed the venv path. Tests passed on the third try with `.venv/bin/python -m pytest`.
- **How to avoid:**
  - First test-runner invocation on this project should always be `docker compose exec backend .venv/bin/python -m pytest …`.
  - Suggest documenting this in CLAUDE.md under a "Running tests" section so the pattern is discoverable without trial and error.

### 3. (Avoided — worth naming) Writing an overly broad kernel pattern without a magic gate
- **What was done:** NOT done in this campaign — but tempting. The filename pattern `^zImage.*$` alone would false-positive on Android zImage partition files (which are valid kernels, so category-level the match is right) but also on any random file whose name starts with "zImage" — say, a bookkeeping file called `zImage-notes.txt`.
- **Failure mode:** Would emit kernel classification for non-kernel files.
- **Evidence:** The final implementation uses `^zimage([-_.][a-z0-9._-]*)?$` (no trailing wildcard) AND keeps the magic-byte gate as the high-confidence upgrade path. The intake called this out as a risk; the pattern was tightened accordingly.
- **How to avoid:** When writing broad filename patterns for commonly-named blobs, anchor the regex tightly (no trailing `.*`) and pair with a magic-byte gate for the high-confidence case. If the magic gate fits in the 64-byte buffer, include it. If not, accept lower confidence and document the trade-off.
