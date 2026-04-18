# Anti-patterns: Phase C4 Tier 0 parser-detected CVE matcher (2026-04-17 session)

> Extracted: 2026-04-17
> Commit: `e74a31d`

Failure modes encountered during the Tier 0 continuation. None caused
rework; all were caught and corrected before commit. One is a RECURRENCE
of a pattern the prior session already surfaced — worth escalating.

## Failed Patterns

### 1. Running pytest in the backend container without dev deps installed (RECURRENCE)
- **What was done:** First invocation of `docker compose exec -T backend
  python -m pytest tests/test_hardware_firmware_cve_matcher.py` failed
  immediately with "No module named pytest."
- **Failure mode:** The production Dockerfile uses `uv sync --no-dev
  --no-editable`, which strips pytest + pytest-asyncio from the image.
  Tests can only run after a dev-deps install. The prior session's
  patterns file (`hw-firmware-mtk-subsystem-parsers-patterns.md` pattern
  #7) already documented the fix — invoke `.venv/bin/python -m pytest`
  from `/app`. But that doesn't help when the venv has no pytest at all.
- **Evidence:** Second session in a row that rediscovers this. The prior
  session noted the `.venv/bin/python` invocation form; this session hit
  the "even the venv has no pytest" variant. Root cause: `--no-dev` in
  the Dockerfile.
- **How to avoid:** The minimum incantation that works fresh-container:
  `docker compose exec backend uv sync` (installs dev deps into the
  running container's venv) `&&` `docker compose exec backend
  .venv/bin/python -m pytest tests/…`. This fact belongs in CLAUDE.md or
  an entry-point doc — three sessions independently rediscovering it is
  a signal that the documentation gap is structural, not individual.
  Candidate CLAUDE.md addition:

  > **Running backend tests requires dev deps installed in the running
  > container.** The production image strips pytest. Run
  > `docker compose exec backend uv sync` once per container lifetime,
  > then `docker compose exec backend /app/.venv/bin/python -m pytest
  > tests/…`. Rebuilding the container drops pytest again — rerun
  > `uv sync` after every rebuild where you plan to test.

### 2. Stale test assertions post silent feature change
- **What was done:** Commit `9e1de6c` ("MTK LK name-field dispatch + CVE
  aggregate dedup") changed `_match_kernel_cpe`'s hardcoded
  `confidence="medium"` to `confidence="low"` to let UIs down-rank
  Cartesian projection rows. Three test assertions in
  `test_hardware_firmware_cve_matcher.py` still expected `"medium"`.
  The suite went red and nobody noticed until the next session ran
  full-file tests.
- **Failure mode:** A symbolic-value change (enum, status string,
  severity tag) is structurally identical to a numeric refactor but
  grep-unfriendly: the old value is usually a common string. Tests
  asserting on the old value don't fail the change's review checklist
  because they're in different files. Failures only surface on the
  next full test run, which may be days or sessions later.
- **Evidence:** Three failing tests in the same file, all on a single
  line pattern (`assert m.confidence == "medium"`). Commit SHA that
  changed the production code: `9e1de6c`. Gap to detection: ~1 day
  across three sessions.
- **How to avoid:** When a commit changes a symbolic value (any hardcoded
  string, enum, status tag), grep the test directory for assertions on
  the OLD value in the SAME commit:
  `grep -rn '"medium"' backend/tests/` would have caught this. If the
  grep is too noisy, scope it by proximity — assertions involving the
  function/tier whose output you changed. Pattern: "I changed what this
  function emits → what asserts on this function's output?"

### 3. Commit message claiming live verification that wasn't run
- **What was done:** Initial draft of the commit message included
  "Verification: DPCS10 (project fe993541) — after POST /cve-match the
  GenieZone CVE-2025-20707 should now appear in the main aggregate
  count as hw_firmware_cves=1 (previously 0)."
- **Failure mode:** Used "should" instead of "did." The verification was
  NOT actually executed — hitting `/cve-match` against the running
  backend is a write operation (it persists new SbomVulnerability rows)
  that warrants user confirmation, per CLAUDE.md's action-reversibility
  guidance. Leaving "should" in the commit message is honest; using
  "did" would have been a quiet lie.
- **Evidence:** The commit message preserved "should" language. The
  session handoff's "Fastest path forward" step 2 (live verify) was
  explicitly deferred to the next session with that reasoning.
- **How to avoid:** When writing commit messages, distinguish
  expectations (what the change MAKES POSSIBLE) from observations (what
  WAS MEASURED). Use "expected" / "should" for the first, past-tense
  verification facts for the second. Don't assert a test you didn't
  run. The prior session's antipattern #9 is exactly this mistake's
  docker-cp cousin: "claimed live across all Docker" when only backend
  was rebuilt. Both are honesty failures at the write-ready boundary.

### 4. Mixed-scope commit temptation
- **What was done:** Considered bundling the pre-existing
  `test_mtk_lk_parser_extracts_partition_name_and_size` failure fix
  (unrelated — `partition_size` metadata key removed by commit `9e1de6c`)
  into the Tier 0 commit because the test suite was already being run.
- **Failure mode:** Scope creep. The parser test failure lives in a
  DIFFERENT test file, touches a DIFFERENT code path, and has a DIFFERENT
  root cause. Including it would have made the commit message
  misleading and review harder. The three Tier 4 `"medium" → "low"`
  assertion fixes WERE in the same file as Tier 0 changes and were
  rolled in; the parser test failure was NOT.
- **Evidence:** Decision logged in the handoff's closing summary —
  "Pre-existing, out of scope." The commit stayed focused on Tier 0.
- **How to avoid:** Apply a two-axis test: (a) is the fix in the same
  FILE as my primary change? (b) is the fix in the same CONCEPTUAL
  unit? Both yes → roll in. Same file, different concept → probably
  still roll in with a separate commit message line. Different file,
  different concept → always a separate commit. The handoff's next
  session will pick up "one pre-existing failure noted, not mine to
  own."

## Recurring themes

- **Docker dev-deps friction is structural, not personal.** Three
  sessions, three rediscoveries of the same "pytest not in production
  image" surface. The fix is a CLAUDE.md entry, not individual memory.
- **Symbolic-value changes need a grep ritual.** Any time a hardcoded
  string/enum changes, the commit that makes the change should include
  a grep pass across tests for assertions on the old value. Cheap,
  recurring value.
- **Honesty at the write-ready boundary matters.** Commit messages and
  handoffs are the two surfaces where "I did X" becomes durable
  testimony. Both sessions in a row hit a variant: prior session's
  docker-cp/claim-done (#9 there), this session's "should have verified
  live" temptation (#3 here). The fix is the same mental check both
  times — "did I measure this or am I predicting it?"
