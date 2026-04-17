# Architectural Fix Design

> Scout 4 of 4
> Date: 2026-04-17

## Summary

**Recommended: Option A (helper module) as the ship-now fix, with a lightweight
Option A+ evolution using `device_metadata` JSONB for persistence.** Wairz
already uses `device_metadata` (JSONB) as its free-form escape hatch on the
Firmware row and follows a service-function convention for cross-cutting
concerns (`firmware_context.py`, `sandbox.py`). A new migration for a single
ARRAY column is disproportionate to the bug — detection-root derivation is
computable deterministically from the existing `extracted_path`,
`extraction_dir`, and the classification that already lives in
`unpack.py::classify_firmware`. A helper encapsulates the known sibling-dir
pattern today, caches the result in `device_metadata["detection_roots"]` when
the unpacker writes it, and leaves the door open to promote to a first-class
column later if demand grows. It matches Wairz's "lean toward JSONB/metadata,
minimal migrations" convention while giving all ~15 consumers a single
call-site to switch to.

---

## Option A — Helper Module

### Design

**Location:** `backend/app/services/firmware_paths.py` (new file).
Follows existing service module layout (`firmware_context.py`,
`firmware_service.py`).

**Signature:**

```python
from pathlib import Path

def get_detection_roots(firmware: "Firmware") -> list[str]:
    """Return every directory that should be walked when analysing this
    firmware's content.

    For multi-partition Android containers (OTA, sparse, super.img,
    scatter), this returns the parent that contains all partition
    sibling dirs.  For single-root firmware (Linux rootfs tar, standalone
    APK, UEFI dump, ELF/PE binaries, Intel HEX, RTOS blob), this returns
    a single-element list.

    Order: the canonical root first, then auxiliary roots (boot/,
    partitions/, rootfs/_extract/).

    Never returns an empty list if the firmware has any usable path —
    worst case, falls back to [extracted_path] or [extraction_dir].
    Returns [] only when both are unset (unpack not yet complete).
    """

def get_primary_root(firmware: "Firmware") -> str | None:
    """Single-root API for consumers that cannot iterate (FileService,
    sandbox resolve).  Returns the first element of get_detection_roots()
    or None if nothing is extracted yet."""

def iter_walk_roots(firmware: "Firmware") -> Iterator[str]:
    """Streaming wrapper for walk-based consumers (SBOM, YARA, hw-fw
    detector).  Deduplicates by realpath."""
```

**Per-type dispatch logic (no schema change required):**

The helper inspects `firmware.extracted_path` and reads sibling directories
on disk — reusing `_pick_detection_root()` from `unpack.py` verbatim but
returning a list rather than replacing the single path. Dispatch key is
derived from inspecting the directory structure, not from a persisted
`firmware_type` column (which doesn't exist). Rules:

1. If `extracted_path` has Android partition-like siblings
   (`_ANDROID_PARTITION_SIBLINGS` set OR ≥2 `partition_*` entries),
   return `[parent(extracted_path)]`. This is the documented bug fix.
2. Otherwise return `[extracted_path]`.
3. If `extraction_dir` is set *and* distinct from both the return set
   and `extracted_path`'s parent, append it (catches binwalk/unblob
   output dirs with sibling `_extract/` trees).
4. Special-case: for `android_boot`, both `rootfs/boot/ramdisk/` and
   `rootfs/boot/` are valid roots; detector currently uses only the
   ramdisk. Helper returns both in order.
5. For standalone APK (`android_apk`), returns `[extracted_path]` only
   (single .apk file container).

**Caching (zero-cost upgrade path):** The first time the helper runs, it
writes its result to `firmware.device_metadata["detection_roots"]`. Every
subsequent call short-circuits to the cached value. This means we get
(a) the fix immediately without a migration and (b) a DB-visible source
of truth that debug tools and Scout 3 (live-DB-auditor) can inspect.

### Pros / Cons

**Pros**
- Zero migration, zero backfill. Ships today.
- Cached in JSONB — not purely derived, so Scout 3's concern ("what if
  the siblings are gone?") is addressed from run 1.
- Single call-site to fix all ~15 consumers identified by Scout 2.
- Fails closed: if the helper doesn't know a firmware type, it returns
  the current single-path behavior — no regression risk.

**Cons**
- Heuristic matching on disk structure at call time (same as current
  bug fix in `unpack.py`). Mitigated by JSONB cache.
- Per-type dispatch table is centralized; adding a new firmware type
  (iOS IPSW, OpenWrt multi-root) still requires touching one module.
- The JSONB cache key is a new convention — needs documentation in
  CLAUDE.md.

### Effort estimate (session count)

- **1 session** to write `firmware_paths.py` + unit tests (helper is
  ~60 LOC incl. docstrings).
- **1 session** to migrate the 3 critical consumers: `hw-firmware
  detector`, `sbom_service`, `yara_service`.
- **1 session** to migrate the remaining 12 consumers (most are
  MCP tool handlers in `ai/tools/*.py` that use `context.resolve_path`
  — these mostly just need `extracted_path` swapped for
  `get_primary_root()`).
- **0.5 session** for CLAUDE.md update + observability (log the
  roots the first time the helper resolves them).

**Total: ~3.5 sessions.**

### Files affected

New:
- `backend/app/services/firmware_paths.py`
- `backend/tests/services/test_firmware_paths.py`

Modified (per Scout 2 inventory — estimates from the grep results):
- `backend/app/services/hardware_firmware/detector.py`
- `backend/app/services/yara_service.py`
- `backend/app/services/sbom_service.py` (caller of — not yet read, implied)
- `backend/app/services/firmware_service.py`
- `backend/app/workers/unpack.py` (move `_pick_detection_root` into helper,
  keep thin shim for back-compat)
- `backend/app/routers/{sbom,files,analysis,terminal,security_audit,...}.py`
  — ~10 routers touch `firmware.extracted_path` directly; swap to
  `get_primary_root()`.
- `backend/app/ai/tools/filesystem.py` and friends (≈8 tool modules).
- `CLAUDE.md` — document the new helper + JSONB cache key.

---

## Option B — Schema Column

### Migration design

**Column type:** `detection_roots: ARRAY(Text)`, nullable. PostgreSQL
native array, not JSONB, because we want cheap contains-checks and
ordering semantics.

**Alembic sketch:**

```python
# e.g. e1f2a3b4c5d6_add_detection_roots_to_firmware.py
def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "detection_roots",
            postgresql.ARRAY(sa.Text()),
            nullable=True,
        ),
    )

def downgrade() -> None:
    op.drop_column("firmware", "detection_roots")
```

**Backfill:** One-shot Python migration script that iterates every
Firmware row, calls `get_detection_roots()` against the on-disk state,
and sets `detection_roots`. Since the unpack artifacts for old firmware
still exist under `STORAGE_ROOT`, this walk is 1 `os.listdir()` per row
— roughly free for <5,000 rows. If the directory is gone (firmware was
deleted but row retained), set `detection_roots = [extracted_path]` as
a safe default. Can run inside the migration itself:

```python
def upgrade() -> None:
    op.add_column(..., nullable=True)
    # Backfill in post-create batch
    conn = op.get_bind()
    firmware = conn.execute(sa.text("SELECT id, extracted_path FROM firmware WHERE extracted_path IS NOT NULL"))
    for row in firmware:
        roots = compute_roots_from_disk(row.extracted_path)
        conn.execute(
            sa.text("UPDATE firmware SET detection_roots = :r WHERE id = :i"),
            {"r": roots, "i": row.id},
        )
```

Not 1-line-per-row — needs `compute_roots_from_disk`, which is the
same logic as Option A's helper. So Option B's backfill is
"re-implement Option A inside a migration script."

### Unpacker changes

- `UnpackResult` dataclass grows `detection_roots: list[str] | None`.
- `_analyze_filesystem`, `_extract_android_ota`, etc. populate it.
- `arq_worker.py` assigns `firmware.detection_roots = result.detection_roots`
  alongside the other fields (line 103-108 area).

### Pros / Cons

**Pros**
- Single source of truth in the DB.
- Cheap to query/inspect; no on-disk scan needed after extraction.
- Cleanly indexable if we ever need `WHERE '/path' = ANY(detection_roots)`.

**Cons**
- Migration + backfill burden.
- All code paths that write to `extracted_path` (unpack.py, firmware_service.py
  manual-rootfs, device_service restore) must remember to also write
  `detection_roots` — new failure mode.
- A Firmware row's two path columns can drift if one writer forgets to
  update the other.

### Effort estimate

- **1 session** migration + backfill script (backfill reuses Option A logic, so
  effectively this is Option A *plus* migration).
- **1 session** unpacker instrumentation (UnpackResult + every write site).
- **1 session** consumer migration (same as Option A).
- **1 session** backfill execution + verification (run in dev, staging, prod;
  write a reconciliation query to detect drift).

**Total: ~4 sessions.** Higher than Option A because of the persistent
write-site hazard (every future unpack path must remember it) and
backfill verification.

---

## Option C — Normalize Layout

### Disk-layout change

`unpack_android._extract_android_ota` currently extracts partitions under
`extraction_dir/rootfs/{system,vendor,...}`, then sets `extracted_path =
rootfs/system` (or whichever matches `find_filesystem_root`). This
sibling layout IS the bug.

Proposed change: `find_filesystem_root` already treats `rootfs/` as a
candidate root when it exists. Change it to *always* return
`extraction_dir/rootfs/` for Android extractions (where multiple
partitions exist as siblings). Detector walks `rootfs/` → sees all
partitions.

### Hard-link vs copy tradeoff

No copies or hard-links required — the partitions are already laid out
as siblings under `rootfs/`. The fix is purely one of `find_filesystem_root`
heuristics: stop descending into a single partition when the parent has
multiple partition-shaped siblings.

If the layout required flattening (e.g., symlink `rootfs/_all/` pointing
at each partition), hard-links beat copies 20:1 on disk — a typical
Android OTA extraction is 4–8 GB, and copies would inflate to 8–16 GB.
Hard-links work since partitions are on the same filesystem. But this
is hypothetical: the existing tree is already unioned under `rootfs/`.

### Pros / Cons

**Pros**
- Zero consumer changes. `firmware.extracted_path` remains the One Path.
- Simplest conceptual model.
- Backwards-compatible on existing extractions: if we just change
  `find_filesystem_root` to prefer `rootfs/` over `rootfs/system` when
  siblings are present, existing rows' `extracted_path` values no
  longer point at the right place → they'd need to be updated.

**Cons**
- Changes `extracted_path` semantics from "a filesystem root" to "a
  container of filesystem roots." Consumer `detect_os_info`,
  `detect_architecture`, and `detect_kernel` all assume a rootfs tree
  (expect `bin/`, `etc/`, `usr/bin/` as children). They break on a
  container directory.
- Rewrite of `detect_architecture`, `detect_os_info`, `detect_kernel`,
  and any consumer that treats `extracted_path` as a rootfs.
- Backfill still required to update existing rows' `extracted_path`.
- Loses the semantic "which partition is the primary rootfs?" info —
  some Android-specific consumers need that.

### Effort estimate

- **2 sessions** change layout + rewrite arch/OS/kernel detection to
  tolerate container-of-rootfs.
- **2 sessions** update every consumer that walked down from rootfs/
  (sbom service assumes rootfs layout heavily).
- **1 session** backfill existing firmware (update extracted_path to
  parent, or remove+re-unpack).

**Total: ~5 sessions**, with the highest regression risk of the three.

---

## Recommendation

**Option A, shipped in three phases with Option A+ (JSONB cache) as a
near-zero-cost enhancement.**

Rationale:

1. **Wairz convention:** `device_metadata` is already the JSONB escape
   hatch. A `detection_roots` key in it costs nothing and gives Scout 3
   the DB-visible truth they want. CLAUDE.md explicitly steers toward
   JSONB over new columns for evolving metadata.
2. **Effort vs risk:** 3.5 sessions, no migration, no schema churn.
   Option B is 4+ sessions with a persistent write-site hazard. Option
   C is 5+ sessions with high regression risk.
3. **Future-proofing:** iOS IPSW (DMG with multiple partitions),
   Qualcomm TEE (multiple rawfs images), OpenWrt multi-radio builds —
   all require the same "walk multiple roots" semantic. A helper that
   takes a Firmware and returns roots accommodates any of them by
   adding a branch to the dispatch.
4. **Cleanliness:** One function to change, one cache to invalidate,
   one place to add instrumentation. Contrast with Option B where
   write-sites are scattered across 5+ files.
5. **LATTE / multi-binary analysis:** the future `FirmwarePath` table
   (fourth-option variant below) becomes natural if we later want
   provenance per path (which partition did this blob come from, which
   OTA step, which encryption key). Option A's helper migrates cleanly
   into a table-backed lookup later.

### Fourth option considered and rejected (for now)

**Option D — FirmwarePath table (normalized relation)**

Schema:
```
firmware_paths (
    id UUID PK,
    firmware_id UUID FK,
    path TEXT,
    role TEXT,  -- 'rootfs' | 'boot' | 'partition_container' | 'auxiliary'
    partition_name TEXT NULL,
    created_at TIMESTAMPTZ
)
```

This is the "correct" long-term design. Every consumer queries paths
for role = 'rootfs' or whatever fits. Supports provenance, ordering,
and multi-root cases natively. But it's a table-create + 4 files of
relationship wiring + migration + backfill, probably 5+ sessions.

**Deferred**, not abandoned. Option A's helper is a stepping stone:
when demand for per-path metadata grows (LATTE's path-level
entitlements, iOS IPSW's per-partition signing keys), the helper's
return type promotes from `list[str]` to `list[FirmwarePath]` and the
dispatch moves from disk inspection to DB query.

---

## Implementation Sketch (Option A)

### Phase 1: Add helper + tests (1 session)

- Create `backend/app/services/firmware_paths.py` with
  `get_detection_roots`, `get_primary_root`, `iter_walk_roots`.
- Move `_pick_detection_root` and `_ANDROID_PARTITION_SIBLINGS` from
  `unpack.py` into the helper. Keep a thin re-export in `unpack.py`.
- Unit tests in `backend/tests/services/test_firmware_paths.py`:
  - Multi-partition Android (siblings present).
  - Single-root Linux rootfs.
  - Single-root standalone APK.
  - `extracted_path` is None (pre-unpack).
  - `extracted_path` points at a missing directory.
  - JSONB cache hit vs miss.

### Phase 2: Migrate critical consumers (1 session)

Priority order (these are the data-loss surfaces Scouts 1/2/3 flagged):

1. `hardware_firmware/detector.py` — replace
   `_pick_detection_root(extracted_path)` with
   `get_detection_roots(firmware)`. The detector becomes a loop over
   roots.
2. `sbom_service.py` — the SBOM walk was flagged as walking
   `extracted_path` only. Swap to `iter_walk_roots`.
3. `yara_service.py` — same treatment.

### Phase 3: Tests + validation (1 session)

- Add an integration test: upload a multi-partition Android OTA (mock
  fixture), run detection, assert blobs from `vendor/`, `system/`,
  `odm/` all appear.
- Regression test the single-root firmware types don't change behavior
  (Linux rootfs, APK, UEFI, ELF).
- Add Scout 3's "live DB auditor" query as a CI smoke test: for every
  firmware where `os.path.basename(extracted_path) in
  _ANDROID_PARTITION_SIBLINGS`, assert the blob count > 0 rows from
  sibling partitions.

### Phase 4: Backfill existing firmware (0.5 session)

Not strictly required — the JSONB cache populates lazily on first
helper call. But for immediate visibility, a one-shot script
(`scripts/backfill_detection_roots.py`) that iterates all firmware
rows, calls the helper, and persists the cache. Idempotent.

Follow-up: re-run `detect_hardware_firmware` on firmware whose
`device_metadata["detection_roots"]` expanded from 1 to >1 path.
That's the real data recovery step — existing hw-firmware blobs for
those rows are incomplete.

### Phase 5: Observability (0.5 session)

- Log `detection_roots` at the start of every walk-based service
  (detector, SBOM, YARA). One line, one time per unpack.
- Prometheus-style counter (if/when metrics land):
  `firmware_detection_roots{count="1|2|3|4+"}`. A sudden drop in
  multi-root count after a deploy means a regression.
- Add a CLAUDE.md "Learned Rule #16": Every filesystem walker over a
  Firmware row MUST use `get_detection_roots` / `iter_walk_roots`,
  never read `firmware.extracted_path` directly. Add a grep-based
  pre-commit check to enforce.

---

## Risks

| Risk | Mitigation |
|---|---|
| Helper dispatch misses a future firmware type | Falls back to `[extracted_path]` — same behavior as today, no regression. Log a warning on the fallback path. |
| Consumers forget to migrate; continue reading `extracted_path` directly | Pre-commit grep check: `grep -rn 'firmware\.extracted_path' backend/app/services backend/app/routers backend/app/ai/tools` — whitelist the ~3 known-safe call sites, fail CI on new ones. |
| JSONB cache goes stale if disk is reorganized | Cache key includes `extraction_dir` modtime. On miss, recompute. In practice, extraction directories don't change after unpack. |
| Performance regression from `os.scandir(parent)` on every call | Cache hit path is a dict lookup. Miss path is one scandir — same as today's bug fix in `unpack.py`. |
| Partial migration: some consumers migrate, others don't — data is inconsistent | Phase 2 migrates all 3 critical (detection-side) consumers atomically. Routers and MCP tools can migrate incrementally — they're read-side, worst case they see one root instead of N (same as today's bug). |
| Siblings detection false-positive (non-Android firmware with partition-shaped dirs) | Allow-list siblings (`_ANDROID_PARTITION_SIBLINGS`) is tight. `partition_*` prefix requires ≥2 matches. This heuristic is already in prod in `unpack.py`. |

---

## Connection to Future Campaigns

- **iOS IPSW:** IPSW is a ZIP with multiple DMGs (root FS + secondary +
  update RAM disk). Helper returns all three. No further changes
  needed to detector / SBOM / YARA — they iterate roots.
- **Qualcomm TEE:** TZ images, QSEE trustlets, SBL/ABL sit beside the
  Android partitions. Helper returns `[parent]` and TEE detector
  picks them up naturally from the scan.
- **LATTE (path-level taint):** Eventually needs per-path provenance
  (which partition, which firmware, which signer). Helper return type
  promotes from `list[str]` to `list[FirmwarePath]` — Option D
  silently enabled.
- **OpenWrt multi-radio builds:** Two rootfs images (main + wireless
  module). Helper dispatches on `openwrt_multi_root` marker
  (presence of `rootfs.squashfs` + `rootfs-wireless.squashfs`).
- **Firmware diff (comparison router):** Cross-firmware diff already
  walks trees. Migrating to the helper gives it multi-root-aware diff
  for free.

---

## Confidence

**High** on the recommendation (Option A).

- The sibling-partition bug is *already* solved inside `unpack.py`
  (the `_pick_detection_root` helper exists and works — lines 52-68
  of `unpack.py`). We just need to extract it, generalise to
  `list[str]`, and ensure every consumer calls it.
- No schema change, no backfill, no production risk.
- The `device_metadata` JSONB cache is a clean fit with the existing
  pattern documented in CLAUDE.md.
- Effort estimate is grounded in counted call-sites (15 consumers,
  grep-verified).

Medium confidence on effort estimates (±1 session) — the 12 non-critical
consumers may have subtle `FileService` integration issues that only
surface when exercised via MCP.
