# HANDOFF — 2026-04-17 MTK Subsystem Phase C

> Session: 9967a3b3 (DPCS10 firmware debugging + MTK subsystem parsers + CVE precision)
> Outgoing model: Opus 4.7 (1M)
> Branch: clean-history (27+ commits ahead of origin, nothing pushed)

## What shipped this session (4 commits)

| SHA | What |
|-----|------|
| `431e3ec` | EDAN partial-extraction diagnostic + zImage arch fallback (encrypted vendor containers get flagged, kernel-image header reader populates arch when rootfs is encrypted) |
| `9e1de6c` | MTK LK name-field dispatch + CVE aggregate dedup (Bug 1: 12 blobs → 7 correct categories; Bug 2: no more 1.9GB partition_size nonsense; Bug 3: 185,260 → 1,193 distinct CVEs) |
| `7ab35b5` | `mediatek_atf` / `mediatek_geniezone` / `mediatek_tinysys` parsers + **CVE-2025-20707 inline version-pin fingerprint** on GenieZone |
| `61ed863` | UI fixes — parser-detected CVEs surfaced in BlobDetail, version + CVE chips in tree view, honest "projection rows" label on aggregate |

**Containers all rebuilt** from committed source (`docker compose up -d --build backend worker frontend` at 18:50). All three show matching classifier.py + mediatek_geniezone.py mtimes. Frontend serving 200 on port 3000.

## Live state — DPCS10 verified

Project `fe993541-7f0d-47d7-9d2c-c40ab39a241f`, firmware `188c5b24-9852-4a99-93e5-15e847ebc6c0`:

- `gz.img` → format=`mtk_geniezone`, version `3.2.1.004`, build `2025-12-12`, **CVE-2025-20707 in `metadata.known_vulnerabilities`** (Medium, CWE-416). Visible in BlobDetail's dedicated "Known vulnerabilities — parser-detected" panel.
- `tee.img` → format=`mtk_atf`, TF-A `v1.3(debug):0cf92e67769`, git hash extracted, built `Apr 13 2026`
- `scp.img` → format=`mtk_tinysys`, FreeRTOS, Cortex-M vector table validated, board tag `aiot8788ep1_64_bsp_k66`
- `spmfw.img` → format=`mtk_tinysys`, PCM microcode `pcm_allinone_lp3_1866.bin`, `no_ghidra_import=true`
- `modem.img` → stub_descriptor flagged (528B md1rom on modem-less SKU)

## Known architectural gap — Phase C4 pending

**Problem**: parser-detected CVEs live only in `blob.metadata.known_vulnerabilities`. The UI's main CVE panel, aggregate count, and HBOM export all read from `sbom_vulnerabilities` — where parser CVEs don't exist. The BlobDetail patch in commit `61ed863` renders them separately as a workaround, but they're absent from roll-ups.

**Verdict from deep research (Option B)**: add a Tier 0 matcher `_match_parser_detected(blobs)` in `cve_matcher.py` (~40 LOC) that reads each blob's `metadata.known_vulnerabilities` and emits `CveMatch` rows with `tier="parser_version_pin"`. Zero DB migrations needed — `SbomVulnerability` already has `blob_id` FK, `match_confidence`, `match_tier`. Call it as the first tier in `match_firmware_cves`; existing dedup `(firmware_id, blob_id, cve_id)` in-memory set handles re-runs.

### Ready-to-implement implementation sketch

```python
# backend/app/services/hardware_firmware/cve_matcher.py

async def _match_parser_detected(
    blobs: Sequence[HardwareFirmwareBlob],
) -> list[CveMatch]:
    """Tier 0 — CVEs embedded by parsers (version-pin fingerprints).

    Parsers like mediatek_geniezone populate
    `blob.metadata["known_vulnerabilities"]` during detection. Project
    each to a CveMatch so the same dedup, persistence, UI read, and
    HBOM paths apply as the other tiers.
    """
    matches: list[CveMatch] = []
    for blob in blobs:
        known = (blob.metadata_ or {}).get("known_vulnerabilities") or []
        if not isinstance(known, list):
            continue
        for v in known:
            if not isinstance(v, dict) or not v.get("cve_id"):
                continue
            matches.append(
                CveMatch(
                    blob_id=blob.id,
                    cve_id=v["cve_id"],
                    severity=v.get("severity", "medium"),
                    cvss_score=None,
                    description=v.get("rationale", ""),
                    confidence=v.get("confidence", "high"),
                    tier="parser_version_pin",
                )
            )
    return matches
```

Then at the top of `match_firmware_cves()` (around line 512, before any other tier):
```python
all_matches.extend(await _match_parser_detected(blobs))
```

**Field mapping** the next session should confirm:
| parser record | SbomVulnerability column |
|---|---|
| `cve_id` | `cve_id` |
| `severity` | `severity` |
| `confidence` | `match_confidence` |
| `source` / fixed "parser_version_pin" | `match_tier` |
| `rationale` | `description` |
| `cwe` / `subcomponent` / `reference` | stay in blob.metadata; not columnar |

**Update the router aggregate counter** (`backend/app/routers/hardware_firmware.py:167-186`) to include Tier 0 in the `hw_firmware_cves` bucket (not kernel-tier). Currently the split is kernel-tier `{kernel_cpe, kernel_subsystem}` vs everything else — parser_version_pin slots into "everything else" correctly without code change, just worth verifying.

**Regression test target**: after C4 ships, re-run CVE match on DPCS10 → aggregate should show `hw_firmware_cves: 1` (the GenieZone CVE) instead of `0`; `/cves` endpoint for `gz.img` returns one row with `match_tier="parser_version_pin"`.

## Research also pending (unfinished when session handed off)

**Track B (ASB curated YAML harvest)** — spawned late in the session, may still be running when the next session opens. Check:
- `/tmp/claude-1002/-home-dustin-code-wairz/9967a3b3-9d94-485a-b2cd-9323d468932a/tasks/a3a946c5c89683cff.output`

The goal was 25-40 ready-to-paste family entries for `known_firmware.yaml` covering geniezone/atf/tinysys/wlan/modem subcomponents, sourced from Android Security Bulletin (CC-BY, safe to commit — unlike MediaTek's own PSB which has ToS problems per earlier research). When C4 Tier 0 ships, this YAML expansion is the natural next step; together they deliver both the parser fingerprint path AND the curated-broad-coverage path into one matcher pipeline.

**Track 3 research (confidence scoring + UX tiering)** — banked earlier in the session, already in `.planning/knowledge/hw-firmware-mtk-subsystem-parsers-patterns.md`. Has:
- Tier base scores (curated_yaml=90, parser_version_pin would be 90, kernel_subsystem=85, kernel_cpe=40)
- Adjustment formula (subcomp +15, version exact +10, age -5/-10, KEV +5, etc.)
- Confirmed/Suspect/Dismissed bucketing at 80/40 thresholds
- Implementation scope: ~300 LOC + one Alembic migration

## Durable lessons this session codified

See `.planning/knowledge/hw-firmware-mtk-subsystem-parsers-{patterns,antipatterns}.md`. Particularly worth reading before the next coding session:

- **Antipattern #9** (Docker hot-patching via cp while claiming done) — this session shipped a knowledge file that called out CLAUDE.md rule #8 and then violated it within 30 minutes. `docker compose cp` is iteration-only; ship-ready state requires full rebuild + `ps --format "{{.CreatedAt}}"` verification.
- **Antipattern #10** (parser-detected CVEs in metadata-only) — the root cause of the "I don't see CVEs" complaint. Parser output needs to feed through the existing state-machine (sbom_vulnerabilities), not park in a side table. This is the ENTIRE motivation for Phase C4.
- **Pattern #1** (empirical on-disk verification before parser code) — three research hypotheses were wrong; one 20-line docker-exec caught them before Python was written.
- **Pattern #2** (ship CVE fingerprints inline with parsers) — when a CVE has a pinned version threshold AND the binary carries an extractable banner, fingerprint in the parser. Cheap, zero-infrastructure, ships a real hit without a bulletin feed.

## Quality rule drafts blocked on protected file

Two medium-confidence rules drafted for `.claude/harness.json → qualityRules.custom` but the protect-files hook blocked the edit. Rules are listed at the bottom of `.planning/knowledge/hw-firmware-mtk-subsystem-parsers-patterns.md` — worth a manual add if you're tightening the harness. Summary:

1. `auto-mtk-subsystem-no-raw-cartesian-count` — flag `"count": len(matches)` in `hardware_firmware.py` router (dedup by distinct CVE).
2. `auto-mtk-bulletin-no-corp-mediatek-fetch` — flag any `httpx.get / requests.get` on `corp.mediatek.com` in backend code (ToS prohibits derivative works).

## Uncommitted / un-pushed state

- **Uncommitted in tree**: telemetry + harness state + pre-existing classifier-patterns-mcu-kernel closeout (knowledge MDs, postmortem, patterns YAML WIP). NONE of this was touched this session. Safe to leave or commit separately as a docs-only change.
- **Not pushed**: all 4 session commits + the 27 pre-existing commits. No `git push` issued this session.
- **Three containers rebuilt at 18:50**: backend, worker, frontend. All healthy. DB state reflects all session work (re-detection run populated new metadata including CVE-2025-20707 flag).

## Fastest path forward for next session

1. **Implement Tier 0 parser_version_pin** (30 min including test): add `_match_parser_detected` + 1-line call + 1 regression test. Commit.
2. **Verify live** on DPCS10: `POST /cve-match` → aggregate `hw_firmware_cves` should now show `1` for the GenieZone CVE; `/cves?blob_id=<gz_blob>` returns a row with `match_tier=parser_version_pin`.
3. **Harvest ASB YAML** (Track B research): 25-40 family entries, commit with attribution header. Re-run matcher → additional Tier 3 hits on chipset/subcomponent matches.
4. **(Optional)** Phase C4 confidence scoring — scope is ~300 LOC + migration; defer if session budget is tight.

Rebuild and verify per CLAUDE.md rule #8 before claiming done:
```
docker compose up -d --build backend worker frontend
docker compose ps --format "{{.Service}}\t{{.CreatedAt}}"
```
