# Patterns: MTK MCU Coverage

> Extracted: 2026-04-17
> Session: `626b3752` (no formal campaign — direct execution under `/do continue`)
> Commit: `9480bc7 feat(hw-firmware): MTK MCU coverage`
> Related work: `.planning/knowledge/handoff-2026-04-17-mtk-phase-c.md`,
>                `.planning/knowledge/hw-firmware-mtk-subsystem-parsers-patterns.md`

## Successful Patterns

### 1. Live-data pre-flight before generating matchers
- **Description:** The handoff said "do step 3 — ASB YAML harvest." Before
  spawning the research agent or writing entries, queried the live DB
  (`SELECT chipset_target FROM hardware_firmware_blobs WHERE format LIKE 'mtk_%'`)
  and discovered chipset_target was NULL on every MTK tinysys/atf/geniezone
  blob. The matcher's `if not blob_chipset: continue` would have made every
  chipset_regex YAML entry silently no-op.
- **Evidence:** Caught the gap in one psql query (~30s) instead of after
  shipping a 18-entry YAML harvest that produced zero new matches. Forced
  the work order to be 1+2+3 instead of 1+3 with 2 deferred.
- **Applies when:** Adding rule-based matching against a column or field
  populated by a separate component. Always confirm the input field is
  populated on the target data before writing the rules.

### 2. Sequence prerequisites before deliverables (chipset_target before YAML)
- **Description:** The four-item plan (categorization fix → chipset wiring →
  YAML harvest → version-banner extraction) was sequenced specifically so
  the chipset_target population (item 2) shipped before the YAML entries
  that depend on it (item 3). Each item's verification depended on the
  previous item being live in the running container.
- **Evidence:** Final cve-match showed `hw_firmware_cves: 27` because all
  three items shipped together; if item 3 had shipped alone, only the
  chipset-less entries (modem cluster + advisory) would have fired.
- **Applies when:** A multi-step change has data dependencies between steps.
  Identify the data flow first, then sequence so each step has its inputs
  populated before its consumer runs.

### 3. Web-research agent with explicit anti-scope
- **Description:** Spawned the deep-research agent with hard "Do NOT scrape
  corp.mediatek.com (ToS-prohibited derivative works)" constraint embedded
  in the brief, alongside positive "use Android Security Bulletin
  (CC-BY 2.5) and NVD (public domain)" sources. The constraint preserved
  the prior session's licensing decision without re-litigating it.
- **Evidence:** Agent's report explicitly noted "MTK PSB pages not scraped
  per ToS — all data above sourced from ASB and NVD only" and reproduced
  ALPS/MOLY/WCNCR patch IDs as factual cross-reference (allowed) rather
  than scraping bulletin text (prohibited).
- **Applies when:** Briefing a research agent on a topic where prior
  context contains licensing or scope decisions. State the negative
  constraints, not just the positive sources.

### 4. Anchor commit copy to the user's exposed need
- **Description:** Commit message leads with: "Three changes drive a 1 → 27
  distinct hw-firmware CVE uplift on DPCS10 and answer 'why aren't MTK
  microcontrollers showing as MCUs?'" — directly cites both the measured
  outcome and the user's original question.
- **Evidence:** Compare to a generic message like "feat: add MTK MCU YAML
  entries". The actual message gives the reviewer the customer-impact
  framing in one sentence.
- **Applies when:** Writing commits/PR descriptions for work driven by a
  specific user complaint or question. Lead with the answer, then the
  technical change.

### 5. Empirical verification ladder (parse → test → re-detect → curl API)
- **Description:** Each item shipped through four independent verification
  rungs:
  1. Local YAML parse confirms syntactic validity (`python -c "yaml.safe_load(...)"`)
  2. Container-side pytest confirms unit-level correctness (78/78 green)
  3. Wipe + re-detect + match script confirms data-flow correctness
     (chipset='mt8788' on scp.img; 27 distinct CVEs)
  4. Production HTTP endpoint confirms ship-ready container state
     (`curl POST /cve-match` returned matching counts)
- **Evidence:** Each rung caught a different class of mistake — rung 1
  caught YAML syntax, rung 2 caught regex too strict (`\bmt8195\b` failed
  on `MT8195_PROJ`), rung 3 caught the VARCHAR(20) constraint, rung 4
  confirmed the docker-cp'd YAML matched the rebuilt image.
- **Applies when:** Any change spanning multiple layers (config → code →
  DB → API). Don't claim done until the last rung passes.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Categorize SCP/SCP1/SCP2/tinysys-* as `mcu` (was `dsp`) | SCP is a Cortex-M4 system controller, not a signal processor; aligns with sspm/spmfw/mcupm/dpm | Worked — directly answered user's question |
| Keep VPU/APU under `dsp` | They actually ARE DSPs (vision / AI accelerators); only SCP was mis-tagged | Correctness preserved; no over-correction |
| Derive chipset from `platform_tree` AND AIoT board names | platform_tree gives explicit `mt6771`; AIoT boards encode the SoC in the board tag (`aiot8788ep1` → `mt8788`) | Worked — scp.img got chipset='mt8788' on first try |
| Use word-boundary-style regex `(?<![A-Za-z0-9])mt(\d{4,5})(?!\d)` instead of `\bmt\d+\b` | `\b` doesn't trip on `_` so `MT8195_PROJ` was rejected; trailing `(?!\d)` prevents truncating `mt67711` | Test caught it; fix was one regex tweak |
| Drop `chipset_regex` on modem-format YAML entries | mtk_lk parser doesn't populate chipset_target on modem.img / md1*.img blobs; better to over-fire than under-fire | Worked but introduces noise; flagged as a future work item to write a chipset-aware mtk_modem parser |
| Name the SSPM/SPMFW/MCUPM advisory just "MTK PM" | cve_id is VARCHAR(20); ADVISORY-MTK-PM = 15 chars fits; longer names blow the constraint | Worked; latent bug remains for the existing kamakiri advisory entry (not in scope) |
| Bundle categorization + chipset wiring + YAML into one commit | All three are interdependent — can't review chipset_regex YAML without seeing the chipset population it depends on | Cleaner reviewable atomic change |
| Defer SCP version-banner fingerprinting (item 4 of original plan) | DPCS10's mt8788 SCP is outside CVE-2025-20668's affected chipset list anyway; payoff for THIS firmware is zero | Right call; logged as separate-session work for Dimensity-class samples |

## Reusable Helper

`derive_chipset(metadata: dict) -> str | None` in
`backend/app/services/hardware_firmware/parsers/mediatek_gfh.py:288` is the
canonical entry point. Call it from any new MTK parser before returning
`ParsedBlob` so chipset_regex matching keeps working as new formats land.
