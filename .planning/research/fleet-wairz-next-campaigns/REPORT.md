# Research Fleet: Wairz Next Campaigns (4 Candidates)

> Question: Which of four candidates should Wairz pursue as the next campaign, and what does each look like at implementation-ready detail?
> Date: 2026-04-17
> Scouts: 4 in 1 wave
> Confidence: **High** overall

## TL;DR — One paragraph

All four candidates are technically viable on Wairz's current architecture. But **Candidate 4 (VEX + Dependency-Track) is not a campaign — it's an afternoon** because Wairz already has 80% of the plumbing (DependencyTrackService, /sbom/export?format=cyclonedx-vex-json, VEX mappers, MCP tools). The actual campaign candidates are iOS IPSW (biggest device-class unlock), LATTE LLM taint (biggest novelty), and Qualcomm TEE (deepest on existing strength). Recommendation: **ship VEX polish immediately (1 session, ~200 LOC), then pick iOS or LATTE for the next major campaign based on Dustin's appetite for new-device-class vs. AI-frontier work.**

## Consensus Findings

1. **Wairz's existing architecture supports all four** — FastAPI async + MCP ToolContext + YAML-driven CVE matcher + Ghidra headless + kernel.org vulns.git tier 5 each scout found a clean integration shape without architectural surgery.
2. **No new pip dependencies are required for three of four** — iOS (ipsw Go binary as subprocess), LATTE (pure prompt + existing decomp cache), VEX (pure dict building). Only Qualcomm TEE might benefit from vendored code from the arXiv 2507.08331 companion repo.
3. **All four can live on the existing schema** — zero migrations across the four campaigns. Phase 2's Decision Log pattern (store in `metadata_` JSONB) keeps paying dividends.
4. **The Phase 2 pattern of live verification during a campaign applies to all four** — iOS (run a real IPSW through the new unpack), LATTE (run on a DVRF binary with known CVE), TEE (run on a Samsung image's mcRegistry), VEX (validate against EMBA's output format).

## Conflicts

**None substantive.** The four candidates don't compete technically — they're independent additions. Only resource conflict: one campaign at a time, so sequencing matters.

## Surprises

**VEX+Dependency-Track is mostly already shipped.** Scout 4 discovered that `DependencyTrackService.push_sbom()`, `GET /sbom/export?format=cyclonedx-vex-json`, three VEX state/justification mappers, and MCP tools `export_sbom` / `set_vulnerability_vex_status` / `push_to_dependency_track` all already exist. The only gap is: the HBOM export (`hbom_export.py` from Phase 5) doesn't emit the `vulnerabilities[].analysis.*` VEX fields. Fix is ~150 LOC, one session. This reframes the candidate from "Tier 2 campaign" to "quick polish we should just ship."

## Key Findings by Angle

### 1. iOS IPSW / IMG4 Firmware Support
**Brief:** `.planning/research/fleet-wairz-next-campaigns/ios-ipsw-img4.md` (1,317 words, 27 citations)

- **Tool of choice:** `blacktop/ipsw` (MIT, v3.1.664 Mar 2026, self-contained Go binary). Wrap as subprocess; do NOT port to Python.
- **Mach-O path is solid** — `ipsw kernel extract` emits Ghidra-loadable arm64e Mach-O. No new decompiler needed.
- **SEP / baseband:** classify-only for MVP. A11+ SEP keybags are device-bound; Hexacon 2025 confirms this is active research, out of scope for a campaign.
- **Apple CVE feed:** no machine-readable source. Recommend 6th matcher tier scraping `support.apple.com/en-us/100100` monthly (~150 LOC) with NVD fallback.
- **Licensing:** IPSW files are Apple-copyright (user-upload-only, same pattern as Android). `ipsw` binary itself is MIT. Do not ship `ipsw download` — Apple has DMCA history on beta distribution.
- **Estimate:** ~1,200 LOC across 6 new + 4 modified files. **2-3 sessions.**
- **Scope calls for Archon:** bundle `ipsw` in Docker (+60-90MB, recommended) vs host install; defer CVE scraper to follow-up; Darwin-only `dsc_extractor.bundle` stays out of Linux.

### 2. LATTE-Style LLM Taint Analysis
**Brief:** `.planning/research/fleet-wairz-next-campaigns/latte-llm-taint.md` (1,546 words, 22 citations)

- **Paper:** arXiv 2310.08275v4 (TOSEM 2025, Liu/Lyu/Zhu/Sun). 4-stage prompt (sink-id → source-id → dataflow → CWE). **No public code.**
- **Accuracy baseline (LATTE on Juliet):** CWE-78 96.5%, CWE-134 93.9%, CWE-190 62.1%, CWE-606 73.3%. Real-world on Karonte firmware dataset: 119 bugs / 37 new / 10 CVEs.
- **LLM placement:** **Option A confirmed** — MCP tool returns a prompt-string; Claude Code analyzes. Zero Anthropic SDK in backend (verified by grep). Preserves offline-capability and follows the project rule about no API keys in backend.
- **Integration shape:** single new MCP tool file `backend/app/ai/tools/taint_llm.py` (~450 LOC) + companion `list_taint_candidates` (~150 LOC) that ranks functions by imported dangerous sinks so Claude picks targets. **1-2 sessions.**
- **Market gap:** GhidraMCP / binary_ninja_mcp / pyghidra-mcp all expose decomp to LLMs but none ship a LATTE-style taint flow. Wairz could be the first open-source MCP tool to do this.
- **Risks:** hallucinated CVEs (mitigation: require quoted source lines in the report), scale (~$3/binary with candidate filter), consistency (cache in `analysis_cache`). Open question: whether Claude Opus 4.7 beats LATTE's GPT-4.0 accuracy — no published comparison exists, a finding worth publishing.

### 3. Qualcomm TEE / Trusted Application Parser
**Brief:** `.planning/research/fleet-wairz-next-campaigns/qualcomm-tee-ta.md` (1,265 words)

- **Scaffolding is 80% present.** `qualcomm_mbn.py` already captures hash/sig/cert segments + image_id. `elf_tee.py` handles `.ta_head` OP-TEE TAs but misses SHDR-wrapped form (magic `0x4F545348` at offset 0). MCLF (Kinibi) magic `TRUS` detected but no parser extracting the UUID at offset 0x18.
- **New work:** `kinibi_mclf.py` parser + `elf_tee.py` SHDR extension + `qualcomm_mbn.py` image_id enum (openpst MbnImageId 0x00-0x1F for human labels) + classifier mcRegistry path rules + new `analyze_ta_security` MCP tool.
- **arXiv 2507.08331** (July 2025) gives concrete `.mdt`/`.b0x` merge heuristics (arch at 0x04, seg-count at 0x2C/0x38) and command-handler naming patterns (`widevine_dash_cmd_handler`, `drmprov_cmd_handler`, `tzcommon_cmd_handler`, `OEMCrypto_*`). Companion repo exists at `github.com/hanhan3927/usenix2025-qualcomm-trusted-application-emulation-for-fuzzing-testing` (check license before vendoring).
- **7 new YAML families proposed** — covering Dec 2025 QC bulletin (CVE-2025-47319/25/72/73), 2020 QTEE cluster (CVE-2020-11298/11304/11284/11306), Widevine CVE-2021-0592, Kinibi.
- **Estimate:** ~500 LOC. **2 sessions.**
- **Dead ends called out:** QBDL (wrong tool despite name), full TEEGRIS parser (no public spec), pre-merge `.mdt`+`.b0x`, SHDR signature verification at scan time.

### 4. VEX + Dependency-Track Integration
**Brief:** `.planning/research/fleet-wairz-next-campaigns/vex-dependency-track.md` (1,472 words)

- **Already built:** `DependencyTrackService.push_sbom()` (62 LOC, httpx, X-Api-Key, base64, `/api/v1/bom`); `GET /sbom/export?format=cyclonedx-vex-json` builds a full CDX 1.7 VEX doc; `_map_resolution_to_vex_state / _response / _justification` helpers exist; MCP tools `export_sbom`, `set_vulnerability_vex_status`, `push_to_dependency_track` registered. `SbomVulnerability` model has every field VEX needs.
- **Actual gap:**
  1. `hbom_export._build_vulnerability()` does NOT emit `analysis.*` fields (confirmed via grep — 0 mentions).
  2. No HBOM-specific DT push endpoint or MCP tool; the existing DT push inlines a BOM builder instead of calling `build_hbom()`.
  3. CVE matcher tiers aren't fed into VEX state (recommended refinement: Tier 5 `kernel_subsystem` → `in_triage`; Tier 3 `curated_yaml` + `high` → `exploitable`).
  4. Minor: SBOM is 1.7 but HBOM is 1.6 — stay on 1.6 for DT-destined docs.
- **Estimate:** **~150-250 LOC, ONE session.**
- **Open question:** Does Dustin actually run a Dependency-Track instance? If not, VEX-as-file export still has value for CI gating and third-party sharing.

## Recommendation

### Immediate (next session, ~4-8 hours)
1. **Tier-1 security sprint** — the 4 critical intake items already on file (fuzzing shell injection, VARCHAR fix, Android unpack hardening, CWE checker session fix). Surgical, high-security-impact, zero-risk fixes.
2. **VEX polish campaign** — ship the HBOM VEX extension + Tier-aware state mapping. One session, ~200 LOC, closes the enterprise-interop story Phase 5 started.

### Next major campaign — pick one of three based on appetite

| Candidate | Best if Dustin wants... | Session count | Biggest payoff |
|-----------|-------------------------|---------------|----------------|
| **iOS IPSW** | Maximum device-class expansion (Apple is the biggest firmware RE domain Wairz doesn't touch) | 2-3 | Unlocks ALL Apple firmware analysis in one campaign |
| **LATTE LLM taint** | Frontier AI × security fusion, publishable novelty | 1-2 | First OSS MCP taint tool using Claude as the LLM; may outperform LATTE's GPT-4.0 baseline |
| **Qualcomm TEE** | Depth over breadth (sharpens existing Qualcomm strength) | 2 | Closes the highest-value Android attack surface Wairz currently shows but can't analyze |

### My synthesis vote
**iOS IPSW first, LATTE second.** Rationale:
- iOS IPSW is the natural sequel to the hw-firmware Phase 2 campaign (another whole device class unlocked with the same patterns: native parsers, classifier rules, CVE tier).
- LATTE has more uncertainty (no public code, accuracy vs Claude Opus 4.7 unknown). Better as the second campaign once Dustin has evaluated whether he wants to spend tokens on per-binary LLM analysis.
- Qualcomm TEE is excellent but narrower — schedule after iOS to keep the "another device class" momentum.

## Open Questions (need Dustin's judgment)

1. **Dependency-Track hosting:** Is there a Wairz-adjacent DT instance to push to, or is VEX purely file-export for now?
2. **iOS scope:** MVP classify-only SEP/baseband and only extract kernelcache + DSC names? Or aim for SEP-ROM analysis in the first campaign?
3. **LATTE target binaries:** Focus on firmware-specific binaries (busybox-in-firmware, vendor daemons) or broader (system binaries too)?
4. **Qualcomm TEE fuzzing:** Ship the parser-only MVP (~500 LOC, 2 sessions) or include fuzzing harness from arXiv 2507.08331 (additional 1-2 sessions)?

## Scout Briefs

- `.planning/research/fleet-wairz-next-campaigns/ios-ipsw-img4.md` — 1,317 words
- `.planning/research/fleet-wairz-next-campaigns/latte-llm-taint.md` — 1,546 words
- `.planning/research/fleet-wairz-next-campaigns/qualcomm-tee-ta.md` — 1,265 words
- `.planning/research/fleet-wairz-next-campaigns/vex-dependency-track.md` — 1,472 words
- Total: 5,600 words of implementation-ready briefs

---

```
---HANDOFF---
- Research Fleet: Wairz Next Campaigns (4 Candidates)
- Scouts: 4 across 1 wave
- Consensus: All four are technically viable; Phase 2's architectural patterns apply to each
- Surprises: VEX+DT is already 80% built in Wairz — not a campaign, just a session
- Recommendation: Security sprint → VEX polish → iOS IPSW → LATTE
- Report: .planning/research/fleet-wairz-next-campaigns/REPORT.md
---
```
