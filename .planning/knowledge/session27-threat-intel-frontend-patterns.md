# Patterns: Session 27 — Threat Intel Frontend + Intake Cleanup

> Extracted: 2026-04-10
> Commit: d86adad on clean-history
> Work: ThreatIntelTab component, intake queue archive, FindingSource expansion

## Successful Patterns

### 1. Expand union types AND all Record<UnionType, ...> maps together
- **Description:** When adding `abusech_scan` and `known_good_scan` to the `FindingSource` union type, TypeScript correctly caught that `FindingDetail.tsx` and `FindingsList.tsx` both had `Record<FindingSource, ...>` maps that needed updating. The build failed on the first try because of this, but the error messages pinpointed exactly which files needed changes.
- **Evidence:** Docker build failed with TS2739 citing missing properties. Fixed in one pass after reading the two files.
- **Applies when:** Expanding any union type that's used as a Record key elsewhere in the frontend.

### 2. Use Explore agent for thorough frontend research before building
- **Description:** Spawned an Explore agent to map the SecurityScanPage structure, backend response schemas, API client patterns, and existing tab component patterns before writing any code. The agent returned exact field names, response types, and UI patterns. This meant the ThreatIntelTab was written correctly on the first attempt (250 lines, no logic errors).
- **Evidence:** ThreatIntelTab.tsx created in one shot, matched existing patterns exactly.
- **Applies when:** Building any new frontend feature that needs to integrate with existing page structure and backend APIs.

### 3. Extract tab content into separate component files
- **Description:** Created ThreatIntelTab as a standalone component (like AttackSurfaceTab and CraChecklistTab) rather than inlining the content in SecurityScanPage. This kept SecurityScanPage manageable and follows the established pattern.
- **Evidence:** SecurityScanPage only needed 3 small edits (import, tab button, content slot) rather than 250+ inline lines.
- **Applies when:** Adding any new tab to a page that already has extracted tab components.

### 4. Archive completed plans rather than deleting them
- **Description:** Moved 14 completed plan files to `.planning/archive/` instead of deleting. Git tracks the rename cleanly (shows as rename, not delete+add), and the plans remain accessible for reference.
- **Evidence:** Git diff shows `rename .planning/{intake => archive}/plan-*.md` entries.
- **Applies when:** Cleaning up completed work items from any queue directory.

### 5. Verify implementation exists before trusting plan status markers
- **Description:** Two plans (CRA compliance, frontend gaps F4) had no explicit "completed" status marker despite being fully built. Verified by checking for the actual service file (833 lines) and spec files (9 E2E specs). Updated status markers only after verifying the code exists.
- **Evidence:** `grep` for CRA service found `cra_compliance_service.py`, `glob` found 9 `.spec.ts` files.
- **Applies when:** Auditing intake queue or any status-tracked plan files.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Put Threat Intel tab between Attack Surface and CRA | Logical grouping: scanning tools before compliance | Clean tab order |
| Use `variant="outline"` for CIRCL button | Visual distinction: CIRCL is supplementary (known-good) vs abuse.ch (threat detection) | Clear primary/secondary action hierarchy |
| Show known-good table inline with pagination | Avoid modal for list data, show first 20 with "show all" toggle | Low friction for analysts reviewing results |
| Disable both scan buttons during any scan | Prevent concurrent external API calls that share rate limits | Clean UX, avoids backend conflicts |
| Hide main findings list for threat-intel tab | ThreatIntelTab has its own findings display with correct source filter | No duplicate findings sections |
