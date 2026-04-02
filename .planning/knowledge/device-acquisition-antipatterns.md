# Anti-patterns: Device Acquisition v1

> Extracted: 2026-04-02
> Campaign: .planning/campaigns/device-acquisition.md

## Failed Patterns

### 1. Architecture design not persisted from prior session
- **What was done:** Previous session ran an Agent to research "5 approaches for device acquisition" and referenced the output in the session plan ("See .planning/knowledge/ for full architecture design"), but the actual research output was never written to disk.
- **Failure mode:** Next session had to re-run the entire architecture research because the findings only existed in a prior conversation's context. Wasted ~5 minutes of research agent time.
- **Evidence:** Session plan line 16: "See `.planning/knowledge/` for full architecture design (5 approaches evaluated, hybrid selected)" — but no such file existed.
- **How to avoid:** When an Agent produces research findings that inform future work, always persist the output to `.planning/knowledge/` or the campaign file before the session ends. Research that only lives in conversation context is lost.

### 2. Worktree path returned as "ok" instead of actual path
- **What was done:** Agents launched with `isolation: "worktree"` completed successfully but the worktree path was reported as "ok" rather than an actual filesystem path.
- **Failure mode:** Couldn't verify worktree state or merge from worktree branches. Changes appeared directly in the main working tree instead of being isolated.
- **Evidence:** Both Phase 1 and Phase 2 agents returned `worktreePath: ok` in their task notifications.
- **How to avoid:** When worktree isolation is critical (e.g., agents modifying overlapping files), verify worktree creation succeeded by checking `git worktree list` before and after. For non-overlapping work, the files ending up in the main tree was acceptable.

### 3. Frontend typecheck not verified
- **What was done:** Created 733 lines of TypeScript (DeviceAcquisitionPage.tsx) without running `npx tsc --noEmit` because node_modules wasn't installed on the machine.
- **Failure mode:** Potential type errors in the frontend code that won't be caught until the next `npm install && npx tsc` run. The agent manually verified against component signatures but this is error-prone.
- **Evidence:** Agent output: "TypeScript compilation could not be verified because npm/npx are not installed."
- **How to avoid:** If building frontend code, ensure the build toolchain is available before delegating to agents. Or: defer frontend phases to sessions where `node_modules` is installed, and do backend-only work in environments without it.
