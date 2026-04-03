# Patterns: Session 7 — Docker GID Fix, Feature Verification, Emulation Testing

> Extracted: 2026-04-03
> Source: session 7 commits (3 commits on clean-history)
> Postmortem: none

## Successful Patterns

### 1. Runtime GID detection via entrypoint script
- **Description:** Instead of requiring users to set `DOCKER_GID` in `.env` (error-prone, host-specific), added an `entrypoint.sh` that detects the actual Docker socket GID at runtime via `stat -c %g`, adjusts the container's docker group with `groupmod`, then drops to the application user via `su`.
- **Evidence:** `entrypoint.sh` commit `ae766e8`. Container now works on any host regardless of docker GID (tested: GID 145 on Raspberry Pi, default 999 on most systems).
- **Applies when:** Any container that needs host socket access where the GID varies between hosts. Runtime detection eliminates a class of "works on my machine" issues.

### 2. Autopilot audit catching wiring gaps
- **Description:** Running `/autopilot` with an Explore agent to audit feature completeness found that SecurityScanPage rendered the FirmwareSelector but never wired `selectedFirmwareId` into its `listFindings` call.
- **Evidence:** SecurityScanPage fix in commit `309cbdc`. The component was visually present but functionally disconnected.
- **Applies when:** After adding a component to multiple pages, audit all instances to verify the data flow is complete, not just the visual rendering.

### 3. Verifying Docker access end-to-end after infrastructure changes
- **Description:** After fixing the GID, verified the fix at three levels: (1) `id` command showing correct group membership, (2) `ls -la` on socket showing matching GID, (3) `docker.from_env().version()` confirming actual API access.
- **Evidence:** All three checks passed in sequence after rebuild.
- **Applies when:** Any infrastructure fix. Verify at the permission level, the access level, AND the application level. A correct permission doesn't guarantee the application can use it.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Runtime entrypoint.sh over build-time DOCKER_GID | Build-time requires user to know host GID; runtime is zero-config | Correct — works on any host without .env changes |
| Container starts as root, drops to wairz via su | Need root to run groupmod; gosu not available in image | Correct — su is always available, minimal security impact since drop happens before app starts |
| Clean up error sessions via direct DB delete | 4 stale error sessions from pre-fix attempts cluttering UI | Correct — simple cleanup, no orphaned resources |
