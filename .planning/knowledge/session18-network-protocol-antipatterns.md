# Anti-patterns: Network Protocol Analysis Campaign

> Extracted: 2026-04-08
> Campaign: .planning/campaigns/network-protocol-analysis.md

## Failed Patterns

### 1. Git Stash Checkpoint With Dirty Untracked Files
- **What was done:** Archon created a checkpoint via `git stash push --include-untracked` before Phase 1. When trying to pop it back, it conflicted with files that already existed in the working tree (untracked files from prior sessions that hadn't been committed).
- **Failure mode:** `git stash pop` failed repeatedly with "Your local changes would be overwritten" and "already exists, no checkout" errors. Required multiple rounds of `git checkout` + retry before giving up and dropping the stash.
- **Evidence:** Session telemetry — 4 failed stash pop attempts, eventual `git stash drop`
- **How to avoid:** When the working tree has many uncommitted/untracked files from prior sessions, `git stash` checkpoints don't work cleanly. Options: (a) commit everything first, (b) skip the checkpoint when working tree is dirty, (c) use a worktree-based checkpoint instead of stash. The simplest fix: log `checkpoint-phase-N: none` and skip the stash when `git status --porcelain` shows > 20 uncommitted files.

### 2. Attempting Docker cp via SDK get_archive Before Verifying File Exists
- **What was done:** Initial implementation assumed the pcap file would always exist after tcpdump ran. If tcpdump captured zero packets (no traffic), the file might not be created.
- **Failure mode:** `docker.errors.NotFound` when calling `container.get_archive("/tmp/capture.pcap")` on an empty capture
- **Evidence:** Phase 1 implementation includes explicit `docker.errors.NotFound` handling with a descriptive error message
- **How to avoid:** Always wrap `container.get_archive()` in a try/except for `docker.errors.NotFound`. The sidecar container is not guaranteed to produce the expected file. Add a defensive check or pre-run `ls` in the container before attempting extraction.

## Notes

This was a clean campaign with no circuit breaker activations, no phase rework, and no quality gate failures. The main friction was the stash checkpoint mechanism interacting poorly with a dirty working tree from accumulated prior-session changes.
