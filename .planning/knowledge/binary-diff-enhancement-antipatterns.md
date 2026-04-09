# Anti-patterns: Binary Diff Enhancement

> Extracted: 2026-04-08
> Campaign: .planning/campaigns/binary-diff-enhancement.md

## Failed Patterns

### 1. Campaign file phase status not updated during execution
- **What was done:** Campaign file phases and Feature Ledger all show "pending" / "not started" even though the campaign is marked `Status: completed` and work was delivered across sessions 12-14.
- **Failure mode:** Campaign file becomes unreliable as a source of truth — cannot tell what was actually built vs. what was planned.
- **Evidence:** Campaign file shows Phase 1-4 all "pending", Continuation State says "not started", but intake plan confirms completion and code exists in comparison_service.py
- **How to avoid:** When completing campaign phases (especially across multiple sessions), update the campaign file's phase status and Feature Ledger in the same commit as the code changes. The campaign file should always reflect reality.

### 2. pyelftools assumption for binary content access
- **What was done:** Initial comparison_service.py used pyelftools for binary diff, which could only compare function names and sizes — not actual content.
- **Failure mode:** Two functions with the same name and size but different code appeared identical, making the diff tool miss real changes.
- **Evidence:** Decision Log entry about choosing LIEF over pyelftools
- **How to avoid:** When building binary analysis tools, verify the library can access raw bytes (function bodies, section content), not just metadata. Test with a known-different binary pair early.
