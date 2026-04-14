# Anti-patterns: Comparison Export Feature (Session 37)

> Extracted: 2026-04-14
> Campaign: none (in-session feature addition)

## Failed Patterns

No anti-patterns extracted — feature was implemented cleanly in a single pass.

Note: The initial research considered adding a backend `/compare/export` endpoint, but this was correctly rejected during implementation when it became clear the data was already in browser state. This saved unnecessary backend work.
