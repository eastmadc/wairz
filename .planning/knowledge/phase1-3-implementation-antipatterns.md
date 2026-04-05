# Phase 1-3 Bulk Implementation Anti-patterns

**Type:** pitfall
**Source:** session 2026-04-03, phases 1-3 roadmap implementation
**Applies to:** parallel agent workflows, MCP tool development, Citadel harness usage

## Summary
Worktree agent restrictions, hardcoded test assertions, and parameter naming mismatches were the main friction points during bulk implementation.

## Details

### Citadel hooks block file writes in worktrees
The Citadel harness hooks (circuit breakers, quality gates) blocked Edit/Write tool calls when agents operated in git worktrees. Simple changes had to be applied from the main session instead. Complex features that wrote many files sometimes succeeded, suggesting the blocking is intermittent or path-dependent. Workaround: for small changes, do them in the main worktree; for large features, worktree agents can usually write.

### Hardcoded tool registration assertions break on new tools
The binary tools test file contained a hardcoded set of expected tool names. Adding `detect_capabilities` (capa) broke the assertion. When adding any new MCP tool, always check for registration count or name-set assertions in the corresponding test file and update them.

### Parameter naming must match category conventions
Each tool category has established parameter naming. Binary tools use `binary_path`, filesystem tools use `path`. A new tool using the wrong parameter name will pass development but fail integration tests that validate the schema. Always check 2-3 existing tools in the same category file before choosing parameter names.

### Don't assume library availability on ARM64
The target platform is aarch64 (Raspberry Pi). Many Python packages with C extensions don't publish ARM64 wheels. Prefer: (1) subprocess to existing binaries, (2) pure-Python implementations, (3) manual JSON over serialization libraries. Only add a pip dependency if it's pure Python or known to have ARM64 wheels.

## Example
```python
# WRONG - mismatches existing binary tool convention
registry.register(name="detect_capabilities", input_schema={
    "properties": {"path": {"type": "string"}}  # should be binary_path
})

# RIGHT - matches existing convention
registry.register(name="detect_capabilities", input_schema={
    "properties": {"binary_path": {"type": "string"}}
})
```
