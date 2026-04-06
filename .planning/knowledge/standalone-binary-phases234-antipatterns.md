# Anti-patterns: Standalone Binary Support - Phases 2, 3, 4

> Extracted: 2026-04-06
> Campaign: .planning/campaigns/standalone-binary-phases234.md

## Failed Patterns

### 1. Assuming PyPI Availability for Research Tools
- **What was done:** Initially assumed cpu_rec could be installed via pip.
- **Failure mode:** cpu_rec is not published to PyPI. `pip install cpu_rec` fails.
- **Evidence:** Decision log: "cpu_rec installed from git (not pip)." Required `git clone` + manual install to /opt/cpu_rec in Dockerfile.
- **How to avoid:** Before adding a Python dependency, check PyPI first: `pip index versions <package>`. For research/academic tools, expect git-only distribution and plan for manual Docker installation.

### 2. Bundling Proprietary DLLs for Cross-Platform Emulation
- **What was done:** Considered bundling Windows system DLLs in the Docker image for Qiling PE emulation.
- **Failure mode:** Windows system DLLs (ntdll.dll, kernel32.dll, etc.) are copyrighted by Microsoft. Bundling them in an open-source project creates licensing liability.
- **Evidence:** Decision log: "Windows DLLs not bundled — licensing prevents bundling Windows system DLLs; users mount their own."
- **How to avoid:** Never bundle proprietary runtime dependencies in open-source containers. Document how users provide their own (bind mount, volume). Provide clear setup instructions for obtaining legal copies.
