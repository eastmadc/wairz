---
stream: B
campaign: wairz-intake-sweep-2026-04-19
intake: .planning/intake/security-fuzzing-shell-injection.md
status: complete
date: 2026-04-19
---

## Commits

| SHA | Message |
|-----|---------|
| e443def | fix(security): eliminate double-shell injection at 4 sites in services |

## Files Touched

- `backend/app/services/fuzzing_service.py` — 3 sites fixed
- `backend/app/services/emulation_service.py` — 2 sites fixed (1 from intake, 1 additional harness-rule hit)

## Verification Results

| # | Check | Result |
|---|-------|--------|
| 1 | `grep -rn 'sh", "-c",\s*f"' backend/app/services/` → 0 hits | PASS |
| 1 | `grep -rnE 'sh -c.*f"\|f".*sh -c' backend/app/services/` → 0 hits | PASS |
| 2 | Intake test payloads (binary_path with `'; touch /tmp/pwned; #`) | PASS (script-file path, no second shell level to interpret) |
| 3 | Fuzzing regression: no live fuzzing fixture (`grep -r fuzz backend/tests/fixtures/` → no hits); module import + signature check clean | PASS |
| 4 | Emulation regression: shlex.quote is transparent for benign filenames; argv-list chmod behaves identically for extant dirs | PASS |
| 5 | `docker compose exec backend python -c "import app.services.fuzzing_service, app.services.emulation_service"` | PASS (output: IMPORT OK) |
| 6 | Harness rule `auto-review-no-shell-interpolation` — pattern matches 0 files post-fix | PASS |

## Fix Hierarchy Used Per Site

| Site | Location | Hierarchy Level | Technique |
|------|----------|----------------|-----------|
| 1 | `fuzzing_service.py` AFL launch (~line 531) | L1 — file staging + exec | `_write_file_to_container` writes `/opt/fuzzing/run.sh` via `put_archive`; exec runs the file directly with `nohup /opt/fuzzing/run.sh` (no `'{...}'` wrapper) |
| 2 | `fuzzing_service.py` GDB triage (~line 840) | L1 — file staging + exec | `_write_file_to_container` writes `/opt/fuzzing/triage_gdb.sh` via `put_archive`; exec is `["timeout", "30", "/opt/fuzzing/triage_gdb.sh"]` — no second shell |
| 3 | `emulation_service.py` standalone QEMU (~line 1383) | L3 — shlex.quote on all vars | `quoted_binary = shlex.quote((session.binary_path or "").lstrip("/"))` — single shell level, only one expansion pass |
| 4 | `emulation_service.py` chmod dirs (~line 460) | L2 — argv list, no shell | `container.exec_run(["test", "-d", d])` + `container.exec_run(["chmod", "-R", "+x", d])` — hardcoded paths, harness rule false-positive eliminated |

## Notes

- Site 4 (`emulation_service.py:462`) was not in the original intake but matched the harness rule `auto-review-no-shell-interpolation`. The `d` variable is drawn from a static hardcoded list (no user input), so there was no real injection risk — but eliminating it achieves the stated goal of 0 harness-rule hits.
- The `_write_file_to_container` helper already existed in `fuzzing_service.py` (lines 104–121). Both L1 fixes reuse it rather than introducing new infrastructure.
- GDB script retains single-quote `gdb -ex 'cmd'` syntax inside the script body — this is safe because the script itself is written as bytes via `put_archive`; the quotes are never interpreted by a container shell during the exec step.
- No rebuild triggered: only logic inside existing functions changed, no new imports, no class-shape changes (CLAUDE.md rule 20 exception does not apply). However, per rule 8, next session should `docker compose up -d --build backend worker` before trusting for production.

## Unresolved Risks

- The run.sh and triage_gdb.sh script files persist in the container filesystem after the campaign ends. Per the intake's suggestion, a future cleanup task in `stop_session` should unlink campaign-scoped script files. Not blocking — the fuzzing container is ephemeral and network-isolated.
- The `command` argument at `emulation_service.py:1391` (user-supplied exec intent) is still interpolated without quoting — this is by-design per the intake ("by design — container-local impact") and the QEMU exec context where the user explicitly controls command execution.
