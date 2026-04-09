# Session 21 Reusable Patterns

**Type:** pattern
**Source:** session-21
**Applies to:** firmware static analysis scanners, regex-based detection tools, autopilot sessions

## 3-Phase Scanning for Static Detection

When scanning firmware for patterns (network dependencies, update mechanisms, credentials, etc.), use a 3-phase approach to control false positive rates:

1. **Phase 1 - Known config files** (high confidence): Scan specific paths like `etc/fstab`, `etc/exports`, `etc/mosquitto/mosquitto.conf`. Findings here are almost always real.
2. **Phase 2 - Init scripts and crontabs** (medium confidence): Scan `etc/init.d/`, `etc/cron*`, systemd units. These are operational files where matches are likely intentional.
3. **Phase 3 - Broad sweep** (lower confidence): Walk remaining text files. Apply stricter pattern scoping here to avoid noise.

This was used successfully in `detect_network_dependencies` and implicitly in `update_mechanism_service.py` (which scans known binary paths first, then config paths, then broad text files).

## Scope Regex Patterns to File Context

Patterns like rsyslog `@@host` or MQTT `listener 1883` are only meaningful in their own config files. Gate pattern matching on the filename:

```python
if "rsyslog" in desc.lower() and "rsyslog" not in basename and "syslog" not in basename:
    continue
```

This eliminates entire classes of false positives cheaply.

## Parallel Agent Builds

Session 21 ran two build agents simultaneously (network dependency mapping + firmware update detection). This works well when:
- Features touch different files (different services, different tool registrations)
- Both integrate into the same pipeline but at different insertion points
- Each agent handles its own Docker rebuild and smoke test

The key enabler is that each feature was a self-contained plan file in `.planning/intake/`.

## Autopilot Intake Triage

Before building anything, scan all intake items and classify them as completed/pending/blocked. Session 21 found 8 of 15 items were already done, saving significant wasted effort. Pattern: read existing code first, grep for feature signatures, then only build what is genuinely missing.

## Dataclass-per-Service for Structured Detection Output

The `UpdateMechanism` dataclass pattern (used in `update_mechanism_service.py`) works well for detection services: define a structured output type, have each detector return instances, then format to text at the boundary. This keeps detection logic testable and the output format changeable independently.
