"""VulHunt binary vulnerability scanning AI tools.

Integrates with the VulHunt Community Edition container for deep binary
vulnerability detection. VulHunt performs semantic analysis (dataflow,
control flow, decompilation) and rule-based vulnerability detection on
ELF and PE32+ binaries — particularly strong for UEFI firmware modules.

VulHunt runs in a separate Docker container (ghcr.io/vulhunt-re/vulhunt).
Communication is via `docker exec` CLI invocation with JSON output.
"""

import asyncio
import json
import logging
import os
import shutil

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.config import get_settings

logger = logging.getLogger(__name__)


def register_vulhunt_tools(registry: ToolRegistry) -> None:
    """Register VulHunt binary vulnerability scanning tools."""

    registry.register(
        name="vulhunt_scan_binary",
        description=(
            "Scan a single binary with VulHunt for vulnerabilities. "
            "Performs deep static analysis: dataflow tracking, pattern "
            "matching, and rule-based detection. Returns structured "
            "findings with severity, description, and location. "
            "Supports ELF (Linux) and PE32+ (UEFI) binaries."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
            },
            "required": ["path"],
        },
        handler=_handle_vulhunt_scan_binary,
    )

    registry.register(
        name="vulhunt_scan_firmware",
        description=(
            "Scan all ELF and PE32+ binaries in the extracted firmware "
            "with VulHunt. Automatically discovers binaries in the "
            "filesystem, runs VulHunt on each, and aggregates findings. "
            "For UEFI firmware, scans DXE/PEI/SMM modules from the "
            "UEFIExtract output."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_binaries": {
                    "type": "integer",
                    "description": "Maximum number of binaries to scan (default 50)",
                    "default": 50,
                },
                "min_size": {
                    "type": "integer",
                    "description": "Minimum binary size in bytes to scan (default 4096)",
                    "default": 4096,
                },
            },
        },
        handler=_handle_vulhunt_scan_firmware,
    )

    registry.register(
        name="vulhunt_check_available",
        description=(
            "Check if the VulHunt container is running and available. "
            "Returns version info and status."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        handler=_handle_vulhunt_check_available,
    )


# ── Helpers ───────────────────────────────────────────────────────────


async def _run_vulhunt(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run vulhunt-ce inside the Docker container."""
    settings = get_settings()
    container = settings.vulhunt_container

    cmd = ["docker", "exec", container, "vulhunt-ce"] + args
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"VulHunt timed out after {timeout}s"

    return (
        proc.returncode or 0,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


def _is_elf(path: str) -> bool:
    """Check if a file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_pe(path: str) -> bool:
    """Check if a file is a PE32/PE32+ binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return False
            pe_offset = int.from_bytes(pe_offset_bytes, "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _find_binaries(root: str, max_count: int = 50, min_size: int = 4096) -> list[str]:
    """Find ELF and PE32+ binaries in a directory tree."""
    binaries: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if len(binaries) >= max_count:
                return binaries
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) < min_size:
                    continue
                if not os.path.isfile(fpath):
                    continue
                if _is_elf(fpath) or _is_pe(fpath):
                    binaries.append(fpath)
            except OSError:
                continue
    return binaries


def _parse_vulhunt_json(output: str) -> list[dict]:
    """Parse VulHunt JSON output into a list of findings."""
    findings = []
    # VulHunt can output JSONL (one JSON object per line) or a single JSON array
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                findings.extend(obj)
            elif isinstance(obj, dict):
                findings.append(obj)
        except json.JSONDecodeError:
            continue
    return findings


def _format_findings(findings: list[dict], binary_name: str) -> str:
    """Format VulHunt findings as readable text."""
    if not findings:
        return f"  {binary_name}: No vulnerabilities found."

    lines = [f"  {binary_name}: {len(findings)} finding(s)"]
    for f in findings[:20]:  # Limit output
        severity = f.get("severity", "unknown")
        rule_id = f.get("rule_id", f.get("id", "unknown"))
        desc = f.get("description", f.get("message", ""))
        location = f.get("location", {})
        func = location.get("function", "")
        addr = location.get("address", "")

        loc_str = ""
        if func:
            loc_str = f" in {func}"
        if addr:
            loc_str += f" @ {addr}"

        lines.append(f"    [{severity:8s}] {rule_id}{loc_str}")
        if desc:
            lines.append(f"              {desc[:120]}")

    if len(findings) > 20:
        lines.append(f"    ... and {len(findings) - 20} more")

    return "\n".join(lines)


# ── Handlers ──────────────────────────────────────────────────────────


async def _handle_vulhunt_check_available(
    input: dict, context: ToolContext
) -> str:
    code, stdout, stderr = await _run_vulhunt(["--version"], timeout=30)
    if code == -1:
        return (
            "VulHunt container is not running or not available.\n"
            "Start it with: docker compose up -d vulhunt\n"
            f"Error: {stderr}"
        )
    if code != 0:
        # Try alternative — docker exec might fail if container doesn't exist
        return (
            f"VulHunt returned exit code {code}.\n"
            f"stdout: {stdout[:200]}\n"
            f"stderr: {stderr[:200]}\n"
            "The vulhunt container may not be running. "
            "Start it with: docker compose up -d vulhunt"
        )
    return f"VulHunt is available.\n{stdout.strip()}"


async def _handle_vulhunt_scan_binary(
    input: dict, context: ToolContext
) -> str:
    path = input.get("path", "")
    if not path:
        return "Error: 'path' is required."

    # Resolve to real filesystem path
    real_path = context.resolve_path(path)
    if not os.path.isfile(real_path):
        return f"File not found: {path}"

    if not (_is_elf(real_path) or _is_pe(real_path)):
        return f"{path} is not an ELF or PE32+ binary."

    # VulHunt runs in its own container with firmware_data mounted at /data/firmware
    # The real_path on the backend container maps to the same path via shared volume
    settings = get_settings()
    code, stdout, stderr = await _run_vulhunt(
        ["scan", real_path, "--pretty", "--stream"],
        timeout=settings.vulhunt_timeout,
    )

    if code == -1:
        return f"VulHunt is not available. Start with: docker compose up -d vulhunt\nError: {stderr}"

    findings = _parse_vulhunt_json(stdout)
    binary_name = os.path.basename(real_path)

    if not findings and code != 0:
        return (
            f"VulHunt scan failed (exit code {code}).\n"
            f"stderr: {stderr[:500]}\n"
            f"stdout: {stdout[:500]}"
        )

    return _format_findings(findings, binary_name)


async def _handle_vulhunt_scan_firmware(
    input: dict, context: ToolContext
) -> str:
    max_binaries = input.get("max_binaries", 50)
    min_size = input.get("min_size", 4096)

    root = context.extracted_path
    if not root:
        return "No extracted firmware available."

    # Find all scannable binaries
    binaries = _find_binaries(root, max_count=max_binaries, min_size=min_size)

    # Also check extraction_dir for UEFI .dump/ body.bin files
    if context.extraction_dir:
        for dirpath, _dirs, files in os.walk(context.extraction_dir):
            if len(binaries) >= max_binaries:
                break
            if "body.bin" in files:
                body = os.path.join(dirpath, "body.bin")
                try:
                    if os.path.getsize(body) >= min_size and (
                        _is_elf(body) or _is_pe(body)
                    ):
                        binaries.append(body)
                except OSError:
                    pass

    if not binaries:
        return "No ELF or PE32+ binaries found in the firmware."

    # Check VulHunt availability first
    code, _, stderr = await _run_vulhunt(["--version"], timeout=15)
    if code != 0 and code != -1:
        pass  # Version might not be a supported subcommand
    if code == -1:
        return (
            f"Found {len(binaries)} binaries but VulHunt is not available.\n"
            "Start with: docker compose up -d vulhunt"
        )

    settings = get_settings()
    results: list[str] = []
    total_findings = 0

    for binary_path in binaries:
        binary_name = os.path.relpath(binary_path, root)
        code, stdout, stderr = await _run_vulhunt(
            ["scan", binary_path, "--stream"],
            timeout=settings.vulhunt_timeout,
        )
        findings = _parse_vulhunt_json(stdout)
        total_findings += len(findings)
        if findings:
            results.append(_format_findings(findings, binary_name))

    header = (
        f"VulHunt Firmware Scan: {len(binaries)} binaries scanned, "
        f"{total_findings} finding(s)\n"
        f"{'=' * 60}"
    )

    if not results:
        return header + "\n\nNo vulnerabilities found in any binary."

    return header + "\n\n" + "\n\n".join(results)
