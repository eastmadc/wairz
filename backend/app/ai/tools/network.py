"""Network protocol analysis tools for analyzing captured pcap files."""

import asyncio
from uuid import UUID

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.emulation_session import EmulationSession
from app.services.pcap_analysis_service import PcapAnalysisService


def register_network_tools(registry: ToolRegistry) -> None:
    """Register network analysis MCP tools."""

    registry.register(
        name="analyze_network_traffic",
        description=(
            "Run full protocol analysis on a captured pcap file from an emulation session. "
            "Returns protocol breakdown, conversations, insecure protocol findings, "
            "DNS queries, and TLS metadata. Run capture_network_traffic first to create a pcap."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The system emulation session ID that has a captured pcap",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_analyze_network_traffic,
    )

    registry.register(
        name="get_protocol_breakdown",
        description=(
            "Get a quick protocol breakdown from a captured pcap. "
            "Shows which protocols are in use and their packet counts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The system emulation session ID",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_get_protocol_breakdown,
    )

    registry.register(
        name="identify_insecure_protocols",
        description=(
            "Scan a captured pcap for insecure protocols (Telnet, FTP, plaintext MQTT, "
            "SNMPv1/v2c, HTTP without TLS, etc.). Returns security findings with severity levels. "
            "Useful for firmware security assessments."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The system emulation session ID",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_identify_insecure_protocols,
    )

    registry.register(
        name="get_dns_queries",
        description=(
            "Extract DNS queries from a captured pcap. Reveals what domains the firmware "
            "contacts -- C2 servers, update endpoints, telemetry hosts, NTP servers, etc."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The system emulation session ID",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_get_dns_queries,
    )

    registry.register(
        name="get_network_conversations",
        description=(
            "List the top network conversations from a captured pcap. Shows source and "
            "destination endpoints with protocol, packet count, and byte count."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The system emulation session ID",
                },
            },
            "required": ["session_id"],
        },
        handler=_handle_get_network_conversations,
    )


# ── Helpers ────────────────────────────────────────────────────────


async def _load_pcap_analysis(input: dict, context: ToolContext):
    """Shared helper: validate session, load pcap, run analysis.

    Returns (analysis, None) on success or (None, error_string) on failure.
    """
    session_id = input.get("session_id")
    if not session_id:
        return None, "Error: session_id is required."

    result = await context.db.execute(
        select(EmulationSession).where(EmulationSession.id == UUID(session_id))
    )
    session = result.scalar_one_or_none()
    if not session:
        return None, f"Error: Session {session_id} not found."
    if not session.pcap_path:
        return None, "Error: No pcap capture available. Run capture_network_traffic first."

    loop = asyncio.get_running_loop()
    svc = PcapAnalysisService()
    try:
        analysis = await loop.run_in_executor(None, svc.analyze_pcap, session.pcap_path)
    except Exception as exc:
        return None, f"Error analyzing pcap: {exc}"

    return analysis, None


# ── Handlers ───────────────────────────────────────────────────────


async def _handle_analyze_network_traffic(input: dict, context: ToolContext) -> str:
    """Full network traffic analysis."""
    analysis, err = await _load_pcap_analysis(input, context)
    if err:
        return err

    lines = [f"=== Network Traffic Analysis ({analysis.total_packets} packets) ===\n"]

    # Protocol breakdown
    lines.append("## Protocol Breakdown")
    for proto, count in sorted(
        analysis.protocol_breakdown.items(), key=lambda x: -x[1]
    ):
        pct = (count / analysis.total_packets * 100) if analysis.total_packets else 0
        lines.append(f"  {proto}: {count} packets ({pct:.1f}%)")

    # Insecure findings
    if analysis.insecure_findings:
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        lines.append("\n## Insecure Protocols Detected")
        for f in sorted(
            analysis.insecure_findings,
            key=lambda x: severity_order.index(x.severity)
            if x.severity in severity_order
            else 99,
        ):
            lines.append(
                f"  [{f.severity}] {f.protocol} (port {f.port}): {f.description}"
            )
            lines.append(f"    Evidence: {f.evidence}")
    else:
        lines.append("\n## Insecure Protocols Detected")
        lines.append("  None found.")

    # DNS queries
    if analysis.dns_queries:
        lines.append("\n## DNS Queries")
        for q in analysis.dns_queries:
            ips = ", ".join(q.resolved_ips) if q.resolved_ips else "unresolved"
            lines.append(f"  {q.domain} ({q.query_type}) -> {ips}")
    else:
        lines.append("\n## DNS Queries")
        lines.append("  None observed.")

    # Top conversations
    if analysis.conversations:
        lines.append("\n## Top Conversations")
        for c in analysis.conversations[:20]:
            lines.append(
                f"  {c.src}:{c.src_port} <-> {c.dst}:{c.dst_port} "
                f"({c.protocol}) -- {c.packet_count} pkts, {c.byte_count} bytes"
            )

    # TLS info
    if analysis.tls_info:
        lines.append("\n## TLS Connections")
        for t in analysis.tls_info:
            lines.append(f"  {t.server}:{t.port} -- {t.version}")
            if t.cipher_suites:
                lines.append(f"    Ciphers: {', '.join(t.cipher_suites[:5])}")

    return "\n".join(lines)


async def _handle_get_protocol_breakdown(input: dict, context: ToolContext) -> str:
    """Quick protocol breakdown."""
    analysis, err = await _load_pcap_analysis(input, context)
    if err:
        return err

    lines = [f"=== Protocol Breakdown ({analysis.total_packets} packets) ===\n"]
    for proto, count in sorted(
        analysis.protocol_breakdown.items(), key=lambda x: -x[1]
    ):
        pct = (count / analysis.total_packets * 100) if analysis.total_packets else 0
        bar = "#" * int(pct / 2)
        lines.append(f"  {proto:20s} {count:6d} ({pct:5.1f}%) {bar}")

    return "\n".join(lines)


async def _handle_identify_insecure_protocols(
    input: dict, context: ToolContext
) -> str:
    """Scan for insecure protocols."""
    analysis, err = await _load_pcap_analysis(input, context)
    if err:
        return err

    if not analysis.insecure_findings:
        return (
            f"No insecure protocols detected in {analysis.total_packets} packets.\n"
            "This is a good sign, but note that encrypted traffic may hide "
            "insecure inner protocols."
        )

    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    findings = sorted(
        analysis.insecure_findings,
        key=lambda x: severity_order.index(x.severity)
        if x.severity in severity_order
        else 99,
    )

    lines = [
        f"=== Insecure Protocol Findings ({len(findings)} issues) ===\n"
    ]

    for f in findings:
        lines.append(f"[{f.severity}] {f.protocol}")
        lines.append(f"  Port: {f.port}")
        lines.append(f"  Description: {f.description}")
        lines.append(f"  Evidence: {f.evidence}")
        lines.append(f"  Packets: {f.packet_count}")
        lines.append("")

    # Summary
    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    summary_parts = [f"{count} {sev}" for sev, count in by_severity.items()]
    lines.append(f"Summary: {', '.join(summary_parts)}")

    return "\n".join(lines)


async def _handle_get_dns_queries(input: dict, context: ToolContext) -> str:
    """Extract DNS queries from pcap."""
    analysis, err = await _load_pcap_analysis(input, context)
    if err:
        return err

    if not analysis.dns_queries:
        return (
            f"No DNS queries found in {analysis.total_packets} packets.\n"
            "The firmware may use hardcoded IPs, a local DNS cache, "
            "or DNS-over-HTTPS."
        )

    lines = [f"=== DNS Queries ({len(analysis.dns_queries)} unique domains) ===\n"]

    for q in analysis.dns_queries:
        ips = ", ".join(q.resolved_ips) if q.resolved_ips else "unresolved"
        lines.append(f"  {q.domain}")
        lines.append(f"    Type: {q.query_type}")
        lines.append(f"    Resolved: {ips}")
        lines.append("")

    return "\n".join(lines)


async def _handle_get_network_conversations(
    input: dict, context: ToolContext
) -> str:
    """List top network conversations."""
    analysis, err = await _load_pcap_analysis(input, context)
    if err:
        return err

    if not analysis.conversations:
        return f"No TCP/UDP conversations found in {analysis.total_packets} packets."

    lines = [
        f"=== Network Conversations (top {min(len(analysis.conversations), 30)}"
        f" of {len(analysis.conversations)}) ===\n"
    ]

    lines.append(
        f"  {'Source':>21s}   {'Destination':>21s}  {'Proto':>5s}  "
        f"{'Packets':>7s}  {'Bytes':>10s}"
    )
    lines.append("  " + "-" * 75)

    for c in analysis.conversations[:30]:
        src = f"{c.src}:{c.src_port}"
        dst = f"{c.dst}:{c.dst_port}"
        lines.append(
            f"  {src:>21s}   {dst:>21s}  {c.protocol:>5s}  "
            f"{c.packet_count:>7d}  {c.byte_count:>10d}"
        )

    return "\n".join(lines)
