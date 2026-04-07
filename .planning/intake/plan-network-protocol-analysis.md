# Plan: Network Protocol Analysis (5.4)

**Priority:** Medium | **Effort:** Large (~13h) | **Status:** pending
**Route:** `/citadel:archon` (3 phases: capture, analysis, MCP+frontend)
**Depends on:** System emulation (5.1) -- COMPLETED

## Goal

Capture pcap from emulated firmware, analyze protocols, fingerprint services, detect insecure protocols. Provide structured protocol analysis results via MCP tools and frontend display.

## Current State (verified 2026-04-06)

- `capture_network_traffic()` in `system_emulation_service.py` runs tcpdump -> plain text output
- nmap in FirmAE shim provides basic service discovery (port + service name)
- `discovered_services` JSONB stored in EmulationSession
- tcpdump installed in sidecar container
- No pcap file output, no protocol dissection, no structured analysis
- No insecure protocol detection (plaintext telnet, unencrypted MQTT, HTTP without TLS, etc.)

## Phase 1: Pcap Capture Infrastructure (~3h)

**Goal:** Modify tcpdump to write pcap files, store them, and make them downloadable.

**Implementation approach:**
1. Modify `capture_network_traffic()` in `system_emulation_service.py`:
   - Run `tcpdump -i any -w /tmp/capture_{session_id}.pcap -c 10000` (cap at 10K packets)
   - Add timeout: `-G 300` (5 min max capture duration)
   - Capture filter: exclude SSH management traffic (`not port 22`)
   - Copy pcap from sidecar container to host storage after capture
2. New REST endpoint: `GET /api/v1/projects/{pid}/emulation/{sid}/pcap`
   - Returns pcap file as binary download
   - Stores pcap path in EmulationSession model
3. Add `pcap_path: str | None` field to EmulationSession model
4. Add Alembic migration for new field

**Storage:** Save pcap files alongside firmware storage: `{STORAGE_ROOT}/projects/{pid}/pcaps/{session_id}.pcap`

## Phase 2: Protocol Analysis with Scapy (~6h)

**Goal:** Parse captured pcap, extract protocol breakdown, detect insecure protocols.

**New service: `pcap_analysis_service.py`**

**Libraries:**
- `scapy>=2.6` -- primary packet analysis library
  - Pros: Pure Python, rich protocol support (200+ protocols), IoT protocols (MQTT, CoAP built-in), active development
  - Cons: Memory-heavy for large pcaps (>100MB), slower than tshark for bulk parsing
  - Mitigation: Cap capture at 10K packets (~5-10MB), use `PcapReader` iterator (not `rdpcap` which loads all into memory)
- **NOT pyshark** -- pyshark requires tshark binary in the container, adds complexity. Scapy handles everything we need natively.
- **NOT dpkt** -- less protocol coverage, less active development than Scapy

**Core analysis functions:**

```python
class PcapAnalysisService:
    async def analyze_pcap(self, pcap_path: str) -> PcapAnalysis:
        """Full analysis pipeline."""
        
    def _extract_protocol_breakdown(self, packets) -> dict[str, int]:
        """Count packets per protocol layer (IP, TCP, UDP, HTTP, DNS, MQTT, etc.)"""
        
    def _extract_conversations(self, packets) -> list[Conversation]:
        """Unique src:port <-> dst:port conversations with packet/byte counts."""
        
    def _detect_insecure_protocols(self, packets) -> list[InsecureProtocolFinding]:
        """Flag plaintext protocols that should be encrypted."""
        
    def _extract_dns_queries(self, packets) -> list[DnsQuery]:
        """All DNS lookups (reveals what services firmware contacts)."""
        
    def _fingerprint_services(self, packets) -> list[ServiceFingerprint]:
        """Deep service fingerprinting beyond nmap's basic detection."""
        
    def _extract_tls_metadata(self, packets) -> list[TlsInfo]:
        """TLS version, cipher suites, certificate info, JA3 hashes."""
```

**Insecure protocol detection rules:**

| Protocol | Port | Finding | Severity |
|----------|------|---------|----------|
| Telnet | 23 | Plaintext remote shell | Critical |
| FTP | 21 | Plaintext file transfer (credentials exposed) | High |
| HTTP (no TLS) | 80 | Unencrypted web traffic | Medium |
| MQTT (no TLS) | 1883 | Unencrypted IoT messaging | High |
| CoAP (no DTLS) | 5683 | Unencrypted IoT constrained protocol | Medium |
| TFTP | 69 | Plaintext firmware update channel | Critical |
| UPnP/SSDP | 1900 | Network discovery without authentication | Medium |
| SNMPv1/v2c | 161 | Community string in plaintext | High |
| DNS (no DoT/DoH) | 53 | Unencrypted DNS queries | Low |
| Syslog (UDP) | 514 | Unencrypted log shipping | Medium |
| NTP (unauthenticated) | 123 | Potential NTP amplification | Low |

**TLS analysis:**
- Detect TLS 1.0/1.1 (deprecated) -- flag as insecure
- Extract cipher suites, flag weak ones (RC4, DES, export ciphers)
- Extract server certificate (CN, issuer, expiry, self-signed detection)
- Compute JA3/JA3S fingerprints for client/server TLS identification

**IoT-specific protocol detection (using Scapy layers):**
- `scapy.contrib.mqtt` -- MQTT packet parsing (connect, publish, subscribe)
- `scapy.contrib.coap` -- CoAP request/response parsing
- DNS-SD / mDNS -- service discovery announcements
- UPnP/SSDP -- device discovery

## Phase 3: MCP Tools + Frontend (~4h)

**New MCP tools in `tools/network.py`:**

1. `analyze_network_traffic` -- full pcap analysis (protocol breakdown, conversations, insecure protocols)
   - Input: `session_id` (uses stored pcap from emulation session)
   - Output: structured analysis summary with findings
2. `get_protocol_breakdown` -- quick protocol statistics
   - Input: `session_id`
   - Output: protocol -> packet count mapping
3. `identify_insecure_protocols` -- security-focused analysis
   - Input: `session_id`
   - Output: list of insecure protocol findings with severity and remediation
4. `get_dns_queries` -- DNS query extraction
   - Input: `session_id`
   - Output: domain names firmware resolved (reveals C2, update servers, telemetry endpoints)
5. `capture_network_traffic` -- start/stop pcap capture on running emulation
   - Input: `session_id`, `duration_seconds` (default 60, max 300)
   - Output: capture status + packet count

**Frontend additions to EmulationPage.tsx:**

1. "Network Traffic" tab on EmulationPage:
   - Protocol breakdown pie/bar chart (use existing chart library or simple HTML table)
   - Conversation table: src -> dst, protocol, packets, bytes
   - Insecure protocol findings (styled like security findings elsewhere)
2. "Capture" button to start pcap capture on running emulation
3. "Download PCAP" button to download raw pcap for Wireshark analysis
4. DNS query list with domain names and resolved IPs

## Key Files

- `backend/app/services/system_emulation_service.py` (modify capture_network_traffic)
- New: `backend/app/services/pcap_analysis_service.py` (~400 lines)
- New: `backend/app/ai/tools/network.py` (~200 lines)
- `backend/app/ai/__init__.py` (register network tools)
- `backend/app/models/emulation.py` (add pcap_path field)
- `backend/app/routers/emulation.py` (add pcap download endpoint)
- `frontend/src/pages/EmulationPage.tsx` (add Network Traffic tab)
- `backend/pyproject.toml` (add scapy dependency)

## Related Tools (reference, not dependencies)

- **FATT** (fingerprintAllTheThings) -- pyshark-based JA3/HASSH fingerprinting. Could use their fingerprint databases as reference but too heavy as a dependency.
- **Cotopaxi** (Samsung) -- IoT protocol security testing toolkit supporting 13 protocols. Active testing tool, not passive analysis. Could be a future integration for active security scanning.
- **Zeek** -- full network security monitor. Too heavy for our use case (requires dedicated process), but its protocol logs format is well-known. Consider as a future alternative if Scapy performance is insufficient.

## Acceptance Criteria

- [ ] Pcap files captured from emulated firmware and stored on disk
- [ ] Scapy parses pcap and produces protocol breakdown (protocol -> packet count)
- [ ] Insecure protocol detection flags telnet, plaintext MQTT, FTP, etc.
- [ ] DNS queries extracted and displayed (reveals firmware network behavior)
- [ ] TLS version/cipher analysis identifies deprecated TLS 1.0/1.1
- [ ] 5 MCP tools registered and functional
- [ ] EmulationPage shows Network Traffic tab with analysis results
- [ ] Raw pcap downloadable for external Wireshark analysis
- [ ] Memory-safe: pcap capped at 10K packets, Scapy PcapReader used (not rdpcap)
