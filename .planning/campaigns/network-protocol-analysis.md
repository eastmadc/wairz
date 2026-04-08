---
Status: completed
Direction: Capture pcap from emulated firmware, analyze protocols with Scapy, detect insecure protocols, expose via MCP tools + frontend
Estimated Sessions: 2-3
Actual Sessions: 1
Type: build
---

# Campaign: Network Protocol Analysis

## Direction

Add deep network protocol analysis to wairz: binary pcap capture from FirmAE
emulation, Scapy-based protocol dissection (200+ protocols including IoT),
insecure protocol detection, DNS/TLS analysis, and a frontend Network Traffic
tab with pcap download. Depends on system emulation (completed).

## Current State (verified 2026-04-07)

- `capture_network_traffic()` in `system_emulation_service.py:531-579` runs tcpdump → plain text output
- FirmAE sidecar has tcpdump, nmap, socat, iproute2 installed
- Shim `/ports` endpoint does nmap on 14 hardcoded ports, returns basic service info
- `discovered_services` JSONB stored in EmulationSession model
- REST endpoint `POST .../system/{sid}/capture` returns raw tcpdump text
- MCP tool `capture_network_traffic` wraps the same tcpdump text capture
- **No binary pcap files**, no protocol dissection, no Scapy, no insecure protocol detection
- **No pcap_path column** on EmulationSession model
- **No Network Traffic tab** on EmulationPage frontend

## Phases

| # | Type | Description | Status |
|---|------|-------------|--------|
| 1 | build | Pcap capture infrastructure — binary pcap files, storage, download endpoint, DB migration | complete |
| 2 | build | Scapy protocol analysis service — protocol breakdown, insecure detection, DNS, TLS, conversations | complete |
| 3 | build | MCP tools (5) + REST endpoints + frontend Network Traffic tab | complete |

## Phase End Conditions

| Phase | Condition | Type |
|-------|-----------|------|
| 1 | `capture_network_traffic()` writes .pcap file to disk | command_passes |
| 1 | `GET .../emulation/system/{sid}/pcap` returns binary pcap download | command_passes |
| 1 | EmulationSession model has `pcap_path` column (migration applied) | command_passes |
| 2 | `PcapAnalysisService.analyze_pcap()` returns protocol breakdown from pcap | command_passes |
| 2 | Insecure protocol detection flags telnet/FTP/plaintext-MQTT in test pcap | command_passes |
| 2 | DNS query extraction returns domain names from pcap | command_passes |
| 3 | 5 MCP tools registered: analyze_network_traffic, get_protocol_breakdown, identify_insecure_protocols, get_dns_queries, capture_network_traffic (enhanced) | command_passes |
| 3 | EmulationPage shows Network Traffic tab with protocol breakdown | manual |
| 3 | "Download PCAP" button returns valid pcap file | manual |

## Phase Details

### Phase 1: Pcap Capture Infrastructure

**Files to modify:**
- `backend/app/services/system_emulation_service.py` — modify `capture_network_traffic()` to write pcap binary
- `backend/app/models/emulation_session.py` — add `pcap_path: Mapped[str | None]`
- `backend/app/schemas/emulation.py` — add pcap_path to response, add NetworkCaptureResponse
- `backend/app/routers/emulation.py` — add `GET .../pcap` download endpoint
- `alembic/versions/` — new migration for pcap_path column

**Approach:**
1. Modify tcpdump command: `-w /tmp/capture_{sid}.pcap -c 10000` (binary pcap, 10K packet cap)
2. Add `-G 300` timeout (5 min max) and `not port 22` filter (exclude SSH management)
3. After capture, `docker cp` pcap from sidecar to `{STORAGE_ROOT}/projects/{pid}/pcaps/{sid}.pcap`
4. Store path in EmulationSession.pcap_path
5. New endpoint returns FileResponse with content_type `application/vnd.tcpdump.pcap`

### Phase 2: Scapy Protocol Analysis Service

**Files to create/modify:**
- New: `backend/app/services/pcap_analysis_service.py` (~400 lines)
- `backend/pyproject.toml` — add `scapy>=2.6`
- `backend/Dockerfile` — scapy is pure Python, installs via pip (no extra apt packages)

**PcapAnalysisService methods:**
1. `analyze_pcap(pcap_path) → PcapAnalysis` — full pipeline
2. `_extract_protocol_breakdown(packets) → dict[str, int]` — protocol → packet count
3. `_extract_conversations(packets) → list[Conversation]` — src:port ↔ dst:port with stats
4. `_detect_insecure_protocols(packets) → list[InsecureProtocolFinding]` — 13 rules (see below)
5. `_extract_dns_queries(packets) → list[DnsQuery]` — domain, query type, resolved IPs
6. `_extract_tls_metadata(packets) → list[TlsInfo]` — version, ciphers, certs, JA3

**Memory safety:** Use `PcapReader` iterator (not `rdpcap` which loads all into memory). Cap at 10K packets.

**Insecure protocol rules (13):**

| Protocol | Port | Severity | Detection |
|----------|------|----------|-----------|
| Telnet | 23 | Critical | TCP to port 23 with payload |
| TFTP | 69 | Critical | UDP to port 69 |
| FTP | 21 | High | TCP to port 21 with payload |
| MQTT (no TLS) | 1883 | High | scapy.contrib.mqtt layer present |
| SNMPv1/v2c | 161 | High | SNMP layer with version < 3 |
| HTTP (no TLS) | 80 | Medium | TCP to port 80 with HTTP payload |
| CoAP (no DTLS) | 5683 | Medium | scapy.contrib.coap layer present |
| UPnP/SSDP | 1900 | Medium | UDP to 239.255.255.250:1900 |
| Syslog (UDP) | 514 | Medium | UDP to port 514 |
| TLS 1.0/1.1 | any | Medium | TLS ClientHello with version <= 0x0302 |
| DNS (no DoT) | 53 | Low | UDP/TCP to port 53 |
| NTP (unauth) | 123 | Low | UDP to port 123 |
| mDNS | 5353 | Info | UDP to 224.0.0.251:5353 |

### Phase 3: MCP Tools + Frontend

**Files to create/modify:**
- New: `backend/app/ai/tools/network.py` (~200 lines)
- `backend/app/ai/__init__.py` — register network tools
- `backend/app/routers/emulation.py` — add analysis REST endpoints
- `backend/app/routers/tools.py` — whitelist network tools
- `frontend/src/pages/EmulationPage.tsx` — add Network Traffic tab
- New: `frontend/src/components/emulation/NetworkTrafficPanel.tsx`
- `frontend/src/api/emulation.ts` — add pcap download + analysis API calls

**5 MCP tools:**
1. `capture_network_traffic` — enhanced: writes pcap, returns packet count + path
2. `analyze_network_traffic` — full analysis (protocol breakdown, conversations, insecure findings)
3. `get_protocol_breakdown` — quick protocol statistics from stored pcap
4. `identify_insecure_protocols` — security-focused: insecure protocol findings with severity
5. `get_dns_queries` — DNS query extraction (reveals C2, update servers, telemetry)

**Frontend Network Traffic tab:**
- Protocol breakdown table (protocol → packet count, percentage)
- Conversation table (src ↔ dst, protocol, packets, bytes)
- Insecure protocol findings (styled like security findings elsewhere)
- DNS query list (domain, query type, resolved IPs)
- "Capture Traffic" button (starts capture on running emulation)
- "Download PCAP" button (downloads raw pcap for Wireshark)

## Feature Ledger

| Feature | Phase | Status | Files |
|---------|-------|--------|-------|
| Binary pcap capture (tcpdump -w) | 1 | complete | system_emulation_service.py |
| Pcap storage + docker cp | 1 | complete | system_emulation_service.py |
| pcap_path DB column + migration | 1 | complete | emulation_session.py, alembic |
| Pcap download REST endpoint | 1 | complete | routers/emulation.py |
| Scapy dependency | 2 | complete | pyproject.toml |
| PcapAnalysisService | 2 | complete | pcap_analysis_service.py |
| Protocol breakdown extraction | 2 | complete | pcap_analysis_service.py |
| Insecure protocol detection (13 rules) | 2 | complete | pcap_analysis_service.py |
| DNS query extraction | 2 | complete | pcap_analysis_service.py |
| TLS metadata analysis | 2 | complete | pcap_analysis_service.py |
| Conversation extraction | 2 | complete | pcap_analysis_service.py |
| 5 MCP tools (network.py) | 3 | complete | tools/network.py |
| Network analysis REST endpoints | 3 | complete | routers/emulation.py |
| NetworkTrafficPanel component | 3 | complete | NetworkTrafficPanel.tsx |
| EmulationPage Network tab | 3 | complete | EmulationPage.tsx |
| Pcap download button | 3 | complete | NetworkTrafficPanel.tsx |

## Decision Log

| Decision | Reason |
|----------|--------|
| Scapy over pyshark | Pure Python, no tshark binary needed in container, 200+ protocols including IoT |
| Scapy over dpkt | Better protocol coverage, more active development, IoT protocol support |
| PcapReader iterator over rdpcap | Memory safety — rdpcap loads entire pcap into memory, PcapReader streams |
| 10K packet cap | Prevents runaway captures from consuming disk/memory on large firmware |
| pcap stored on disk, not DB | Binary files don't belong in PostgreSQL; path reference in DB is sufficient |
| Exclude port 22 from capture | SSH management traffic between backend and sidecar is noise |
| 13 insecure protocol rules | Covers the most common embedded/IoT insecure protocols; extensible later |
| Network tools as separate category | Distinct from emulation tools — analysis runs on stored pcap, not live sessions |

## Active Context

- Campaign completed 2026-04-07 in a single session (estimated 2-3)
- All 3 phases built and verified: pcap capture, Scapy analysis, MCP tools + frontend

## Completion Summary

**Phase 1:** Modified `capture_network_traffic()` to write binary pcap via `tcpdump -w`, added `pcap_path` column + migration, added `GET /pcap` download endpoint.

**Phase 2:** Created `PcapAnalysisService` (~400 lines) with PcapReader iterator (memory-safe), 13 insecure protocol detection rules, DNS query extraction, TLS metadata, conversation grouping. Verified with synthetic pcap.

**Phase 3:** Created 5 MCP tools (`network.py`), `GET /network-analysis` REST endpoint, `NetworkTrafficPanel` React component with capture controls + protocol breakdown + insecure findings + DNS + conversations + PCAP download. Integrated as sub-tab in EmulationPage System Mode.

<!-- session-end: 2026-04-07 -->
