# Plan: Network Protocol Analysis (5.4)

**Priority:** Medium | **Effort:** Large (~13h) | **Route:** `/citadel:archon` (depends on system emulation, now complete)

## Goal

Capture pcap from emulated firmware, analyze protocols, fingerprint services.

## Current State

- `capture_network_traffic()` in `system_emulation_service.py` runs tcpdump → plain text output
- nmap in shim provides basic service discovery (port + service name)
- `discovered_services` JSONB stored in EmulationSession
- tcpdump now installed in sidecar (added this session)
- No pcap file output, no protocol dissection, no structured analysis

## What Needs to Change

1. **Capture to pcap file** — modify tcpdump to write `-w /tmp/capture.pcap` instead of text
2. **Protocol dissection** — integrate scapy or pyshark for parsing pcap
3. **Service fingerprinting** — enhance beyond nmap's basic detection
4. **Vulnerability correlation** — map discovered protocols to known CVEs
5. **MCP tools** — `analyze_network_traffic`, `get_protocol_breakdown`, `identify_insecure_protocols`
6. **Frontend** — traffic summary panel on EmulationPage

## Key Files

- `backend/app/services/system_emulation_service.py` (lines 531-579)
- `system-emulation/shim/app.py` (nmap integration)
- New: `backend/app/services/pcap_analysis_service.py`
- New: `backend/app/ai/tools/network.py`

## Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| 1 | Pcap capture (modify tcpdump, store file) | 4h |
| 2 | Scapy integration + protocol analysis | 6h |
| 3 | Service fingerprinting + insecure protocol detection | 3h |
