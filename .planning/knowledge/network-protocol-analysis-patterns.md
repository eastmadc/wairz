# Patterns: Network Protocol Analysis Campaign

> Extracted: 2026-04-08
> Campaign: .planning/campaigns/network-protocol-analysis.md
> Postmortem: none

## Successful Patterns

### 1. Completed in 1 Session vs 2-3 Estimated
- **Description:** 3-phase campaign (pcap infrastructure, Scapy analysis service, MCP tools + frontend) completed in a single session despite estimating 2-3 sessions.
- **Evidence:** Campaign file shows "Estimated Sessions: 2-3, Actual Sessions: 1". All 15 feature ledger items marked complete.
- **Applies when:** Campaigns where all phases are build-only (no research uncertainty) and the spec is fully detailed with file paths, method signatures, and protocol rules pre-defined.

### 2. PcapReader Iterator Over rdpcap for Memory Safety
- **Description:** Used Scapy's `PcapReader` (streaming iterator) instead of `rdpcap` (loads entire pcap into memory). Combined with 10K packet cap.
- **Evidence:** Decision log entry: "Memory safety — rdpcap loads entire pcap into memory, PcapReader streams"
- **Applies when:** Any file-processing service that handles potentially large binary files. Always stream, never load-all.

### 3. Scapy Over pyshark/dpkt for IoT Protocol Coverage
- **Description:** Chose Scapy for protocol analysis because it's pure Python (no tshark binary needed), covers 200+ protocols including IoT (MQTT, CoAP, BLE), and is more actively maintained than dpkt.
- **Evidence:** Decision log. 13 insecure protocol rules implemented covering IoT-specific protocols (MQTT no-TLS, CoAP no-DTLS, UPnP/SSDP) that pyshark/dpkt would require extra packages for.
- **Applies when:** Adding protocol analysis to a Docker-based tool where minimizing binary dependencies matters.

### 4. Exclude Management Traffic from Captures
- **Description:** Added `not port 22` filter to tcpdump to exclude SSH traffic between backend and FirmAE sidecar.
- **Evidence:** Decision log entry. Without this filter, the majority of captured packets would be management SSH noise.
- **Applies when:** Any network capture from emulation/sidecar containers. Always filter out the management channel.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Scapy over pyshark | Pure Python, no tshark binary, 200+ protocols, IoT support | Good — zero extra apt packages needed |
| PcapReader over rdpcap | Memory safety for large pcap files | Good — streaming approach with 10K cap |
| pcap on disk, not DB | Binary files don't belong in PostgreSQL | Good — simple file path reference |
| Network tools as separate category file | Distinct from emulation tools — analysis runs on stored pcap | Good — clean separation of concerns |
| 13 insecure protocol rules | Covers common embedded/IoT insecure protocols, extensible | Good — covers telnet, FTP, MQTT, SNMP, HTTP, CoAP, UPnP, syslog, weak TLS |
| 10K packet cap | Prevents runaway captures | Good — sufficient for protocol detection without disk exhaustion |
