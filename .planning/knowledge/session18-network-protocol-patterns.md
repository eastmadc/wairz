# Patterns: Network Protocol Analysis Campaign

> Extracted: 2026-04-08
> Campaign: .planning/campaigns/network-protocol-analysis.md
> Postmortem: none

## Successful Patterns

### 1. Container-to-Host File Transfer via Docker tar API
- **Description:** Used `container.get_archive("/tmp/capture.pcap")` to extract binary pcap from the FirmAE sidecar container, then unpacked the tar stream in Python. This avoids `docker cp` CLI dependency and works within the async executor pattern.
- **Evidence:** Phase 1 — capture_network_traffic() in system_emulation_service.py uses get_archive + tarfile extraction
- **Applies when:** Any time you need to get a file out of a Docker sidecar container into the backend. Prefer the Python Docker SDK's `get_archive()` over shelling out to `docker cp`.

### 2. PcapReader Iterator Over rdpcap for Memory Safety
- **Description:** Used Scapy's `PcapReader` (streaming iterator) instead of `rdpcap` (loads entire pcap into memory). Combined with a 10K packet cap for defense in depth.
- **Evidence:** Phase 2 — Decision Log entry; pcap_analysis_service.py `_read_packets()` method
- **Applies when:** Any Scapy-based pcap analysis. Firmware captures can be large, and `rdpcap` will OOM on a 100MB pcap.

### 3. Lazy Imports for Optional Protocol Layers
- **Description:** Used try/except for Scapy TLS layers and IoT contrib modules (MQTT, CoAP) since they may not be installed or available depending on Scapy version. Set `HAS_TLS` flag at module level.
- **Evidence:** Phase 2 — pcap_analysis_service.py lines 17-23, graceful degradation in TLS and IoT protocol detection
- **Applies when:** Any time you use Scapy contrib modules or optional protocol layers. Never crash on an unavailable dissector.

### 4. Shared Helper for Repeated DB Lookup in MCP Tools
- **Description:** Created `_load_pcap_analysis()` helper function shared by all 5 network MCP tools. It handles session lookup, pcap_path validation, and executor-based analysis — eliminating code duplication across handlers.
- **Evidence:** Phase 3 — network.py has `_load_pcap_analysis` reused by all 5 handlers
- **Applies when:** When creating multiple MCP tools that share the same DB lookup + service call pattern. Extract the common prefix into a helper.

### 5. Sub-Tab Architecture for Complex Pages
- **Description:** Added Terminal/Network Traffic sub-tabs within the System Mode tab of EmulationPage, using a `systemSubTab` state variable. This extends the existing page without cluttering the top-level tab bar.
- **Evidence:** Phase 3 — EmulationPage.tsx `systemSubTab` state, conditional rendering between terminal and NetworkTrafficPanel
- **Applies when:** Adding a new analysis view to an existing feature page. Use sub-tabs within the feature's content area rather than adding top-level navigation.

### 6. Synthetic Pcap for End-to-End Verification
- **Description:** Phase 2 was verified by constructing a synthetic pcap with Scapy (Telnet, FTP, DNS, MQTT, HTTP, NTP packets) and running `PcapAnalysisService.analyze_pcap()` against it. All 3 end conditions validated programmatically.
- **Evidence:** Phase 2 verification — sub-agent built and ran a synthetic pcap test inline
- **Applies when:** Testing protocol analysis or detection rules. Craft synthetic pcaps with known contents rather than relying on real captures that may not contain the protocols you need to test.

### 7. Campaign Completed in 1 Session (Estimated 2-3)
- **Description:** Detailed upfront planning with file-level change specifications, clear phase boundaries, and machine-verifiable end conditions enabled all 3 phases to complete in a single session.
- **Evidence:** Campaign metadata: Estimated Sessions: 2-3, Actual Sessions: 1
- **Applies when:** When a campaign has been thoroughly researched and planned (current state verified, approach specified, files enumerated), delegate execution to sub-agents and verify end conditions.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Scapy over pyshark | Pure Python, no tshark binary needed in Docker container, 200+ protocols including IoT (MQTT, CoAP) | Good — installed cleanly via pip, no apt dependencies |
| Scapy over dpkt | Better protocol coverage, more active maintenance, IoT protocol support | Good — dpkt would have missed IoT protocols |
| PcapReader iterator over rdpcap | Memory safety — rdpcap loads entire pcap into RAM, PcapReader streams | Good — essential for embedded firmware analysis where captures vary in size |
| 10K packet cap | Prevents runaway captures consuming disk/memory on large firmware | Good — reasonable limit; 5 min + 10K packets covers typical firmware network behavior |
| pcap on disk, not DB | Binary files don't belong in PostgreSQL; path reference is sufficient | Good — follows existing firmware file storage pattern |
| Exclude port 22 from capture | SSH management traffic between backend and sidecar is noise | Good — clean captures without infrastructure chatter |
| Network tools as separate category (network.py) | Distinct from emulation tools — analysis runs on stored pcap, not live sessions | Good — clean separation of capture (emulation) vs analysis (network) |
| Port-based protocol mapping (not deep inspection) | Simple, fast, covers 90% of embedded firmware protocols | Good — correct tradeoff for firmware analysis; deep inspection can be added later |
