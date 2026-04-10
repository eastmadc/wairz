# Anti-patterns: Network Protocol Analysis Campaign

> Extracted: 2026-04-10
> Campaign: .planning/campaigns/network-protocol-analysis.md

## Failed Patterns

### 1. rdpcap Loading Entire Pcap Into Memory
- **What was done:** Initial consideration of Scapy's `rdpcap()` function to load pcap files for analysis.
- **Failure mode:** `rdpcap()` loads the entire pcap file into memory at once. Firmware emulation can generate large captures (10K+ packets, tens of MB). This would exhaust container memory on long captures.
- **Evidence:** Decision Log: "Memory safety — rdpcap loads entire pcap into memory, PcapReader streams." Chose PcapReader iterator + 10K packet cap instead.
- **How to avoid:** Always use streaming/iterator APIs for file processing in the backend. Never load entire files into memory when the size is unbounded. This applies to pcap, large firmware binaries, and any binary analysis output.

### 2. Capturing Management Traffic as Signal
- **What was done:** Initial tcpdump capture included all traffic including SSH between backend and FirmAE sidecar.
- **Failure mode:** Majority of captured packets were SSH management traffic, drowning out actual firmware network behavior. Protocol analysis would report SSH as the dominant protocol, which is misleading.
- **Evidence:** Decision Log: "Exclude port 22 from capture — SSH management traffic between backend and sidecar is noise."
- **How to avoid:** When capturing traffic from emulated/sidecar environments, always filter out management channels (SSH, Docker internal networking). The capture should reflect firmware behavior, not infrastructure.

### 3. Overestimating Session Count for Well-Specified Work
- **What was done:** Estimated 2-3 sessions for the campaign. Completed in 1 session.
- **Failure mode:** Not a code failure, but session estimation was 2-3x too high. The spec was fully detailed with file paths, method signatures, and protocol rules pre-defined.
- **Evidence:** Campaign file: "Estimated Sessions: 2-3, Actual Sessions: 1."
- **How to avoid:** When a campaign spec includes exact file paths, method signatures, data structures, and detection rules, estimate 1 session for build-only campaigns. Reserve multi-session estimates for campaigns with research phases or unclear requirements.
