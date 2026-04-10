<p align="center">
  <img src="frontend/src/assets/wairz_banner.png" alt="Wairz - Every Firmware Has Secrets... WAIRZ Finds Them" width="100%">
</p>

---

Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Connect any MCP-compatible AI agent to Wairz's 160+ analysis tools — [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Claude Desktop](https://claude.ai/download), [OpenCode](https://opencode.ai/), [Codex](https://github.com/openai/codex), [Cursor](https://cursor.com/), [VS Code + Copilot](https://code.visualstudio.com/docs/copilot/), [Gemini CLI](https://github.com/google-gemini/gemini-cli), [Windsurf](https://windsurf.com/), and more.

[Watch the demo video](https://www.youtube.com/watch?v=gDLhtMFMmMM)

## Features

- **Firmware Unpacking** — Automatic extraction of SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO, and Intel HEX filesystems via binwalk3 and unblob, with multi-partition support
- **File Explorer** — Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search across files
- **Binary Analysis** — Disassemble and decompile binaries using radare2 and Ghidra headless, with cross-reference, taint analysis, and capability detection (capa)
- **Component Map** — Interactive dependency graph showing binaries, libraries, scripts, and their relationships
- **Security Assessment** — Detect hardcoded credentials, crypto material, hardcoded IPs, setuid binaries, insecure configs, weak permissions, and network dependencies
- **Attack Surface Scoring** — Automated 0-100 risk scoring across network exposure, CGI, setuid, dangerous functions, and known daemons
- **SAST** — ShellCheck for shell scripts and Bandit for Python scripts, with CWE mapping
- **cwe_checker** — Binary vulnerability pattern detection (17 CWEs) via Docker sidecar with ARM/MIPS/x86 support
- **YARA Scanning** — Custom rules + ~5000 YARA Forge community rules, with on-demand updates
- **Threat Intelligence** — ClamAV malware scanning, VirusTotal hash lookups (privacy-first, no file upload), abuse.ch suite (MalwareBazaar, ThreatFox, URLhaus, YARAify), and CIRCL Hashlookup for known-good binary identification via NSRL
- **SBOM & CVE Scanning** — Generate Software Bill of Materials (CycloneDX 1.7, SPDX 2.3, CycloneDX VEX) with generic binary version detection fallback, CPE enrichment via NVD dictionary, and vulnerability scanning against the NVD
- **Firmware Emulation** — User-mode (QEMU) for single binaries, system-mode (FirmAE) for full OS boot in isolated containers, with GDB, pcap capture, and web endpoint interaction
- **Network Protocol Analysis** — Capture and analyze traffic from emulated firmware: protocol breakdown, insecure protocol detection, DNS queries, TLS metadata
- **Fuzzing** — AFL++ with QEMU mode for cross-architecture binary fuzzing, with automatic dictionary/corpus generation and crash triage
- **Firmware Comparison** — Diff filesystem trees, binaries, and decompiled functions across firmware versions
- **RTOS & Bare-Metal Support** — Detection of FreeRTOS, VxWorks, Zephyr, ThreadX and companion components (lwIP, FatFs, etc.)
- **UEFI Firmware Support** — UEFIExtract for firmware volumes, module listing, NVRAM variable extraction, and PE32+ scanning
- **Android Firmware** — APK analysis via Androguard, permission listing, signature verification, SELinux policy analysis
- **Device Acquisition** — Pull firmware directly from ADB-connected Android devices via a host-side bridge
- **Firmware Update Detection** — Identify SWUpdate, RAUC, Mender, opkg, U-Boot, and custom update mechanisms with security gap analysis
- **CRA Compliance** — EU Cyber Resilience Act Annex I assessment (20 requirements), auto-populate from existing findings, Article 14 notification export
- **Live Device UART** — Connect to physical devices via a host-side serial bridge for interactive console access
- **AI Analysis via MCP** — 160+ analysis tools exposed to any MCP-compatible AI agent for autonomous security research
- **Findings & Reports** — Record security findings with severity ratings and evidence, export as Markdown, with full assessment orchestration

## Architecture

```
Claude Code / Claude Desktop / OpenCode
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  160+ tools     │     │  Services: firmware, analysis,     │
│                 │     │  emulation, fuzzing, sbom, uart    │
└─────────────────┘     │                                    │
                        │  Ghidra headless · QEMU · AFL++    │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  Redis       │
│  (Frontend)  │    │              │              │
└──────────────┘    └──────────────┴──────────────┘

Optional:
  wairz-uart-bridge.py (host) ←─ TCP:9999 ─→ Docker backend
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development only)

## Public Beta

WAIRZ is currently in **public beta**. You may encounter bugs or rough edges. If you run into any issues, please [open an issue on GitHub](https://github.com/digitalandrew/wairz/issues) or reach out at andrew@digitalandrew.io.

WAIRZ supports **embedded Linux**, **RTOS/bare-metal** (FreeRTOS, VxWorks, Zephyr, ThreadX), **UEFI**, and **Android** firmware.

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

### Docker with Hot-Reload (development)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Backend Python changes are picked up automatically via uvicorn `--reload`. Frontend uses Vite dev server with HMR. No rebuild needed for code changes — only rebuild when dependencies change (`pyproject.toml` or `package.json`).

### Local Development

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Backend
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Or use the helper script:

```bash
./launch.sh
```

## Connecting AI via MCP

Wairz uses MCP to give AI agents access to firmware analysis tools. After starting the backend, register the MCP server with your preferred client:

### Claude Code

```bash
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

### Claude Desktop

Add to your Claude Desktop config (`~/.config/Claude/claude_desktop_config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

### OpenCode

Add to your `opencode.json` (project root or `~/.config/opencode/opencode.json`):

```json
{
  "mcp": {
    "wairz": {
      "type": "local",
      "command": ["docker", "exec", "-i", "wairz-backend-1", "uv", "run", "wairz-mcp", "--project-id", "<PROJECT_ID>"],
      "timeout": 30000,
      "enabled": true
    }
  }
}
```

> **Note:** The `timeout` must be increased from the default 5000ms because Wairz registers 160+ tools.

Once connected, your AI agent can autonomously explore firmware, analyze binaries, run emulation, fuzz targets, and generate security findings. The MCP server supports dynamic project switching via the `switch_project` tool — no restart needed to change projects.

### MCP Tools (160+)

| Category | Count | Tools |
|----------|-------|-------|
| **Security** | 26 | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate`, `check_kernel_hardening`, `scan_with_yara`, `extract_kernel_config`, `check_kernel_config`, `analyze_selinux_policy`, `check_selinux_enforcement`, `check_compliance`, `scan_scripts`, `shellcheck_scan`, `bandit_scan`, `check_secure_boot`, `update_yara_rules`, `detect_network_dependencies`, `detect_update_mechanisms`, `analyze_update_config`, `create_cra_assessment`, `auto_populate_cra`, `update_cra_requirement`, `export_cra_checklist`, `generate_article14_notification` |
| **Threat Intelligence** | 10 | `scan_with_clamav`, `scan_firmware_clamav`, `check_virustotal`, `scan_firmware_virustotal`, `check_malwarebazaar_hash`, `check_threatfox_ioc`, `check_urlhaus_url`, `enrich_firmware_threat_intel`, `check_known_good_hash`, `scan_firmware_known_good` |
| **Emulation** | 25 | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `enumerate_emulation_services`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset`, `emulate_with_qiling`, `check_qiling_rootfs`, `start_system_emulation`, `system_emulation_status`, `list_firmware_services`, `run_command_in_firmware`, `stop_system_emulation`, `capture_network_traffic`, `get_nvram_state`, `interact_web_endpoint`, `list_available_kernels`, `download_kernel` |
| **Binary Analysis** | 23 | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `analyze_binary_format`, `check_binary_protections`, `check_all_binary_protections`, `find_string_refs`, `resolve_import`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `trace_dataflow`, `cross_binary_dataflow`, `detect_capabilities`, `list_binary_capabilities`, `detect_rtos`, `analyze_raw_binary` |
| **Fuzzing** | 9 | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash`, `diagnose_fuzzing_campaign` |
| **SBOM** | 9 | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan`, `list_vulnerabilities_for_assessment`, `export_sbom`, `push_to_dependency_track`, `assess_vulnerabilities`, `set_vulnerability_status` |
| **Filesystem** | 8 | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| **UART** | 8 | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| **Reporting** | 6 | `add_finding`, `list_findings`, `update_finding`, `generate_assessment_report`, `generate_executive_summary`, `run_full_assessment` |
| **Documents** | 6 | `read_scratchpad`, `update_scratchpad`, `save_document`, `read_project_instructions`, `list_project_documents`, `read_project_document` |
| **Strings** | 5 | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials`, `find_hardcoded_ips` |
| **Network** | 5 | `analyze_network_traffic`, `get_protocol_breakdown`, `identify_insecure_protocols`, `get_dns_queries`, `get_network_conversations` |
| **UEFI** | 5 | `list_firmware_volumes`, `list_uefi_modules`, `extract_nvram_variables`, `identify_uefi_module`, `read_uefi_module` |
| **Comparison** | 4 | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| **Project** | 3 | `get_project_info`, `switch_project`, `list_projects` |
| **Android** | 3 | `analyze_apk`, `list_apk_permissions`, `check_apk_signatures` |
| **cwe_checker** | 3 | `cwe_check_status`, `cwe_check_binary`, `cwe_check_firmware` |
| **VulHunt** | 3 | `vulhunt_scan_binary`, `vulhunt_scan_firmware`, `vulhunt_check_available` |
| **Attack Surface** | 2 | `detect_input_vectors`, `analyze_binary_attack_surface` |

## UART Bridge (Optional)

For live device access via UART, run the bridge on the host machine (USB serial adapters can't easily pass through to Docker):

```bash
pip install pyserial
python3 scripts/wairz-uart-bridge.py --bind 0.0.0.0 --port 9999
```

The bridge is a TCP server — the serial device path and baud rate are specified via the `uart_connect` MCP tool, not on the command line.

On Linux, allow Docker traffic to reach the bridge and ensure `.env` is configured correctly:

```bash
sudo iptables -I INPUT -p tcp --dport 9999 -j ACCEPT
```

`UART_BRIDGE_HOST` in `.env` must be `host.docker.internal` (not `localhost`). Restart the backend after changing `.env`: `docker compose restart backend`.

See [UART Console docs](docs/features/uart.md) for full setup details.

## Device Acquisition Bridge (Optional)

For pulling firmware directly from ADB-connected Android devices, run the device bridge on the host:

```bash
python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998
```

For development without a real device, use mock mode:

```bash
python3 scripts/wairz-device-bridge.py --mock --port 9998
```

Setup is the same pattern as the UART bridge: set `DEVICE_BRIDGE_HOST=host.docker.internal` in `.env` and allow Docker traffic on port 9998.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| Code Viewer | Monaco Editor |
| Component Graph | ReactFlow + Dagre |
| Terminal | xterm.js |
| State Management | Zustand |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Firmware Extraction | binwalk3, unblob, sasquatch, jefferson, ubi_reader, cramfs-tools, UEFIExtract |
| Binary Analysis | radare2 (r2pipe), pyelftools, LIEF, capa |
| Decompilation | Ghidra 11.3.1 (headless) with custom analysis scripts |
| Vulnerability Detection | cwe_checker (17 CWEs), VulHunt, YARA (~5000 Forge rules), ShellCheck, Bandit |
| Threat Intelligence | ClamAV, VirusTotal, abuse.ch (MalwareBazaar, ThreatFox, URLhaus, YARAify), CIRCL Hashlookup (NSRL) |
| Emulation | QEMU user-mode + system-mode, FirmAE, Qiling (ARM, MIPS, MIPSel, AArch64) |
| Network Analysis | Scapy (pcap capture + protocol analysis from emulated firmware) |
| Fuzzing | AFL++ with QEMU mode |
| SBOM | CycloneDX 1.7, SPDX 2.3, CycloneDX VEX, NVD API (nvdlib), Grype, Syft |
| Android | Androguard (APK analysis), ADB (device acquisition) |
| UART | pyserial (host-side bridge) |
| Compliance | EU CRA Annex I (20 requirements), ETSI EN 303 645 |
| AI Integration | MCP (Model Context Protocol) |
| Containers | Docker + Docker Compose |

## Project Structure

```
wairz/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # Async SQLAlchemy engine/session
│   │   ├── mcp_server.py        # MCP server with dynamic project switching
│   │   ├── models/              # SQLAlchemy ORM models
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── routers/             # REST API endpoints
│   │   ├── services/            # Business logic
│   │   ├── ai/                  # MCP tool registry + 160+ tool implementations
│   │   │   └── tools/           # 18 category files (filesystem, binary, security, emulation, etc.)
│   │   └── utils/               # Path sandboxing, output truncation
│   ├── alembic/                 # Database migrations
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/               # Route pages (explorer, emulation, fuzzing, SBOM, etc.)
│   │   ├── components/          # UI components (file tree, hex viewer, component map, etc.)
│   │   ├── api/                 # API client functions
│   │   ├── stores/              # Zustand state management
│   │   └── types/               # TypeScript type definitions
│   └── package.json
├── ghidra/
│   ├── Dockerfile               # Ghidra headless container
│   └── scripts/                 # Custom Java analysis scripts
├── emulation/
│   ├── Dockerfile               # QEMU container (ARM, MIPS, MIPSel, AArch64)
│   └── scripts/                 # Emulation helper scripts
├── fuzzing/
│   └── Dockerfile               # AFL++ container with QEMU mode
├── scripts/
│   ├── wairz-uart-bridge.py     # Host-side UART serial bridge
│   └── wairz-device-bridge.py   # Host-side ADB device acquisition bridge
├── docker-compose.yml
├── launch.sh                    # Local development launcher
├── .env.example
└── CLAUDE.md
```

## Configuration

All settings are configured via environment variables or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://wairz:wairz@postgres:5432/wairz` | PostgreSQL connection |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection |
| `STORAGE_ROOT` | `/data/firmware` | Firmware storage directory |
| `MAX_UPLOAD_SIZE_MB` | `500` | Maximum firmware upload size |
| `MAX_TOOL_OUTPUT_KB` | `30` | MCP tool output truncation limit |
| `GHIDRA_PATH` | `/opt/ghidra` | Ghidra installation path |
| `GHIDRA_TIMEOUT` | `120` | Ghidra decompilation timeout (seconds) |
| `FUZZING_IMAGE` | `wairz-fuzzing` | Fuzzing container image name |
| `FUZZING_TIMEOUT_MINUTES` | `120` | Max fuzzing campaign duration |
| `FUZZING_MAX_CAMPAIGNS` | `1` | Max concurrent fuzzing campaigns |
| `UART_BRIDGE_HOST` | `host.docker.internal` | UART bridge hostname |
| `UART_BRIDGE_PORT` | `9999` | UART bridge TCP port |
| `DEVICE_BRIDGE_HOST` | `host.docker.internal` | Device acquisition bridge hostname |
| `DEVICE_BRIDGE_PORT` | `9998` | Device acquisition bridge TCP port |
| `NVD_API_KEY` | *(empty)* | Optional NVD API key for higher rate limits |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional VirusTotal API key (hash-only lookups, no file upload) |
| `ABUSECH_AUTH_KEY` | *(empty)* | Optional abuse.ch auth key for higher rate limits |
| `CLAMAV_HOST` | `clamav` | ClamAV daemon hostname (Docker service) |
| `CLAMAV_PORT` | `3310` | ClamAV daemon TCP port |
| `API_KEY` | *(empty)* | Optional API key for REST endpoint authentication |
| `LOG_LEVEL` | `INFO` | Logging level |

## Testing Firmware

Good firmware images for testing:

- **[OpenWrt](https://downloads.openwrt.org/)** — Well-structured embedded Linux (MIPS, ARM)
- **[DD-WRT](https://dd-wrt.com/)** — Similar to OpenWrt
- **[DVRF](https://github.com/praetorian-inc/DVRF)** (Damn Vulnerable Router Firmware) — Intentionally vulnerable, great for security testing

## License

[AGPL-3.0](LICENSE)
