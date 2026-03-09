<p align="center">
  <img src="frontend/src/assets/wairz_banner.png" alt="Wairz - Every Firmware Has Secrets... WAIRZ Finds Them" width="100%">
</p>

---

Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Connect any MCP-compatible AI agent to Wairz's 60+ analysis tools — [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Claude Desktop](https://claude.ai/download), [OpenCode](https://opencode.ai/), [Codex](https://github.com/openai/codex), [Cursor](https://cursor.com/), [VS Code + Copilot](https://code.visualstudio.com/docs/copilot/), [Gemini CLI](https://github.com/google-gemini/gemini-cli), [Windsurf](https://windsurf.com/), and more.

[Watch the demo video](https://www.youtube.com/watch?v=gDLhtMFMmMM)

## Features

- **Firmware Unpacking** — Automatic extraction of SquashFS, JFFS2, UBIFS, CramFS, ext, and CPIO filesystems via binwalk, with multi-partition support
- **File Explorer** — Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search across files
- **Binary Analysis** — Disassemble and decompile binaries using radare2 and Ghidra headless, with cross-reference and taint analysis
- **Component Map** — Interactive dependency graph showing binaries, libraries, scripts, and their relationships
- **Security Assessment** — Detect hardcoded credentials, crypto material, setuid binaries, insecure configs, and weak permissions
- **SBOM & CVE Scanning** — Generate Software Bill of Materials (CycloneDX) and scan components against the NVD for known vulnerabilities
- **Firmware Emulation** — Boot firmware in QEMU (user-mode for single binaries, system-mode for full OS) in isolated containers, with GDB support
- **Fuzzing** — AFL++ with QEMU mode for cross-architecture binary fuzzing, with automatic dictionary/corpus generation and crash triage
- **Firmware Comparison** — Diff filesystem trees, binaries, and decompiled functions across firmware versions
- **Live Device UART** — Connect to physical devices via a host-side serial bridge for interactive console access
- **AI Analysis via MCP** — 60+ analysis tools exposed to Claude for autonomous security research
- **Findings & Reports** — Record security findings with severity ratings and evidence, export as Markdown or PDF

## Architecture

```
Claude Code / Claude Desktop / OpenCode
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  60+ tools      │     │  Services: firmware, analysis,     │
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

WAIRZ is currently designed for **embedded Linux** firmware samples. Support for RTOS and bare-metal firmware is planned for future releases.

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

> **Note:** The `timeout` must be increased from the default 5000ms because Wairz registers 90+ tools.

Once connected, your AI agent can autonomously explore firmware, analyze binaries, run emulation, fuzz targets, and generate security findings. The MCP server supports dynamic project switching via the `switch_project` tool — no restart needed to change projects.

### MCP Tools (60+)

| Category | Tools |
|----------|-------|
| **Project** | `get_project_info`, `switch_project`, `list_projects` |
| **Filesystem** | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| **Strings** | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials` |
| **Binary Analysis** | `list_functions`, `disassemble_function`, `decompile_function`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `check_binary_protections`, `check_all_binary_protections`, `find_string_refs`, `resolve_import`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `trace_dataflow`, `cross_binary_dataflow` |
| **Security** | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate` |
| **SBOM** | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan` |
| **Emulation** | `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `enumerate_emulation_services`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset` |
| **Fuzzing** | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash` |
| **Comparison** | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| **UART** | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| **Reporting** | `add_finding`, `list_findings`, `update_finding`, `read_project_instructions`, `list_project_documents`, `read_project_document` |
| **Code** | `save_code_cleanup` |

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
| Firmware Extraction | binwalk, sasquatch, jefferson, ubi_reader, cramfs-tools |
| Binary Analysis | radare2 (r2pipe), pyelftools |
| Decompilation | Ghidra 11.3.1 (headless) with custom analysis scripts |
| Emulation | QEMU user-mode + system-mode (ARM, MIPS, MIPSel, AArch64) |
| Fuzzing | AFL++ with QEMU mode |
| SBOM | CycloneDX, NVD API (nvdlib) |
| UART | pyserial (host-side bridge) |
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
│   │   ├── ai/                  # MCP tool registry + 60+ tool implementations
│   │   │   └── tools/           # Organized by category (filesystem, binary, security, etc.)
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
│   └── wairz-uart-bridge.py     # Host-side UART serial bridge
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
| `NVD_API_KEY` | *(empty)* | Optional NVD API key for higher rate limits |
| `LOG_LEVEL` | `INFO` | Logging level |

## Testing Firmware

Good firmware images for testing:

- **[OpenWrt](https://downloads.openwrt.org/)** — Well-structured embedded Linux (MIPS, ARM)
- **[DD-WRT](https://dd-wrt.com/)** — Similar to OpenWrt
- **[DVRF](https://github.com/praetorian-inc/DVRF)** (Damn Vulnerable Router Firmware) — Intentionally vulnerable, great for security testing

## License

[AGPL-3.0](LICENSE)
