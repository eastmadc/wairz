from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"), env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://wairz:wairz@localhost:5432/wairz"
    redis_url: str = "redis://localhost:6379/0"
    storage_root: str = "/data/firmware"
    max_upload_size_mb: int = 2048
    max_tool_output_kb: int = 30
    max_tool_iterations: int = 25
    ghidra_path: str = "/opt/ghidra"
    ghidra_scripts_path: str = "/opt/ghidra_scripts"
    ghidra_timeout: int = 300
    jadx_path: str = "/opt/jadx/bin/jadx"
    jadx_timeout: int = 300
    jadx_max_memory: str = "4g"
    jadx_threads: int = 4
    nvd_api_key: str = ""
    emulation_timeout_minutes: int = 30
    emulation_max_sessions: int = 3
    emulation_memory_limit_mb: int = 1024
    emulation_cpu_limit: float = 1.0
    emulation_image: str = "wairz-emulation"
    emulation_kernel_dir: str = "/opt/kernels"
    emulation_network: str = "wairz_emulation_net"
    fuzzing_image: str = "wairz-fuzzing"
    fuzzing_timeout_minutes: int = 120
    fuzzing_max_campaigns: int = 1
    fuzzing_memory_limit_mb: int = 2048
    fuzzing_cpu_limit: float = 2.0
    fuzzing_data_dir: str = "/data/fuzzing"
    system_emulation_image: str = "wairz-system-emulation"
    system_emulation_pipeline_timeout: int = 1800  # 30 min (cross-arch on RPi is slow)
    system_emulation_idle_timeout: int = 1800  # 30 min
    system_emulation_ram_limit: str = "2g"
    system_emulation_cpu_limit: int = 2
    uart_bridge_host: str = "host.docker.internal"
    uart_bridge_port: int = 9999
    uart_command_timeout: int = 30
    device_bridge_host: str = "host.docker.internal"
    device_bridge_port: int = 9998
    cors_origins: str = ""
    syft_enabled: bool = True
    syft_timeout: int = 120
    vulnerability_backend: str = "grype"  # "grype" or "nvd"
    grype_db_cache_dir: str = "/data/grype-db"
    grype_timeout: int = 120
    kernel_vulns_git_url: str = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
    kernel_vulns_cache_dir: str = "/data/kernel-vulns"
    kernel_vulns_sync_timeout: int = 600
    max_extraction_size_mb: int = 10240
    max_extraction_files: int = 500000
    max_compression_ratio: int = 200
    # Max firmware size for the "standalone binary" fallback path.  When all
    # extractors (unblob, binwalk3) fail to produce a filesystem root, firmware
    # at or under this size is COPIED into extraction_dir as a single-file
    # target so users can analyse it as a raw binary (bootloaders, bare-metal
    # medical / automotive / IoT images, ROM dumps).  Past this size, the
    # extraction fails cleanly with a readable error.  Tune up for
    # deployments that ingest large raw firmware; cost is ~input_size extra
    # disk per failed-extraction.  Original hardcoded limit was 10 MB, which
    # excluded most real-world bare-metal firmware.
    max_standalone_binary_mb: int = 512
    dependency_track_url: str = ""
    dependency_track_api_key: str = ""
    vulhunt_url: str = "http://vulhunt:8080"
    vulhunt_timeout: int = 300
    cwe_checker_image: str = "ghcr.io/fkie-cad/cwe_checker:stable"
    cwe_checker_timeout: int = 600
    cwe_checker_memory_limit: str = "4g"
    yara_forge_dir: str = "/data/yara-forge"
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_enabled: bool = True
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""
    api_key: str | None = None
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
