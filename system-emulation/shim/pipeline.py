"""
FirmAE Pipeline Manager

Wraps FirmAE's run.sh execution, parses stdout/stderr for stage transitions,
monitors filesystem state files, tracks QEMU PID, handles timeouts, and
discovers guest IP from FirmAE's network inference output.
"""

import logging
import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class PipelinePhase(str, Enum):
    """Pipeline stages matching FirmAE's execution flow."""
    PENDING = "pending"
    EXTRACTING = "extracting"
    DETECTING_ARCH = "detecting_arch"
    PREPARING_IMAGE = "preparing_image"
    BOOTING = "booting"
    CHECKING = "checking"
    RUNNING = "running"
    FAILED = "failed"
    STOPPED = "stopped"
    TIMEOUT = "timeout"


# Patterns matched against FirmAE stdout/stderr to detect phase transitions.
# Order matters: we match top-down and take the first hit.
_PHASE_PATTERNS: list[tuple[re.Pattern, PipelinePhase]] = [
    (re.compile(r"running firmware", re.IGNORECASE), PipelinePhase.RUNNING),
    (re.compile(r"check(ing)?\s+(network|emulation)", re.IGNORECASE), PipelinePhase.CHECKING),
    (re.compile(r"(booting|starting qemu|qemu-system)", re.IGNORECASE), PipelinePhase.BOOTING),
    (re.compile(r"(creating|preparing)\s+(image|disk)", re.IGNORECASE), PipelinePhase.PREPARING_IMAGE),
    (re.compile(r"(inferring|detecting)\s+(architecture|arch)", re.IGNORECASE), PipelinePhase.DETECTING_ARCH),
    (re.compile(r"(extracting|unpacking|binwalk)", re.IGNORECASE), PipelinePhase.EXTRACTING),
]

# Pattern to extract guest IP from FirmAE output
_IP_PATTERN = re.compile(r"(?:guest|target|ip)\s*(?:ip|address)?[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE)
_IP_GENERIC_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# Pattern to extract architecture from FirmAE output
_ARCH_PATTERN = re.compile(r"(architecture|arch)[:\s]+(mipsel|mipseb|mips|armel|arm|aarch64)", re.IGNORECASE)


@dataclass
class PipelineState:
    """Mutable state for a single FirmAE pipeline run."""
    session_id: str
    firmware_path: str
    brand: str = "unknown"
    timeout: int = 600  # seconds

    # Runtime state
    phase: PipelinePhase = PipelinePhase.PENDING
    error: Optional[str] = None
    arch: Optional[str] = None
    guest_ips: list[str] = field(default_factory=list)
    network_reachable: bool = False
    web_reachable: bool = False
    qemu_pid: Optional[int] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    # Internal
    _process: Optional[subprocess.Popen] = field(default=None, repr=False)
    _output_lines: list[str] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def uptime(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def is_terminal(self) -> bool:
        return self.phase in (
            PipelinePhase.FAILED,
            PipelinePhase.STOPPED,
            PipelinePhase.TIMEOUT,
        )

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "status": "running" if self.phase == PipelinePhase.RUNNING else (
                "error" if self.phase in (PipelinePhase.FAILED, PipelinePhase.TIMEOUT) else
                "stopped" if self.phase == PipelinePhase.STOPPED else
                "starting"
            ),
            "phase": self.phase.value,
            "arch": self.arch,
            "guest_ips": self.guest_ips,
            "network_reachable": self.network_reachable,
            "web_reachable": self.web_reachable,
            "qemu_pid": self.qemu_pid,
            "uptime": round(self.uptime, 1),
            "error": self.error,
        }


class PipelineManager:
    """
    Manages FirmAE pipeline execution for a single session.

    Spawns run.sh, monitors output for phase transitions, discovers
    guest IPs and QEMU PIDs, and enforces timeouts.
    """

    def __init__(
        self,
        firmae_dir: str = "/opt/FirmAE",
        on_phase_change: Optional[Callable[[PipelineState, PipelinePhase], None]] = None,
    ):
        self.firmae_dir = Path(firmae_dir)
        self.on_phase_change = on_phase_change
        self._sessions: dict[str, PipelineState] = {}
        self._lock = threading.Lock()

    @property
    def sessions(self) -> dict[str, PipelineState]:
        return dict(self._sessions)

    def get_session(self, session_id: str) -> Optional[PipelineState]:
        return self._sessions.get(session_id)

    def start(
        self,
        session_id: str,
        firmware_path: str,
        brand: str = "unknown",
        timeout: int = 600,
    ) -> PipelineState:
        """Start a FirmAE pipeline run."""
        with self._lock:
            if session_id in self._sessions:
                existing = self._sessions[session_id]
                if not existing.is_terminal:
                    raise ValueError(f"Session {session_id} is already running")

            state = PipelineState(
                session_id=session_id,
                firmware_path=firmware_path,
                brand=brand,
                timeout=timeout,
            )
            self._sessions[session_id] = state

        # Launch the pipeline in a background thread
        thread = threading.Thread(
            target=self._run_pipeline,
            args=(state,),
            daemon=True,
            name=f"firmae-{session_id[:8]}",
        )
        thread.start()
        return state

    def stop(self, session_id: str) -> bool:
        """Stop a running pipeline session."""
        state = self._sessions.get(session_id)
        if state is None:
            return False

        if state.is_terminal:
            return True

        self._terminate_pipeline(state)
        self._set_phase(state, PipelinePhase.STOPPED)
        return True

    def _run_pipeline(self, state: PipelineState) -> None:
        """Execute the FirmAE pipeline (runs in background thread)."""
        state.start_time = time.time()
        self._set_phase(state, PipelinePhase.EXTRACTING)

        run_script = self.firmae_dir / "run.sh"
        if not run_script.exists():
            state.error = f"FirmAE run.sh not found at {run_script}"
            self._set_phase(state, PipelinePhase.FAILED)
            return

        # FirmAE's run.sh: ./run.sh -r <brand> <firmware_path>
        # -r flag = "run" mode (keep QEMU alive for interactive use)
        cmd = [
            "sudo", str(run_script),
            "-r", state.brand, state.firmware_path,
        ]

        logger.info(
            "Starting FirmAE pipeline: session=%s brand=%s firmware=%s timeout=%ds",
            state.session_id, state.brand, state.firmware_path, state.timeout,
        )

        try:
            env = os.environ.copy()
            env["FIRMAE_DIR"] = str(self.firmae_dir)
            env["FIRMWARE_DIR"] = str(self.firmae_dir / "images")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(self.firmae_dir),
                env=env,
                preexec_fn=os.setsid,  # New process group for clean termination
            )
            state._process = process

            # Start a timeout watchdog thread
            watchdog = threading.Thread(
                target=self._timeout_watchdog,
                args=(state,),
                daemon=True,
            )
            watchdog.start()

            # Read output line by line and parse for state transitions
            self._monitor_output(state, process)

            # Wait for process to complete
            exit_code = process.wait()
            state._process = None

            if state.phase == PipelinePhase.RUNNING:
                # Process exited while in RUNNING state — likely QEMU crashed
                if exit_code != 0 and not state.is_terminal:
                    state.error = f"FirmAE exited with code {exit_code}"
                    self._set_phase(state, PipelinePhase.FAILED)
            elif not state.is_terminal:
                if exit_code != 0:
                    state.error = f"Pipeline failed with exit code {exit_code}"
                    self._set_phase(state, PipelinePhase.FAILED)
                else:
                    # Completed but never reached RUNNING — check emulation failed
                    state.error = "Pipeline completed but emulation did not start"
                    self._set_phase(state, PipelinePhase.FAILED)

        except Exception as exc:
            logger.exception("Pipeline error: session=%s", state.session_id)
            state.error = str(exc)
            self._set_phase(state, PipelinePhase.FAILED)
        finally:
            state.end_time = time.time()

    def _monitor_output(self, state: PipelineState, process: subprocess.Popen) -> None:
        """Parse FirmAE stdout line-by-line for phase transitions and metadata."""
        assert process.stdout is not None

        for raw_line in process.stdout:
            if state.is_terminal:
                break

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            state._output_lines.append(line)

            if len(state._output_lines) > 5000:
                state._output_lines = state._output_lines[-2000:]

            logger.debug("[firmae:%s] %s", state.session_id[:8], line)

            # Detect phase transitions
            for pattern, phase in _PHASE_PATTERNS:
                if pattern.search(line):
                    if self._phase_order(phase) > self._phase_order(state.phase):
                        self._set_phase(state, phase)
                    break

            # Extract architecture
            arch_match = _ARCH_PATTERN.search(line)
            if arch_match and state.arch is None:
                state.arch = arch_match.group(2).lower()
                logger.info("Detected arch: %s (session=%s)", state.arch, state.session_id[:8])

            # Extract guest IP
            ip_match = _IP_PATTERN.search(line)
            if ip_match:
                ip = ip_match.group(1)
                if ip not in state.guest_ips and not ip.startswith("0.") and not ip.startswith("255."):
                    state.guest_ips.append(ip)
                    logger.info("Discovered guest IP: %s (session=%s)", ip, state.session_id[:8])

            # Detect network reachability from FirmAE's check output
            if re.search(r"network\s*(is\s*)?reachable|ping\s*ok|network.*success", line, re.IGNORECASE):
                state.network_reachable = True

            if re.search(r"web\s*(is\s*)?reachable|http.*ok|web.*success|web.*running", line, re.IGNORECASE):
                state.web_reachable = True

        # After output ends, try to discover QEMU PID and guest IPs from filesystem
        self._discover_from_filesystem(state)

    def _discover_from_filesystem(self, state: PipelineState) -> None:
        """Discover QEMU PID and guest IPs from FirmAE's filesystem state."""
        scratch_dir = self.firmae_dir / "scratch"

        # Find QEMU PID from process table
        try:
            result = subprocess.run(
                ["pgrep", "-f", "qemu-system"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                pids = result.stdout.strip().split("\n")
                if pids and pids[0]:
                    state.qemu_pid = int(pids[0])
                    logger.info("Found QEMU PID: %d (session=%s)", state.qemu_pid, state.session_id[:8])
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass

        # Discover guest IPs from FirmAE scratch directory
        if not state.guest_ips:
            for state_file in scratch_dir.glob("*/run.sh"):
                try:
                    content = state_file.read_text()
                    for match in _IP_GENERIC_PATTERN.finditer(content):
                        ip = match.group(1)
                        if (
                            ip not in state.guest_ips
                            and not ip.startswith("0.")
                            and not ip.startswith("255.")
                            and not ip.startswith("127.")
                            and ip != "0.0.0.0"
                        ):
                            state.guest_ips.append(ip)
                except OSError:
                    continue

    def _timeout_watchdog(self, state: PipelineState) -> None:
        """Kill the pipeline if it exceeds the timeout."""
        deadline = (state.start_time or time.time()) + state.timeout

        while not state.is_terminal:
            if time.time() > deadline:
                logger.warning(
                    "Pipeline timeout (%ds): session=%s phase=%s",
                    state.timeout, state.session_id[:8], state.phase.value,
                )
                state.error = f"Pipeline timed out after {state.timeout}s in phase '{state.phase.value}'"
                self._terminate_pipeline(state)
                self._set_phase(state, PipelinePhase.TIMEOUT)
                return
            time.sleep(2)

    def _terminate_pipeline(self, state: PipelineState) -> None:
        """SIGTERM -> SIGKILL cascade on the pipeline process and QEMU."""
        # Kill QEMU processes first
        try:
            subprocess.run(
                ["pkill", "-f", "qemu-system"],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Kill the pipeline process group
        process = state._process
        if process and process.poll() is None:
            try:
                pgid = os.getpgid(process.pid)
                os.killpg(pgid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(pgid, signal.SIGKILL)
                    process.wait(timeout=5)
            except (ProcessLookupError, OSError):
                pass

        state._process = None

        # Clean up TAP interfaces
        self._cleanup_network()

    def _cleanup_network(self) -> None:
        """Remove TAP interfaces and iptables rules created by FirmAE."""
        try:
            # Remove TAP interfaces matching FirmAE's naming pattern
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split("\n"):
                match = re.search(r"(\d+):\s+(tap\w+)", line)
                if match:
                    tap_name = match.group(2)
                    subprocess.run(
                        ["ip", "link", "delete", tap_name],
                        capture_output=True, timeout=5,
                    )
                    logger.info("Removed TAP interface: %s", tap_name)
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("TAP cleanup failed: %s", exc)

        try:
            # Flush FirmAE's iptables rules (FirmAE uses FORWARD chain)
            subprocess.run(
                ["iptables", "-F", "FORWARD"],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    def _set_phase(self, state: PipelineState, phase: PipelinePhase) -> None:
        """Update phase and fire callback."""
        old_phase = state.phase
        state.phase = phase
        logger.info(
            "Phase transition: %s -> %s (session=%s)",
            old_phase.value, phase.value, state.session_id[:8],
        )
        if self.on_phase_change:
            try:
                self.on_phase_change(state, phase)
            except Exception:
                logger.exception("Phase change callback error")

    @staticmethod
    def _phase_order(phase: PipelinePhase) -> int:
        """Numeric order for phases — only allow forward transitions."""
        order = {
            PipelinePhase.PENDING: 0,
            PipelinePhase.EXTRACTING: 1,
            PipelinePhase.DETECTING_ARCH: 2,
            PipelinePhase.PREPARING_IMAGE: 3,
            PipelinePhase.BOOTING: 4,
            PipelinePhase.CHECKING: 5,
            PipelinePhase.RUNNING: 6,
            PipelinePhase.FAILED: 99,
            PipelinePhase.STOPPED: 99,
            PipelinePhase.TIMEOUT: 99,
        }
        return order.get(phase, -1)

    def get_output(self, session_id: str, last_n: int = 100) -> list[str]:
        """Get the last N output lines for a session."""
        state = self._sessions.get(session_id)
        if state is None:
            return []
        return state._output_lines[-last_n:]
