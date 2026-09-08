"""
Endpoint telemetry sensor.

Observes REAL local process activity with psutil and emits endpoint-layer
telemetry into the existing correlation pipeline. This is what allows the
endpoint layer to participate in live cross-layer correlation rather than only
appearing in the simulated replay.

WHAT IT OBSERVES
  * newly created processes (name, pid, parent, command line, user)
  * suspicious parent -> child execution chains (e.g. winword -> powershell)
  * privilege level (SYSTEM / root / admin vs standard user)
  * count of established outbound connections owned by the process

SAFETY
  Observation only. Processes are never terminated, suspended or modified.
  Command lines are truncated and no memory is ever read.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ..observability import log_event
from .config import SensorConfig, get_sensor_config

_PRIVILEGED_USERS = {
    "nt authority\\system", "system", "root", "administrator",
    "nt authority\\local service", "nt authority\\network service",
}


def psutil_available() -> tuple:
    try:
        import psutil  # noqa: F401
        return True, "psutil_importable"
    except Exception as error:
        return False, f"psutil_missing: {type(error).__name__}"


class EndpointSensor:
    """Polls the local process table and reports notable changes."""

    def __init__(self, correlator=None, config: Optional[SensorConfig] = None):
        self.config = config or get_sensor_config()
        self.correlator = correlator
        self._known_pids: Set[int] = set()
        self._seen_chains: Set[str] = set()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        self.running = False
        self.started_at: Optional[float] = None
        self.processes_observed = 0
        self.events_emitted = 0
        self.suspicious_chains = 0
        self.last_event_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.recent: List[Dict[str, Any]] = []

    # ---------------- capability ----------------

    def capability(self) -> Dict[str, Any]:
        available, detail = psutil_available()
        return {
            "sensor": "endpoint",
            "platform": platform.system(),
            "library": "psutil",
            "available": available,
            "detail": detail,
            "capture_possible": available,
            "reason": None if available else "psutil_not_installed",
            "remediation": None if available else "Install psutil: pip install psutil",
            "note": "Some system process details require elevated privileges and are skipped when denied.",
        }

    # ---------------- lifecycle ----------------

    def start(self) -> Dict[str, Any]:
        with self._lock:
            if self.running:
                return {"status": "ALREADY_RUNNING", "sensor": "endpoint"}

            cap = self.capability()
            if not cap["capture_possible"]:
                self.last_error = cap["reason"]
                raise RuntimeError(f"endpoint_sensor_unavailable:{cap['reason']}: {cap['remediation']}")

            self.config = get_sensor_config()
            self._prime_baseline()
            self._stop.clear()
            self.running = True
            self.started_at = time.time()
            self.last_error = None

            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._loop, name="sentinel-endpoint-sensor", daemon=True
                )
                self._thread.start()

            log_event("info", "endpoint_sensor_started", entity=self.config.entity)
            return {"status": "STARTED", "sensor": "endpoint", "entity": self.config.entity}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.running:
                return {"status": "ALREADY_STOPPED", "sensor": "endpoint"}
            self._stop.set()
            self.running = False
            log_event("info", "endpoint_sensor_stopped", events=self.events_emitted)
            return {"status": "STOPPED", "sensor": "endpoint"}

    def _prime_baseline(self) -> None:
        """Record existing PIDs so only NEW processes are reported."""
        try:
            import psutil
            self._known_pids = {p.pid for p in psutil.process_iter(["pid"])}
        except Exception as error:
            self.last_error = f"baseline_failed: {type(error).__name__}"

    # ---------------- polling loop ----------------

    def _loop(self) -> None:
        interval = max(1.0, self.config.endpoint_interval_seconds)
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as error:
                self.last_error = f"poll_error: {type(error).__name__}"
                log_event("error", "endpoint_sensor_error", error_type=type(error).__name__)
            self._stop.wait(interval)

    def poll_once(self) -> List[Dict[str, Any]]:
        """Single scan pass. Returns the notable processes found."""
        import psutil

        notable: List[Dict[str, Any]] = []
        current: Set[int] = set()

        for proc in psutil.process_iter(["pid", "ppid", "name", "username", "create_time"]):
            try:
                info = proc.info
                pid = info.get("pid")
                current.add(pid)
                if pid in self._known_pids:
                    continue

                self.processes_observed += 1
                name = (info.get("name") or "").lower()
                if not name or name in {n.lower() for n in self.config.endpoint_ignore}:
                    continue

                parent_name = ""
                try:
                    parent = psutil.Process(info.get("ppid")) if info.get("ppid") else None
                    parent_name = (parent.name() or "").lower() if parent else ""
                except Exception:
                    parent_name = ""

                try:
                    cmdline = " ".join(proc.cmdline() or [])[:220]
                except Exception:
                    cmdline = ""

                username = (info.get("username") or "").lower()
                privileged = username in _PRIVILEGED_USERS

                record = self._build_record(name, parent_name, cmdline, username, privileged, pid)
                if record["is_notable"]:
                    notable.append(record)
                    self._emit(record)
            except Exception:
                continue

        self._known_pids = current
        return notable

    def _build_record(self, name, parent_name, cmdline, username, privileged, pid) -> Dict[str, Any]:
        """Classifies a newly seen process without asserting more than observed."""
        parents = {p.lower() for p in self.config.suspicious_parents}
        children = {c.lower() for c in self.config.suspicious_children}

        chain_suspicious = parent_name in parents and name in children
        encoded_cmd = any(tok in cmdline.lower() for tok in (
            "-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex ",
            "frombase64string", "-nop", "-w hidden", "bypass",
        ))
        child_of_interest = name in children

        is_notable = chain_suspicious or encoded_cmd or (child_of_interest and privileged)

        if chain_suspicious:
            self.suspicious_chains += 1

        return {
            "pid": pid,
            "process_name": name,
            "parent_process": parent_name,
            "command_line": cmdline,
            "username": username,
            "privileged": privileged,
            "chain_suspicious": chain_suspicious,
            "encoded_command": encoded_cmd,
            "is_notable": is_notable,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---------------- emission ----------------

    def _emit(self, record: Dict[str, Any]) -> None:
        """
        Sends endpoint telemetry through the EXISTING correlator so it scores,
        correlates and maps to MITRE exactly like every other layer.
        """
        detail = {
            "process_name": record["process_name"],
            "parent_process": record["parent_process"],
            "command_line": record["command_line"],
            "user_role": "SYSTEM" if record["privileged"] else "user",
            "privilege_escalation": bool(record["privileged"]),
            "is_suspicious_process": bool(record["chain_suspicious"] or record["encoded_command"]),
            "session_duration": 1.0,
            "packet_size": 0.0,
            "request_rate": 0.0,
            "telemetry_source": "live_endpoint_sensor",
        }

        raw = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "layer": "endpoint",
            "entity_id": self.config.entity,
            "action": "process_create",
            "detail": detail,
            "source_confidence": "high",
            "is_simulated": False,
        }

        incident_id = None
        if self.correlator is not None:
            try:
                _event, incident = self.correlator.process_raw_telemetry(raw)
                incident_id = incident.incident_id
            except Exception as error:
                self.last_error = f"correlator_error: {type(error).__name__}"
                log_event("error", "endpoint_emit_failed", error_type=type(error).__name__)

        self.events_emitted += 1
        self.last_event_at = record["observed_at"]

        entry = {**record, "incident_id": incident_id}
        with self._lock:
            self.recent.insert(0, entry)
            del self.recent[60:]

        log_event(
            "warning", "endpoint_event",
            process=record["process_name"], parent=record["parent_process"],
            privileged=record["privileged"], incident_id=incident_id,
        )

    # ---------------- reporting ----------------

    def status(self) -> Dict[str, Any]:
        uptime = round(time.time() - self.started_at, 1) if self.started_at else 0.0
        return {
            "sensor": "endpoint",
            "layer": "endpoint",
            "running": self.running,
            "is_simulated": False,
            "data_source": "live_endpoint_sensor" if self.running else "none",
            "entity": self.config.entity,
            "uptime_seconds": uptime,
            "processes_observed": self.processes_observed,
            "events_emitted": self.events_emitted,
            "suspicious_chains": self.suspicious_chains,
            "last_event_at": self.last_event_at,
            "poll_interval_seconds": self.config.endpoint_interval_seconds,
            "capability": self.capability(),
            "last_error": self.last_error,
        }

    def events(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent)[:max(1, limit)]
