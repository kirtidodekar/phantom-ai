"""
Application telemetry sensor.

Tails REAL web access logs and emits application-layer telemetry into the
existing correlation pipeline. This is what makes content-dependent verdicts
(SQL injection, XSS, authorization probing) possible on live data - packet
headers alone can never establish them.

SUPPORTED FORMATS
  combined / CLF   standard Nginx & Apache access logs
  json             one JSON object per line (Traefik, Caddy, structured logs)
  auto             sniffed per line

WHAT IT DERIVES
  payload_pattern_score   SQL/XSS signature density in the request
  url_entropy             randomness of the requested path/host
  status_code, error_rate authorization probing and exploitation signals
  request_rate            requests per second over the poll window

SAFETY
  Read-only. Log files are never modified or truncated. Only the request line,
  status and derived scores are retained - no request bodies, cookies or
  credentials are stored.
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from collections import Counter
from urllib.parse import unquote_plus
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..observability import log_event
from .config import SensorConfig, get_sensor_config

# Combined Log Format: host ident auth [time] "METHOD path proto" status bytes ...
_CLF_RE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
)

_SQLI_PATTERNS = [
    r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r"--\s", r";\s*drop\s+table",
    r"select\s+.+\s+from", r"information_schema", r"sleep\s*\(", r"benchmark\s*\(",
    r"waitfor\s+delay", r"xp_cmdshell", r"0x[0-9a-f]{8,}",
]
_XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"<iframe",
    r"document\.cookie", r"alert\s*\(", r"<svg[^>]*onload", r"eval\s*\(",
]
_TRAVERSAL_PATTERNS = [r"\.\./\.\./", r"%2e%2e%2f", r"/etc/passwd", r"boot\.ini", r"win\.ini"]


def _shannon_entropy(text: str) -> float:
    """Normalised Shannon entropy (0..1) - high values suggest generated strings."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(min(1.0, entropy / 6.0), 4)


def score_payload(text: str) -> Dict[str, Any]:
    """
    Signature density for the request. Returns score plus matched families.

    The request is URL-DECODED (twice, to catch double encoding) before matching.
    Attackers percent-encode payloads as a matter of course, so scanning the raw
    log line would miss almost every real injection attempt.
    """
    raw = text or ""
    decoded = raw
    for _ in range(2):
        try:
            nxt = unquote_plus(decoded)
        except Exception:
            break
        if nxt == decoded:
            break
        decoded = nxt

    # Match against both forms so neither encoded nor plain payloads are missed.
    lowered = f"{raw} {decoded}".lower()
    families: List[str] = []
    hits = 0

    for name, patterns in (("SQL Injection", _SQLI_PATTERNS),
                           ("XSS", _XSS_PATTERNS),
                           ("Path Traversal", _TRAVERSAL_PATTERNS)):
        matched = sum(1 for p in patterns if re.search(p, lowered))
        if matched:
            families.append(name)
            hits += matched

    score = min(1.0, hits * 0.34)
    return {"payload_pattern_score": round(score, 4), "families": families, "signature_hits": hits}


class LogTail:
    """Follows a single file, tolerating rotation and truncation."""

    def __init__(self, path: str):
        self.path = path
        self._offset = 0
        self._inode = None
        self._primed = False

    def read_new_lines(self, max_lines: int = 500) -> List[str]:
        try:
            stat = os.stat(self.path)
        except OSError:
            return []

        inode = getattr(stat, "st_ino", None)
        if self._inode is not None and inode != self._inode:
            self._offset = 0            # rotated
        self._inode = inode

        if stat.st_size < self._offset:
            self._offset = 0            # truncated

        if not self._primed:
            # Start at the end so historical noise is not replayed as live.
            self._offset = stat.st_size
            self._primed = True
            return []

        lines: List[str] = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                for _ in range(max_lines):
                    line = handle.readline()
                    if not line:
                        break
                    lines.append(line.rstrip("\n"))
                self._offset = handle.tell()
        except OSError:
            return []
        return lines


class ApplicationSensor:
    """Parses access-log lines into application-layer Sentinel telemetry."""

    def __init__(self, correlator=None, config: Optional[SensorConfig] = None):
        self.config = config or get_sensor_config()
        self.correlator = correlator
        self._tails: Dict[str, LogTail] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        self.running = False
        self.started_at: Optional[float] = None
        self.lines_read = 0
        self.requests_parsed = 0
        self.events_emitted = 0
        self.signature_hits = 0
        self.last_event_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.recent: List[Dict[str, Any]] = []

    # ---------------- capability ----------------

    def capability(self) -> Dict[str, Any]:
        configured = list(self.config.access_log_paths)
        readable = [p for p in configured if os.path.isfile(p) and os.access(p, os.R_OK)]
        missing = [p for p in configured if p not in readable]

        if not configured:
            reason, remediation = "no_log_paths_configured", (
                "Set APPLICATION_LOG_PATHS to one or more access log files "
                "(comma separated), e.g. C:\\nginx\\logs\\access.log"
            )
        elif not readable:
            reason, remediation = "log_paths_unreadable", (
                f"Configured paths not readable: {', '.join(missing[:3])}"
            )
        else:
            reason, remediation = None, None

        return {
            "sensor": "application",
            "configured_paths": configured,
            "readable_paths": readable,
            "unreadable_paths": missing,
            "capture_possible": bool(readable),
            "reason": reason,
            "remediation": remediation,
        }

    # ---------------- lifecycle ----------------

    def start(self) -> Dict[str, Any]:
        with self._lock:
            if self.running:
                return {"status": "ALREADY_RUNNING", "sensor": "application"}

            self.config = get_sensor_config()
            cap = self.capability()
            if not cap["capture_possible"]:
                self.last_error = cap["reason"]
                raise RuntimeError(f"application_sensor_unavailable:{cap['reason']}: {cap['remediation']}")

            self._tails = {p: LogTail(p) for p in cap["readable_paths"]}
            for tail in self._tails.values():
                tail.read_new_lines()     # prime to end-of-file

            self._stop.clear()
            self.running = True
            self.started_at = time.time()
            self.last_error = None

            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=self._loop, name="sentinel-application-sensor", daemon=True
                )
                self._thread.start()

            log_event("info", "application_sensor_started", paths=len(self._tails))
            return {"status": "STARTED", "sensor": "application", "paths": cap["readable_paths"]}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.running:
                return {"status": "ALREADY_STOPPED", "sensor": "application"}
            self._stop.set()
            self.running = False
            log_event("info", "application_sensor_stopped", events=self.events_emitted)
            return {"status": "STOPPED", "sensor": "application"}

    # ---------------- parsing ----------------

    @staticmethod
    def parse_line(line: str, fmt: str = "auto") -> Optional[Dict[str, Any]]:
        """Parses one access-log line into a normalized request record."""
        if not line or not line.strip():
            return None

        stripped = line.strip()
        if fmt in ("auto", "json") and stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                path = obj.get("path") or obj.get("url") or obj.get("request") or obj.get("uri") or ""
                return {
                    "client_ip": str(obj.get("remote_addr") or obj.get("client_ip") or obj.get("ip") or ""),
                    "method": str(obj.get("method") or obj.get("request_method") or "GET").upper(),
                    "path": str(path),
                    "status": int(obj.get("status") or obj.get("status_code") or 0),
                    "user_agent": str(obj.get("user_agent") or obj.get("http_user_agent") or "")[:160],
                }
            except (ValueError, TypeError):
                return None

        match = _CLF_RE.match(stripped)
        if match:
            return {
                "client_ip": match.group("host"),
                "method": match.group("method").upper(),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "user_agent": "",
            }
        return None

    # ---------------- polling loop ----------------

    def _loop(self) -> None:
        interval = max(1.0, self.config.application_interval_seconds)
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as error:
                self.last_error = f"poll_error: {type(error).__name__}"
                log_event("error", "application_sensor_error", error_type=type(error).__name__)
            self._stop.wait(interval)

    def poll_once(self) -> List[Dict[str, Any]]:
        """Reads new log lines, aggregates them, and emits notable evidence."""
        window = max(1.0, self.config.application_interval_seconds)
        requests: List[Dict[str, Any]] = []

        for path, tail in list(self._tails.items()):
            for line in tail.read_new_lines():
                self.lines_read += 1
                parsed = self.parse_line(line, self.config.application_log_format)
                if not parsed:
                    continue
                self.requests_parsed += 1
                scored = score_payload(f"{parsed['path']} {parsed.get('user_agent','')}")
                parsed.update(scored)
                parsed["url_entropy"] = _shannon_entropy(parsed["path"])
                parsed["source_file"] = os.path.basename(path)
                requests.append(parsed)

        if not requests:
            return []

        # Aggregate the window, then emit per notable client IP.
        by_client: Dict[str, List[Dict[str, Any]]] = {}
        for req in requests:
            by_client.setdefault(req["client_ip"] or "unknown", []).append(req)

        emitted: List[Dict[str, Any]] = []
        for client_ip, group in by_client.items():
            worst = max(group, key=lambda r: r["payload_pattern_score"])
            errors = [r for r in group if r["status"] >= 400]
            auth_errors = [r for r in group if r["status"] in (401, 403)]
            error_rate = round(len(errors) / len(group), 4)

            notable = (
                worst["payload_pattern_score"] >= 0.3
                or error_rate >= self.config.app_error_rate_threshold
                or len(auth_errors) >= 3
            )
            if not notable:
                continue

            self.signature_hits += worst.get("signature_hits", 0)
            record = self._emit(client_ip, group, worst, error_rate, auth_errors, window)
            emitted.append(record)

        return emitted

    # ---------------- emission ----------------

    def _emit(self, client_ip, group, worst, error_rate, auth_errors, window) -> Dict[str, Any]:
        """Feeds application evidence into the EXISTING correlator."""
        status_code = auth_errors[0]["status"] if auth_errors else worst["status"]

        detail = {
            "url": worst["path"][:220],
            "payload": worst["path"][:220],
            "http_method": worst["method"],
            "status_code": status_code,
            "error_rate": error_rate,
            "payload_pattern_score": worst["payload_pattern_score"],
            "url_entropy": worst["url_entropy"],
            "request_rate": round(len(group) / window, 2),
            "packet_size": 0.0,
            "session_duration": round(window, 2),
            "src_ip": client_ip,
            "signature_families": worst.get("families", []),
            "telemetry_source": "live_application_sensor",
        }

        raw = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "layer": "application",
            "entity_id": self.config.entity,
            "action": "http_request",
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
                log_event("error", "application_emit_failed", error_type=type(error).__name__)

        self.events_emitted += 1
        self.last_event_at = datetime.now(timezone.utc).isoformat()

        record = {
            "client_ip": client_ip,
            "path": worst["path"][:160],
            "method": worst["method"],
            "status": status_code,
            "requests_in_window": len(group),
            "error_rate": error_rate,
            "payload_pattern_score": worst["payload_pattern_score"],
            "url_entropy": worst["url_entropy"],
            "families": worst.get("families", []),
            "incident_id": incident_id,
            "observed_at": self.last_event_at,
        }
        with self._lock:
            self.recent.insert(0, record)
            del self.recent[60:]

        log_event(
            "warning", "application_event",
            client_ip=client_ip, families=",".join(worst.get("families", [])) or "none",
            error_rate=error_rate, incident_id=incident_id,
        )
        return record

    # ---------------- reporting ----------------

    def status(self) -> Dict[str, Any]:
        uptime = round(time.time() - self.started_at, 1) if self.started_at else 0.0
        return {
            "sensor": "application",
            "layer": "application",
            "running": self.running,
            "is_simulated": False,
            "data_source": "live_application_sensor" if self.running else "none",
            "entity": self.config.entity,
            "uptime_seconds": uptime,
            "lines_read": self.lines_read,
            "requests_parsed": self.requests_parsed,
            "events_emitted": self.events_emitted,
            "signature_hits": self.signature_hits,
            "last_event_at": self.last_event_at,
            "poll_interval_seconds": self.config.application_interval_seconds,
            "capability": self.capability(),
            "last_error": self.last_error,
        }

    def events(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent)[:max(1, limit)]
