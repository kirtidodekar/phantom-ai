"""Configuration for the endpoint and application sensors."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(dotenv_path=_BACKEND_DIR / ".env", override=False)


def _as_bool(value, default=False):
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _as_int(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value, default):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def default_entity() -> str:
    """
    Entity identity for locally observed telemetry.

    Using one stable entity for this host is what allows endpoint, application
    and network evidence to converge on a SINGLE incident.
    """
    configured = (os.getenv("NETWORK_LOCAL_ENTITY") or "").strip()
    if configured:
        return configured
    try:
        host = socket.gethostname() or "localhost"
    except Exception:
        host = "localhost"
    user = os.getenv("USERNAME") or os.getenv("USER") or "local"
    return f"user:{user} / host:{host}"


@dataclass(frozen=True)
class SensorConfig:
    # --- endpoint sensor ---
    endpoint_enabled: bool = False
    endpoint_interval_seconds: float = 5.0
    suspicious_parents: List[str] = field(default_factory=lambda: [
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "winword.exe", "excel.exe", "outlook.exe", "w3wp.exe", "explorer.exe",
        "bash", "sh", "zsh",
    ])
    suspicious_children: List[str] = field(default_factory=lambda: [
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "certutil.exe", "bitsadmin.exe", "vssadmin.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "whoami.exe", "net.exe", "nc", "ncat",
    ])
    endpoint_ignore: List[str] = field(default_factory=lambda: [
        "python.exe", "node.exe", "code.exe", "chrome.exe", "msedge.exe",
    ])

    # --- application sensor ---
    application_enabled: bool = False
    access_log_paths: List[str] = field(default_factory=list)
    application_interval_seconds: float = 5.0
    application_log_format: str = "auto"      # auto | combined | json
    app_error_rate_threshold: float = 0.4

    # --- shared ---
    local_entity: str = ""

    @property
    def entity(self) -> str:
        return self.local_entity or default_entity()


def get_sensor_config() -> SensorConfig:
    raw_paths = os.getenv("APPLICATION_LOG_PATHS", "") or ""
    paths = [p.strip() for p in raw_paths.split(os.pathsep if os.pathsep in raw_paths else ",") if p.strip()]

    return SensorConfig(
        endpoint_enabled=_as_bool(os.getenv("ENDPOINT_SENSOR_ENABLED"), False),
        endpoint_interval_seconds=_as_float(os.getenv("ENDPOINT_SENSOR_INTERVAL"), 5.0),
        application_enabled=_as_bool(os.getenv("APPLICATION_SENSOR_ENABLED"), False),
        access_log_paths=paths,
        application_interval_seconds=_as_float(os.getenv("APPLICATION_SENSOR_INTERVAL"), 5.0),
        application_log_format=(os.getenv("APPLICATION_LOG_FORMAT") or "auto").strip().lower(),
        app_error_rate_threshold=_as_float(os.getenv("APP_ERROR_RATE_THRESHOLD"), 0.4),
        local_entity=(os.getenv("NETWORK_LOCAL_ENTITY") or "").strip(),
    )
