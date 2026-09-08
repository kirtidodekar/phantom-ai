"""Environment-driven configuration for the network monitoring subsystem."""

from __future__ import annotations

import os
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


@dataclass(frozen=True)
class NetworkConfig:
    """Runtime configuration. Thresholds are tunable without code changes."""

    enabled: bool = False
    interface: str = "auto"
    capture_filter: str = ""
    queue_size: int = 20000

    retention_minutes: int = 60
    max_packets_in_memory: int = 2000

    threat_threshold: float = 70.0
    auto_block: bool = False

    windows: List[int] = field(default_factory=lambda: [1, 5, 30, 60])
    detection_interval_seconds: float = 5.0

    port_scan_unique_ports: int = 15
    port_scan_window_seconds: int = 30
    dos_packets_per_second: float = 500.0
    dos_connections_per_second: float = 100.0
    burst_multiplier: float = 5.0
    syn_flood_rate: float = 100.0
    baseline_min_samples: int = 6

    local_entity_hint: str = ""

    @property
    def detection_window_seconds(self) -> int:
        return max(self.windows) if self.windows else 60


def get_network_config() -> NetworkConfig:
    """Builds configuration from environment variables on each call."""
    raw_windows = os.getenv("NETWORK_AGGREGATION_WINDOWS", "1,5,30,60")
    windows = []
    for part in raw_windows.split(","):
        value = _as_int(part, 0)
        if value > 0:
            windows.append(value)
    if not windows:
        windows = [1, 5, 30, 60]

    return NetworkConfig(
        enabled=_as_bool(os.getenv("NETWORK_MONITOR_ENABLED"), False),
        interface=(os.getenv("NETWORK_INTERFACE") or "auto").strip() or "auto",
        capture_filter=(os.getenv("PACKET_CAPTURE_FILTER") or "").strip(),
        queue_size=_as_int(os.getenv("PACKET_QUEUE_SIZE"), 20000),
        retention_minutes=_as_int(os.getenv("PACKET_RETENTION_MINUTES"), 60),
        max_packets_in_memory=_as_int(os.getenv("PACKET_MEMORY_BUFFER"), 2000),
        threat_threshold=_as_float(os.getenv("THREAT_THRESHOLD"), 70.0),
        auto_block=_as_bool(os.getenv("AUTO_BLOCK"), False),
        windows=sorted(set(windows)),
        detection_interval_seconds=_as_float(os.getenv("NETWORK_DETECTION_INTERVAL"), 5.0),
        port_scan_unique_ports=_as_int(os.getenv("PORT_SCAN_UNIQUE_PORTS"), 15),
        port_scan_window_seconds=_as_int(os.getenv("PORT_SCAN_WINDOW_SECONDS"), 30),
        dos_packets_per_second=_as_float(os.getenv("DOS_PACKETS_PER_SECOND"), 500.0),
        dos_connections_per_second=_as_float(os.getenv("DOS_CONNECTIONS_PER_SECOND"), 100.0),
        burst_multiplier=_as_float(os.getenv("TRAFFIC_BURST_MULTIPLIER"), 5.0),
        syn_flood_rate=_as_float(os.getenv("SYN_FLOOD_RATE"), 100.0),
        baseline_min_samples=_as_int(os.getenv("BASELINE_MIN_SAMPLES"), 6),
        local_entity_hint=(os.getenv("NETWORK_LOCAL_ENTITY") or "").strip(),
    )
