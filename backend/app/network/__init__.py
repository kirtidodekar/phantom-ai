"""
Sentinel AI - real-time network telemetry subsystem.

Strictly additive: nothing here replaces the replay engine, the ML models, the
correlator or the trajectory scorer. Network observations are converted into
standard Sentinel telemetry and pushed through the SAME detection pipeline the
rest of the platform already uses.

Modules
    config       environment-driven configuration
    models       data records (packet metadata, flows, windows, threats)
    capture      Scapy-backed background capture + capability probing
    tracker      live per-IP and per-connection statistics
    aggregator   rolling time windows -> traffic features + baseline
    adapter      traffic features -> existing Sentinel feature schema
    detection    network-specific deterministic rules
    persistence  network tables, indexes, retention
    monitor      orchestrating service (start / stop / status)
    routes       FastAPI router under /api/network
"""

from .config import NetworkConfig, get_network_config  # noqa: F401
from .monitor import NetworkMonitorService  # noqa: F401
