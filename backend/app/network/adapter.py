"""
Feature adapter: network telemetry -> existing Sentinel feature schema.

WHY THIS MODULE EXISTS
The trained Random Forest and Isolation Forest expect the platform's ordered
12-dimensional vector. Packet headers cannot supply all 12 dimensions. Rather
than silently redefining what a feature MEANS (which would invalidate the
trained models), this adapter maps only what network telemetry can honestly
provide and marks the rest as NOT OBSERVED with neutral baseline values.

PROVENANCE - derived from real network telemetry (7 of 12)
    packet_size             mean packet size in the window
    protocol_type           dominant L4 protocol
    request_rate            connections per second
    session_duration        mean flow duration
    distinct_ports_touched  max port fan-out for a single source (port scan)
    outbound_bytes_ratio    egress/ingress ratio (C2 beaconing / exfil)
    off_hours_access        observation time vs business hours

PROVENANCE - NOT observable from packet headers (5 of 12)
    payload_pattern_score   needs application-layer content
    login_failure_rate      needs identity telemetry
    is_suspicious_process   needs endpoint telemetry
    privilege_level         needs identity/endpoint telemetry
    url_entropy             needs DNS/HTTP host telemetry

These five keep the SAME benign defaults the extractor already applies to
legacy events, so a network-only verdict is a network-confidence verdict and
never a fabricated claim of full-spectrum visibility. When another layer
reports on the same entity, the correlator supplies the real values.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import WindowFeatures

# Protocol encoding must match ml/models.py exactly: 0 TCP, 1 UDP, 2 ICMP, 3 HTTP
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000}

NETWORK_DERIVED_FEATURES = [
    "packet_size",
    "protocol_type",
    "request_rate",
    "session_duration",
    "distinct_ports_touched",
    "outbound_bytes_ratio",
    "off_hours_access",
]

NOT_OBSERVABLE_FROM_PACKETS = [
    "payload_pattern_score",
    "login_failure_rate",
    "is_suspicious_process",
    "privilege_level",
    "url_entropy",
]


def _dominant_protocol(distribution: Dict[str, float], ports: Optional[List[int]] = None) -> str:
    if ports and any(p in _HTTP_PORTS for p in ports if p is not None):
        return "HTTP"
    if not distribution:
        return "TCP"
    return max(distribution.items(), key=lambda kv: kv[1])[0]


def build_sentinel_detail(
    features: WindowFeatures,
    source_ip: str,
    destination_ip: Optional[str] = None,
    mean_session_duration: float = 0.0,
    observed_ports: Optional[List[int]] = None,
    port_fan_out: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Produces the `detail` dictionary consumed by the EXISTING pipeline
    (normalizer -> ThreatDetectionModels.extract_features_from_event -> RF/IF).

    The returned dict intentionally uses the platform's established key names
    so no change to the ML feature extractor is required.
    """
    protocol = _dominant_protocol(features.protocol_distribution, observed_ports)
    hour = datetime.now(timezone.utc).astimezone().hour

    detail: Dict[str, Any] = {
        # ---- observed from real packets ----
        "packet_size": float(features.average_packet_size or 0.0),
        "protocol": protocol,
        "request_rate": float(features.connections_per_second or 0.0),
        "session_duration": float(mean_session_duration or 0.0),
        "distinct_ports_touched": float(port_fan_out if port_fan_out is not None
                                        else features.max_ports_single_source or 1),
        "outbound_bytes_ratio": float(features.outbound_bytes_ratio or 1.0),
        "off_hours_access": 1 if not (7 <= hour < 19) else 0,

        # ---- network context (not model features, used by rules/UI) ----
        "src_ip": source_ip,
        "dest_ip": destination_ip or "",
        "packets_per_second": float(features.packets_per_second or 0.0),
        "bytes_per_second": float(features.bytes_per_second or 0.0),
        "tcp_syn_rate": float(features.tcp_syn_rate or 0.0),
        "failed_connections": int(features.failed_connections or 0),
        "traffic_burst_rate": float(features.traffic_burst_rate or 1.0),
        "unique_destination_ips": int(features.unique_destination_ips or 0),
        "unique_ports": int(features.unique_ports or 0),
        "window_seconds": int(features.window_seconds),
        "protocol_distribution": dict(features.protocol_distribution or {}),

        # ---- provenance, so the UI can be explicit about visibility ----
        "telemetry_source": "live_network_capture",
        "feature_provenance": {
            "observed": list(NETWORK_DERIVED_FEATURES),
            "not_observed": list(NOT_OBSERVABLE_FROM_PACKETS),
        },
    }
    return detail


def build_raw_telemetry(
    detail: Dict[str, Any],
    entity_id: str,
    action: str = "network_flow_window",
    source_confidence: str = "high",
) -> Dict[str, Any]:
    """
    Wraps the adapted detail into the raw telemetry envelope accepted by
    `CrossLayerCorrelator.process_raw_telemetry`.

    `is_simulated=False` is what distinguishes LIVE capture from replay data
    everywhere downstream, including the dashboard mode badge.
    """
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "layer": "network",
        "entity_id": entity_id,
        "action": action,
        "detail": detail,
        "source_confidence": source_confidence,
        "is_simulated": False,
    }
