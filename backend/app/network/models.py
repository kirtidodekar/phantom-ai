"""Immutable data records for the network telemetry subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class PacketMetadata:
    """
    Header-derived metadata for a single observed packet.

    PRIVACY: payload bytes are never captured or stored. Only the header
    fields below plus the observed length are retained.
    """

    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_size: int
    tcp_flags: str
    interface: str
    direction: str          # inbound | outbound | internal | unknown
    connection_id: str
    is_simulated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectionRecord:
    """An observed flow keyed by its 5-tuple hash."""

    connection_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def failed(self) -> bool:
        """A flow reset without completing is treated as a failed connection."""
        return self.rst_count > 0 and self.packet_count <= 4

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["duration_seconds"] = round(self.duration_seconds, 3)
        data["failed"] = self.failed
        return data


@dataclass
class IpStat:
    """Live rolling statistics for one observed IP address."""

    ip: str
    role: str = "source"          # source | destination
    packet_count: int = 0
    byte_count: int = 0
    connection_count: int = 0
    unique_destinations: set = field(default_factory=set)
    unique_destination_ports: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    syn_count: int = 0
    failed_connections: int = 0
    outbound_bytes: int = 0
    inbound_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    threat_score: float = 0.0
    risk_level: str = "LOW"

    @property
    def traffic_rate(self) -> float:
        """Packets per second across the observation lifetime."""
        span = max(1.0, self.last_seen - self.first_seen)
        return round(self.packet_count / span, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "role": self.role,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "connection_count": self.connection_count,
            "unique_destinations": len(self.unique_destinations),
            "unique_destination_ports": len(self.unique_destination_ports),
            "protocols": sorted(self.protocols),
            "syn_count": self.syn_count,
            "failed_connections": self.failed_connections,
            "traffic_rate": self.traffic_rate,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "threat_score": round(self.threat_score, 1),
            "risk_level": self.risk_level,
        }


@dataclass
class WindowFeatures:
    """Aggregated traffic features for one rolling time window."""

    window_seconds: int
    generated_at: str
    packet_count: int = 0
    byte_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    connections_per_second: float = 0.0
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    unique_ports: int = 0
    tcp_syn_rate: float = 0.0
    failed_connections: int = 0
    connection_frequency: float = 0.0
    traffic_burst_rate: float = 1.0
    average_packet_size: float = 0.0
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    top_source_ip: Optional[str] = None
    max_ports_single_source: int = 0
    outbound_bytes_ratio: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkThreat:
    """A network detection produced from aggregated evidence."""

    threat_id: str
    detected_at: str
    threat_type: str
    source_ip: str
    destination_ip: Optional[str]
    confidence: float
    anomaly_score: float
    threat_score: float
    risk_level: str
    mitre_id: Optional[str]
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    description: str
    incident_id: Optional[str] = None
    detection_source: str = "hybrid_ml_rule"
    recommended_action: str = "MONITOR"
    evidence: Dict[str, Any] = field(default_factory=dict)
    is_simulated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
