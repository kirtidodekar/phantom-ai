"""
Live per-IP and per-connection tracking.

Structures are O(1) per packet and pruned periodically so continuous
monitoring cannot grow memory without bound.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from .models import ConnectionRecord, IpStat, PacketMetadata


def risk_level_for(score: float) -> str:
    """Same thresholds the platform trajectory engine uses."""
    if score < 30.0:
        return "LOW"
    if score < 60.0:
        return "MEDIUM"
    if score < 80.0:
        return "HIGH"
    return "CRITICAL"


class NetworkTracker:
    """Maintains rolling statistics for observed IPs and flows."""

    def __init__(self, max_ips: int = 5000, max_connections: int = 20000):
        self._lock = threading.Lock()
        self.sources: Dict[str, IpStat] = {}
        self.destinations: Dict[str, IpStat] = {}
        self.connections: Dict[str, ConnectionRecord] = {}
        self.port_hits: Dict[int, int] = {}
        self.protocol_counts: Dict[str, int] = {}
        self.max_ips = max_ips
        self.max_connections = max_connections
        self.total_packets = 0
        self.total_bytes = 0

    # ---------------- ingestion ----------------

    def observe(self, packet: PacketMetadata) -> None:
        """Folds one packet into the live statistics."""
        now = time.time()
        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet.packet_size

            src = self._ensure(self.sources, packet.source_ip, "source", now)
            src.packet_count += 1
            src.byte_count += packet.packet_size
            src.unique_destinations.add(packet.destination_ip)
            if packet.destination_port is not None:
                src.unique_destination_ports.add(packet.destination_port)
            src.protocols.add(packet.protocol)
            src.last_seen = now
            if packet.direction == "outbound":
                src.outbound_bytes += packet.packet_size
            else:
                src.inbound_bytes += packet.packet_size
            if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
                src.syn_count += 1

            dst = self._ensure(self.destinations, packet.destination_ip, "destination", now)
            dst.packet_count += 1
            dst.byte_count += packet.packet_size
            dst.protocols.add(packet.protocol)
            dst.last_seen = now
            if packet.destination_port is not None:
                dst.unique_destination_ports.add(packet.destination_port)

            if packet.destination_port is not None:
                self.port_hits[packet.destination_port] = self.port_hits.get(packet.destination_port, 0) + 1
            self.protocol_counts[packet.protocol] = self.protocol_counts.get(packet.protocol, 0) + 1

            conn = self.connections.get(packet.connection_id)
            if conn is None:
                conn = ConnectionRecord(
                    connection_id=packet.connection_id,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    source_port=packet.source_port,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    first_seen=now,
                )
                self.connections[packet.connection_id] = conn
                src.connection_count += 1
                dst.connection_count += 1
            conn.packet_count += 1
            conn.byte_count += packet.packet_size
            conn.last_seen = now
            if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
                conn.syn_count += 1
            if "R" in packet.tcp_flags:
                conn.rst_count += 1
                src.failed_connections += 1
            if "F" in packet.tcp_flags:
                conn.fin_count += 1

    def _ensure(self, store: Dict[str, IpStat], ip: str, role: str, now: float) -> IpStat:
        stat = store.get(ip)
        if stat is None:
            if len(store) >= self.max_ips:
                oldest = min(store.items(), key=lambda kv: kv[1].last_seen)[0]
                store.pop(oldest, None)
            stat = IpStat(ip=ip, role=role, first_seen=now, last_seen=now)
            store[ip] = stat
        return stat

    # ---------------- scoring ----------------

    def apply_threat_score(self, ip: str, score: float) -> None:
        """Records the highest observed score for an IP."""
        with self._lock:
            stat = self.sources.get(ip)
            if stat and score > stat.threat_score:
                stat.threat_score = score
                stat.risk_level = risk_level_for(score)

    # ---------------- queries ----------------

    def unique_ports_for_source(self, ip: str, window_seconds: int) -> int:
        with self._lock:
            stat = self.sources.get(ip)
            if not stat:
                return 0
            if (time.time() - stat.first_seen) > max(1, window_seconds) * 4:
                # Long-lived talker: use recent flow evidence instead.
                cutoff = time.time() - window_seconds
                ports = {
                    c.destination_port for c in self.connections.values()
                    if c.source_ip == ip and c.last_seen >= cutoff and c.destination_port is not None
                }
                return len(ports)
            return len(stat.unique_destination_ports)

    def top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            ranked = sorted(self.sources.values(), key=lambda s: s.packet_count, reverse=True)
            return [s.to_dict() for s in ranked[:limit]]

    def top_destinations(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            ranked = sorted(self.destinations.values(), key=lambda s: s.packet_count, reverse=True)
            return [s.to_dict() for s in ranked[:limit]]

    def top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            ranked = sorted(self.port_hits.items(), key=lambda kv: kv[1], reverse=True)
            return [{"port": p, "hits": c} for p, c in ranked[:limit]]

    def protocol_distribution(self) -> Dict[str, float]:
        with self._lock:
            total = sum(self.protocol_counts.values()) or 1
            return {k: round(v * 100.0 / total, 2) for k, v in self.protocol_counts.items()}

    def active_connections(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            ranked = sorted(self.connections.values(), key=lambda c: c.last_seen, reverse=True)
            return [c.to_dict() for c in ranked[:limit]]

    def counts(self) -> Dict[str, int]:
        with self._lock:
            return {
                "unique_source_ips": len(self.sources),
                "unique_destination_ips": len(self.destinations),
                "active_connections": len(self.connections),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
            }

    def ip_detail(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            stat = self.sources.get(ip) or self.destinations.get(ip)
            return stat.to_dict() if stat else None

    # ---------------- maintenance ----------------

    def prune(self, older_than_seconds: int) -> int:
        """Drops flows and IPs not seen inside the retention horizon."""
        cutoff = time.time() - max(30, older_than_seconds)
        removed = 0
        with self._lock:
            for key in [k for k, c in self.connections.items() if c.last_seen < cutoff]:
                self.connections.pop(key, None)
                removed += 1
            for store in (self.sources, self.destinations):
                for key in [k for k, s in store.items() if s.last_seen < cutoff]:
                    store.pop(key, None)
                    removed += 1
            if len(self.connections) > self.max_connections:
                ranked = sorted(self.connections.items(), key=lambda kv: kv[1].last_seen)
                for key, _ in ranked[: len(self.connections) - self.max_connections]:
                    self.connections.pop(key, None)
                    removed += 1
        return removed

    def reset(self) -> None:
        with self._lock:
            self.sources.clear()
            self.destinations.clear()
            self.connections.clear()
            self.port_hits.clear()
            self.protocol_counts.clear()
            self.total_packets = 0
            self.total_bytes = 0
