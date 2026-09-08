"""
Rolling-window traffic aggregation.

Rationale: a single packet carries almost no security meaning, and per-packet
ML inference would collapse under real traffic. Behaviour only becomes visible
over time, so packets are folded into time windows and ONE feature vector is
produced per window.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from .models import PacketMetadata, WindowFeatures


class TrafficAggregator:
    """Maintains a packet ring buffer and derives per-window features."""

    def __init__(self, windows: List[int], baseline_min_samples: int = 6, buffer_seconds: int = 120):
        self._lock = threading.Lock()
        self.windows = sorted(set(w for w in windows if w > 0)) or [1, 5, 30, 60]
        self.buffer_seconds = max(buffer_seconds, self.windows[-1] * 2)
        self._packets: Deque = deque()
        self._recent: Deque = deque(maxlen=2000)
        self.baseline_min_samples = baseline_min_samples
        self._pps_history: Deque = deque(maxlen=240)
        self._bps_history: Deque = deque(maxlen=240)
        self._baseline_pps: Optional[float] = None
        self._baseline_bps: Optional[float] = None
        self.known_destinations: set = set()
        self.known_ports: set = set()
        self.known_protocols: set = set()

    # ---------------- ingestion ----------------

    def add(self, packet: PacketMetadata) -> None:
        now = time.time()
        with self._lock:
            self._packets.append((now, packet))
            self._recent.appendleft(packet)
            self._evict(now)

    def add_many(self, packets: List[PacketMetadata]) -> None:
        for packet in packets:
            self.add(packet)

    def _evict(self, now: float) -> None:
        cutoff = now - self.buffer_seconds
        while self._packets and self._packets[0][0] < cutoff:
            self._packets.popleft()

    # ---------------- feature derivation ----------------

    def compute(self, window_seconds: int, source_ip: Optional[str] = None) -> WindowFeatures:
        """
        Builds the aggregated feature record for one window.

        When `source_ip` is supplied the sample is restricted to packets from
        that source. This matters for correctness: detection rules are evaluated
        per source IP, so feeding them window-global rates would misattribute
        one host's behaviour to another.
        """
        now = time.time()
        span = max(1, window_seconds)
        cutoff = now - span

        with self._lock:
            sample = [
                p for ts, p in self._packets
                if ts >= cutoff and (source_ip is None or p.source_ip == source_ip)
            ]
            baseline_pps = self._baseline_pps

        features = WindowFeatures(
            window_seconds=span,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        if not sample:
            return features

        packet_count = len(sample)
        byte_count = sum(p.packet_size for p in sample)
        sources = {p.source_ip for p in sample}
        destinations = {p.destination_ip for p in sample}
        ports = {p.destination_port for p in sample if p.destination_port is not None}
        connections = {p.connection_id for p in sample}
        syn_packets = sum(1 for p in sample if "S" in p.tcp_flags and "A" not in p.tcp_flags)
        resets = sum(1 for p in sample if "R" in p.tcp_flags)

        proto_counts: Dict[str, int] = {}
        per_source_ports: Dict[str, set] = {}
        per_source_packets: Dict[str, int] = {}
        outbound = inbound = 0
        for p in sample:
            proto_counts[p.protocol] = proto_counts.get(p.protocol, 0) + 1
            per_source_packets[p.source_ip] = per_source_packets.get(p.source_ip, 0) + 1
            if p.destination_port is not None:
                per_source_ports.setdefault(p.source_ip, set()).add(p.destination_port)
            if p.direction == "outbound":
                outbound += p.packet_size
            else:
                inbound += p.packet_size

        features.packet_count = packet_count
        features.byte_count = byte_count
        features.packets_per_second = round(packet_count / span, 2)
        features.bytes_per_second = round(byte_count / span, 2)
        features.connections_per_second = round(len(connections) / span, 2)
        features.unique_source_ips = len(sources)
        features.unique_destination_ips = len(destinations)
        features.unique_ports = len(ports)
        features.tcp_syn_rate = round(syn_packets / span, 2)
        features.failed_connections = resets
        features.connection_frequency = round(len(connections) / max(1, len(sources)), 2)
        features.average_packet_size = round(byte_count / packet_count, 2)
        features.protocol_distribution = {
            k: round(v * 100.0 / packet_count, 2) for k, v in proto_counts.items()
        }
        features.outbound_bytes_ratio = round(max(0.01, outbound / max(1.0, inbound)), 3)

        if per_source_packets:
            features.top_source_ip = max(per_source_packets.items(), key=lambda kv: kv[1])[0]
        features.max_ports_single_source = max((len(v) for v in per_source_ports.values()), default=0)

        # Burst = current rate relative to the learned baseline.
        if baseline_pps and baseline_pps > 0.5:
            features.traffic_burst_rate = round(features.packets_per_second / baseline_pps, 2)
        else:
            features.traffic_burst_rate = 1.0

        return features

    # ---------------- baseline ----------------

    def update_baseline(self, features: WindowFeatures) -> None:
        """Learns normal traffic levels so deviation can be quantified."""
        with self._lock:
            self._pps_history.append(features.packets_per_second)
            self._bps_history.append(features.bytes_per_second)
            if len(self._pps_history) >= self.baseline_min_samples:
                ordered = sorted(self._pps_history)
                self._baseline_pps = ordered[len(ordered) // 2]
                ordered_b = sorted(self._bps_history)
                self._baseline_bps = ordered_b[len(ordered_b) // 2]

    def note_known_entities(self, packets: List[PacketMetadata]) -> Dict[str, List[str]]:
        """
        Records first-seen destinations/ports/protocols and returns what is new.
        Feeds the existing "What Changed?" baseline-deviation view.
        """
        new_dests: List[str] = []
        new_ports: List[str] = []
        new_protos: List[str] = []
        with self._lock:
            for p in packets:
                if p.destination_ip not in self.known_destinations:
                    self.known_destinations.add(p.destination_ip)
                    if len(self.known_destinations) > 1:
                        new_dests.append(p.destination_ip)
                if p.destination_port is not None and p.destination_port not in self.known_ports:
                    self.known_ports.add(p.destination_port)
                    if len(self.known_ports) > 1:
                        new_ports.append(str(p.destination_port))
                if p.protocol not in self.known_protocols:
                    self.known_protocols.add(p.protocol)
                    if len(self.known_protocols) > 1:
                        new_protos.append(p.protocol)
        return {
            "new_destination_ips": sorted(set(new_dests))[:10],
            "new_destination_ports": sorted(set(new_ports))[:10],
            "new_protocols": sorted(set(new_protos))[:5],
        }

    def baseline(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "baseline_packets_per_second": self._baseline_pps,
                "baseline_bytes_per_second": self._baseline_bps,
                "samples": len(self._pps_history),
                "ready": self._baseline_pps is not None,
            }

    def deviation(self, features: WindowFeatures) -> Dict[str, Any]:
        """Quantifies current traffic against the learned baseline."""
        base = self.baseline()
        baseline_pps = base.get("baseline_packets_per_second")
        if not baseline_pps or baseline_pps <= 0:
            return {"available": False, "reason": "baseline_not_ready", **base}

        delta_pct = ((features.packets_per_second - baseline_pps) / baseline_pps) * 100.0
        return {
            "available": True,
            "baseline_packets_per_second": round(baseline_pps, 2),
            "current_packets_per_second": features.packets_per_second,
            "deviation_percent": round(delta_pct, 1),
            "direction": "increase" if delta_pct >= 0 else "decrease",
            "samples": base.get("samples"),
        }

    # ---------------- exposure ----------------

    def recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in list(self._recent)[:max(1, limit)]]

    def rate_history(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            pps = list(self._pps_history)[-limit:]
            bps = list(self._bps_history)[-limit:]
        return [
            {"index": i, "packets_per_second": p, "bytes_per_second": b}
            for i, (p, b) in enumerate(zip(pps, bps))
        ]

    def reset(self) -> None:
        with self._lock:
            self._packets.clear()
            self._recent.clear()
            self._pps_history.clear()
            self._bps_history.clear()
            self._baseline_pps = None
            self._baseline_bps = None
            self.known_destinations.clear()
            self.known_ports.clear()
            self.known_protocols.clear()
