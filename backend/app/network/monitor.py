"""
Network monitor service - the orchestrator.

PIPELINE
    capture -> tracker/aggregator -> window features -> adapter
            -> EXISTING correlator (normalizer + RF + IsolationForest + rules)
            -> EXISTING trajectory scoring -> EXISTING MITRE mapping
            -> incident create/enrich -> persistence

INTEGRATION DISCIPLINE
  * No second AI system. Inference happens through the platform's own
    CrossLayerCorrelator, so scoring, correlation, attack graphs, MITRE tags
    and the audit trail are all the existing implementations.
  * Evidence is emitted per SOURCE IP per window - not per packet - so 100
    packets collapse into one evidence item on one incident.
  * Entity resolution prefers an EXISTING incident entity, so network evidence
    enriches an open investigation instead of spawning duplicates.
  * LIVE telemetry is tagged is_simulated=False; replay stays untouched.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..observability import log_event
from . import persistence
from .adapter import build_raw_telemetry, build_sentinel_detail
from .aggregator import TrafficAggregator
from .capture import PacketCaptureEngine, capture_backend_status, list_interfaces
from .config import NetworkConfig, get_network_config
from .detection import evaluate_network_rules
from .models import NetworkThreat
from .tracker import NetworkTracker, risk_level_for

_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "127.", "169.254.")


class NetworkMonitorService:
    """Singleton service owning capture, aggregation and detection threads."""

    _instance: Optional["NetworkMonitorService"] = None

    def __init__(self, correlator=None):
        self.config: NetworkConfig = get_network_config()
        self.correlator = correlator
        self.capture = PacketCaptureEngine(queue_size=self.config.queue_size)
        self.tracker = NetworkTracker()
        self.aggregator = TrafficAggregator(
            windows=self.config.windows,
            baseline_min_samples=self.config.baseline_min_samples,
        )
        self._worker: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._lock = threading.Lock()
        self.threats: List[NetworkThreat] = []
        self.mode = "DEMO"                 # DEMO | LIVE
        self.started_at: Optional[float] = None
        self.last_detection_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self.windows_processed = 0
        self.evidence_emitted = 0
        self.packets_persisted = 0
        self._last_retention_sweep = 0.0
        # Marker for delta-based throughput reporting: (timestamp, packets, bytes)
        self._rate_marker = (time.time(), 0, 0)
        self._db_ready = False

    @classmethod
    def get_instance(cls, correlator=None) -> "NetworkMonitorService":
        if cls._instance is None:
            cls._instance = cls(correlator=correlator)
        elif correlator is not None and cls._instance.correlator is None:
            cls._instance.correlator = correlator
        return cls._instance

    # ---------------- capability ----------------

    def capability(self) -> Dict[str, Any]:
        """Honest report of whether real capture is possible on this host."""
        backend = capture_backend_status()
        backend["interfaces_detected"] = len(list_interfaces())
        return backend

    # ---------------- lifecycle ----------------

    def start(self, interface: Optional[str] = None, capture_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Begins LIVE capture. Raises RuntimeError with a precise, actionable
        reason when the platform cannot capture - it never fakes success.
        """
        with self._lock:
            self.config = get_network_config()

            if not self._db_ready:
                result = persistence.init_network_tables()
                self._db_ready = bool(result.get("initialized"))
                if not self._db_ready:
                    log_event("warning", "network_tables_unavailable", db_error=result.get("error"))

            iface = interface or self.config.interface
            bpf = capture_filter if capture_filter is not None else self.config.capture_filter

            started = self.capture.start(iface, bpf)   # raises on failure
            self.mode = "LIVE"
            self.started_at = time.time()
            self._stop_flag.clear()
            self.last_error = None

            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(
                    target=self._run_loop, name="sentinel-network-monitor", daemon=True
                )
                self._worker.start()

            log_event("info", "network_monitor_started",
                      interface=self.capture.interface, capture_filter=bpf)
            return {**started, "mode": self.mode}

    def stop(self) -> Dict[str, Any]:
        """Stops capture and the processing loop, retaining collected statistics."""
        with self._lock:
            self._stop_flag.set()
            result = self.capture.stop()
            self.mode = "DEMO"
            log_event("info", "network_monitor_stopped",
                      windows_processed=self.windows_processed)
            return {**result, "mode": self.mode}

    # ---------------- processing loop ----------------

    def _run_loop(self) -> None:
        """Background consumer. Aggregation and inference happen here only."""
        interval = max(1.0, self.config.detection_interval_seconds)
        while not self._stop_flag.is_set():
            try:
                self._drain_and_process()
            except Exception as error:
                self.last_error = f"processing_error: {type(error).__name__}"
                log_event("error", "network_processing_error", error_type=type(error).__name__)
            self._stop_flag.wait(interval)

    def _drain_and_process(self) -> None:
        batch = self.capture.drain(limit=5000)
        if batch:
            for packet in batch:
                self.tracker.observe(packet)
            self.aggregator.add_many(batch)
            deviations = self.aggregator.note_known_entities(batch)

            if self._db_ready:
                written = persistence.save_packet_batch(batch)
                self.packets_persisted += written
        else:
            deviations = {}

        if not self.capture.is_running and not batch:
            return

        window = self.config.detection_window_seconds
        features = self.aggregator.compute(window)
        if features.packet_count == 0:
            return

        self.windows_processed += 1
        deviation = self.aggregator.deviation(features)
        self.aggregator.update_baseline(features)

        self._evaluate_window(features, deviation, deviations)
        self._retention_sweep()

    def _evaluate_window(self, features, deviation: Dict[str, Any], new_entities: Dict[str, Any]) -> None:
        """Emits at most one evidence item per notable source IP per window."""
        window = self.config.detection_window_seconds
        candidates = self.tracker.top_sources(limit=8)

        for stat in candidates:
            source_ip = stat["ip"]

            # Rules are evaluated PER SOURCE IP, so the feature view must be
            # scoped to that source. Using window-global rates here would
            # attribute one host's behaviour to another.
            source_features = self.aggregator.compute(window, source_ip=source_ip)
            if source_features.packet_count == 0:
                continue

            port_fan_out = self.tracker.unique_ports_for_source(
                source_ip, self.config.port_scan_window_seconds
            )
            observed_ports = sorted({
                c.get("destination_port") for c in self.tracker.active_connections(limit=400)
                if c.get("source_ip") == source_ip and c.get("destination_port") is not None
            })
            external = not str(source_ip).startswith(_PRIVATE_PREFIXES)

            hits = evaluate_network_rules(
                features=source_features,
                config=self.config,
                source_ip=source_ip,
                port_fan_out=port_fan_out,
                observed_ports=observed_ports,
                deviation=deviation,
                external=external,
            )
            if not hits:
                continue    # benign traffic raises no incident - by design

            self._emit_evidence(
                features=source_features,
                source_ip=source_ip,
                port_fan_out=port_fan_out,
                observed_ports=observed_ports,
                rule_hits=hits,
                deviation=deviation,
                new_entities=new_entities,
            )

    # ---------------- evidence emission ----------------

    def _resolve_entity(self, source_ip: str) -> str:
        """
        Prefers an existing incident entity so network evidence ENRICHES an open
        investigation rather than creating duplicate incidents.
        """
        if self.correlator is not None:
            try:
                entity_map = self.correlator.trajectory_engine.entity_incident_map
                for entity_id in entity_map.keys():
                    if source_ip and source_ip in entity_id:
                        return entity_id
            except Exception:
                pass

        if self.config.local_entity_hint and str(source_ip).startswith(_PRIVATE_PREFIXES):
            return self.config.local_entity_hint
        return f"host:{source_ip}"

    def _emit_evidence(
        self,
        features,
        source_ip: str,
        port_fan_out: int,
        observed_ports: List[int],
        rule_hits: List[Dict[str, Any]],
        deviation: Dict[str, Any],
        new_entities: Dict[str, Any],
    ) -> None:
        """Feeds one window of network evidence into the EXISTING pipeline."""
        primary = rule_hits[0]
        detail = build_sentinel_detail(
            features=features,
            source_ip=source_ip,
            destination_ip=None,
            mean_session_duration=self._mean_session_duration(source_ip),
            observed_ports=observed_ports,
            port_fan_out=port_fan_out,
        )
        detail["network_rule_hits"] = [h["rule_name"] for h in rule_hits]
        detail["baseline_deviation"] = deviation
        detail["new_network_entities"] = new_entities

        entity_id = self._resolve_entity(source_ip)
        raw = build_raw_telemetry(detail=detail, entity_id=entity_id,
                                 action=self._action_for(primary["attack_type"]))

        incident_id = None
        confidence = 0.0
        anomaly_score = 0.0
        threat_score = 0.0
        risk_level = "LOW"

        if self.correlator is not None:
            try:
                # SAME entry point the REST telemetry endpoint uses: normalizer,
                # RandomForest + IsolationForest, rules, trajectory, MITRE.
                event, incident = self.correlator.process_raw_telemetry(raw)
                incident_id = incident.incident_id
                threat_score = float(incident.threat_score)
                risk_level = (incident.risk_breakdown.risk_level
                              if incident.risk_breakdown else risk_level_for(threat_score))
                confidence = float(event.confidence_score or 0.0)

                ml = self.correlator.ml_models.predict(detail)
                anomaly_score = float(ml.get("anomaly_score", 0.0))
            except Exception as error:
                self.last_error = f"ml_unavailable: {type(error).__name__}"
                log_event("error", "network_inference_failed", error_type=type(error).__name__)
                threat_score = min(100.0, primary.get("weight", 20.0) * 2.0)
                risk_level = risk_level_for(threat_score)

        self.tracker.apply_threat_score(source_ip, threat_score)
        self.last_detection_at = datetime.now(timezone.utc).isoformat()
        self.evidence_emitted += 1

        threat = NetworkThreat(
            threat_id=f"nthr-{uuid.uuid4().hex[:10]}",
            detected_at=self.last_detection_at,
            threat_type=primary["attack_type"],
            source_ip=source_ip,
            destination_ip=None,
            confidence=round(confidence, 4),
            anomaly_score=round(anomaly_score, 4),
            threat_score=round(threat_score, 1),
            risk_level=risk_level,
            mitre_id=primary.get("mitre_id"),
            mitre_technique=primary.get("mitre_technique"),
            mitre_tactic=primary.get("mitre_tactic"),
            description=primary.get("description", ""),
            incident_id=incident_id,
            detection_source="hybrid_ml_rule",
            recommended_action=self._recommended_action(threat_score),
            evidence={
                "rules": [h["rule_name"] for h in rule_hits],
                "window_seconds": features.window_seconds,
                "packets_per_second": features.packets_per_second,
                "port_fan_out": port_fan_out,
                "baseline_deviation": deviation,
            },
            is_simulated=False,
        )

        with self._lock:
            self.threats.insert(0, threat)
            del self.threats[200:]

        if self._db_ready:
            persistence.save_threat(threat)

        log_event("warning", "network_threat_detected",
                  threat_type=threat.threat_type, source_ip=source_ip,
                  threat_score=threat.threat_score, incident_id=incident_id)

    def _mean_session_duration(self, source_ip: str) -> float:
        conns = [c for c in self.tracker.active_connections(limit=200)
                 if c.get("source_ip") == source_ip]
        if not conns:
            return 0.0
        return round(sum(c.get("duration_seconds", 0.0) for c in conns) / len(conns), 3)

    @staticmethod
    def _action_for(attack_type: str) -> str:
        return {
            "Probe / Reconnaissance": "port_scan_detected",
            "DDoS": "traffic_rate_anomaly",
            "Malware / C2 Beaconing": "egress_beaconing",
            "Unauthorized Access": "sensitive_port_access",
            "Anomaly": "traffic_baseline_deviation",
        }.get(attack_type, "network_flow_window")

    def _recommended_action(self, threat_score: float) -> str:
        """AUTO_BLOCK is opt-in; the default posture only recommends."""
        if threat_score >= self.config.threat_threshold:
            return "BLOCK_IP" if self.config.auto_block else "RECOMMEND_BLOCK_IP"
        return "MONITOR"

    def _retention_sweep(self) -> None:
        now = time.time()
        if now - self._last_retention_sweep < 60:
            return
        self._last_retention_sweep = now
        self.tracker.prune(self.config.retention_minutes * 60)
        if self._db_ready:
            persistence.enforce_retention(self.config.retention_minutes)

    # ---------------- reporting ----------------

    def status(self) -> Dict[str, Any]:
        capture_status = self.capture.status()
        counts = self.tracker.counts()
        # Throughput is derived from counter DELTAS rather than a time window.
        # Packets arrive in bursts each drain cycle, so a fixed window can race
        # the drain interval and report zero while traffic is clearly flowing.
        now = time.time()
        prev_ts, prev_packets, prev_bytes = self._rate_marker
        total_packets = capture_status["packets_captured"]
        total_bytes = counts["total_bytes"]
        elapsed = max(0.001, now - prev_ts)

        if total_packets >= prev_packets and elapsed >= 0.5:
            observed_pps = round((total_packets - prev_packets) / elapsed, 2)
            observed_bps = round((total_bytes - prev_bytes) / elapsed, 2)
            self._rate_marker = (now, total_packets, total_bytes)
        else:
            # Fall back to a lifetime average until the next sample matures.
            uptime = max(1.0, capture_status["uptime_seconds"] or 1.0)
            observed_pps = round(total_packets / uptime, 2)
            observed_bps = round(total_bytes / uptime, 2)
        capability = self.capability()

        health = "MONITORING" if capture_status["running"] else (
            "STOPPED" if capability["capture_possible"] else "UNAVAILABLE"
        )

        return {
            "mode": self.mode,
            "health": health,
            "monitoring": capture_status["running"],
            "data_source": "live_network_capture" if capture_status["running"] else "none",
            "is_simulated": False,
            "interface": capture_status["interface"],
            "capture_filter": capture_status["capture_filter"],
            "uptime_seconds": capture_status["uptime_seconds"],
            "packets_captured": capture_status["packets_captured"],
            "packets_dropped": capture_status["packets_dropped"],
            "packets_persisted": self.packets_persisted,
            "queue_depth": capture_status["queue_depth"],
            "packets_per_second": observed_pps,
            "bytes_per_second": observed_bps,
            "active_connections": counts["active_connections"],
            "unique_source_ips": counts["unique_source_ips"],
            "unique_destination_ips": counts["unique_destination_ips"],
            "threat_count": len(self.threats),
            "windows_processed": self.windows_processed,
            "evidence_emitted": self.evidence_emitted,
            "last_detection_at": self.last_detection_at,
            "capability": capability,
            "database": persistence.status(),
            "config": {
                "enabled": self.config.enabled,
                "interface": self.config.interface,
                "retention_minutes": self.config.retention_minutes,
                "threat_threshold": self.config.threat_threshold,
                "auto_block": self.config.auto_block,
                "windows": self.config.windows,
                "port_scan_unique_ports": self.config.port_scan_unique_ports,
                "dos_packets_per_second": self.config.dos_packets_per_second,
            },
            "last_error": self.last_error or capture_status["last_error"],
        }

    def stats(self) -> Dict[str, Any]:
        windows = {str(w): self.aggregator.compute(w).to_dict() for w in self.config.windows}
        smallest = self.config.windows[0] if self.config.windows else 1
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
            "is_simulated": False,
            "windows": windows,
            "baseline": self.aggregator.baseline(),
            "deviation": self.aggregator.deviation(self.aggregator.compute(smallest)),
            "protocol_distribution": self.tracker.protocol_distribution(),
            "top_ports": self.tracker.top_ports(limit=10),
            "rate_history": self.aggregator.rate_history(limit=60),
            "counts": self.tracker.counts(),
        }

    def packets(self, limit: int = 100) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "is_simulated": False,
            "count": min(limit, self.config.max_packets_in_memory),
            "packets": self.aggregator.recent_packets(limit=limit),
        }

    def ips(self, limit: int = 20) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "top_sources": self.tracker.top_sources(limit=limit),
            "top_destinations": self.tracker.top_destinations(limit=limit),
        }

    def connections(self, limit: int = 50) -> Dict[str, Any]:
        return {"mode": self.mode, "connections": self.tracker.active_connections(limit=limit)}

    def network_threats(self, limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            live = [t.to_dict() for t in self.threats[:limit]]
        return {
            "mode": self.mode,
            "count": len(live),
            "threats": live,
            "persisted": persistence.recent_threats(limit=limit) if self._db_ready else [],
        }

    def reset(self) -> Dict[str, Any]:
        """Clears in-memory network state. Does not touch replay or incidents."""
        with self._lock:
            self.tracker.reset()
            self.aggregator.reset()
            self.threats.clear()
            self.windows_processed = 0
            self.evidence_emitted = 0
        return {"status": "RESET"}
