"""
Tests for the real-time network telemetry subsystem.

These exercise metadata extraction, IP tracking, aggregation, the feature
adapter and the detection rules WITHOUT requiring a live capture driver, plus
the API contract. Synthetic PacketMetadata records are used purely as test
fixtures - the production LIVE path never fabricates packets.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.pop("DATABASE_URL", None)
os.environ["NETWORK_MONITOR_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.ml.dataset_generator import FEATURE_NAMES  # noqa: E402
from app.ml.models import ThreatDetectionModels  # noqa: E402
from app.network.adapter import (  # noqa: E402
    NETWORK_DERIVED_FEATURES,
    NOT_OBSERVABLE_FROM_PACKETS,
    build_raw_telemetry,
    build_sentinel_detail,
)
from app.network.aggregator import TrafficAggregator  # noqa: E402
from app.network.capture import capture_backend_status  # noqa: E402
from app.network.config import get_network_config  # noqa: E402
from app.network.detection import evaluate_network_rules  # noqa: E402
from app.network.models import PacketMetadata  # noqa: E402
from app.network.tracker import NetworkTracker  # noqa: E402


def make_packet(src="192.168.1.50", dst="192.168.1.10", sport=44100, dport=80,
                protocol="TCP", size=120, flags="S", direction="internal"):
    return PacketMetadata(
        timestamp="2026-01-01T10:00:00+00:00",
        source_ip=src, destination_ip=dst,
        source_port=sport, destination_port=dport,
        protocol=protocol, packet_size=size, tcp_flags=flags,
        interface="test0", direction=direction,
        connection_id=f"{src}:{sport}-{dst}:{dport}-{protocol}",
        is_simulated=False,
    )


class TrackerTests(unittest.TestCase):
    def test_tracks_ports_destinations_and_protocols(self):
        tracker = NetworkTracker()
        for port in range(1000, 1030):
            tracker.observe(make_packet(dport=port))

        stat = tracker.ip_detail("192.168.1.50")
        self.assertEqual(stat["packet_count"], 30)
        self.assertEqual(stat["unique_destination_ports"], 30)
        self.assertIn("TCP", stat["protocols"])

    def test_reset_clears_state(self):
        tracker = NetworkTracker()
        tracker.observe(make_packet())
        tracker.reset()
        self.assertEqual(tracker.counts()["total_packets"], 0)

    def test_prune_removes_stale_flows(self):
        """prune() enforces a 30s minimum horizon, so age the records first."""
        tracker = NetworkTracker()
        tracker.observe(make_packet())
        self.assertEqual(tracker.counts()["active_connections"], 1)

        stale = time.time() - 600
        for conn in tracker.connections.values():
            conn.last_seen = stale
        for store in (tracker.sources, tracker.destinations):
            for stat in store.values():
                stat.last_seen = stale

        removed = tracker.prune(older_than_seconds=60)
        self.assertGreater(removed, 0)
        self.assertEqual(tracker.counts()["active_connections"], 0)

    def test_prune_keeps_recent_flows(self):
        """Fresh traffic must survive a retention sweep."""
        tracker = NetworkTracker()
        tracker.observe(make_packet())
        tracker.prune(older_than_seconds=60)
        self.assertEqual(tracker.counts()["active_connections"], 1)


class AggregatorTests(unittest.TestCase):
    def test_window_features_are_derived(self):
        agg = TrafficAggregator(windows=[5], baseline_min_samples=2)
        for port in range(80, 100):
            agg.add(make_packet(dport=port, size=200))

        features = agg.compute(5)
        self.assertEqual(features.packet_count, 20)
        self.assertGreater(features.packets_per_second, 0)
        self.assertEqual(features.average_packet_size, 200.0)
        self.assertEqual(features.max_ports_single_source, 20)
        self.assertIn("TCP", features.protocol_distribution)

    def test_baseline_and_deviation(self):
        agg = TrafficAggregator(windows=[1], baseline_min_samples=2)
        agg.add(make_packet())
        low = agg.compute(1)
        agg.update_baseline(low)
        agg.update_baseline(low)

        deviation = agg.deviation(low)
        self.assertTrue(deviation["available"])
        self.assertIn("deviation_percent", deviation)

    def test_new_entities_feed_what_changed(self):
        agg = TrafficAggregator(windows=[5])
        agg.note_known_entities([make_packet(dst="10.0.0.1", dport=80)])
        result = agg.note_known_entities([make_packet(dst="203.0.113.9", dport=4444)])
        self.assertIn("203.0.113.9", result["new_destination_ips"])
        self.assertIn("4444", result["new_destination_ports"])


class FeatureAdapterTests(unittest.TestCase):
    """The adapter must stay compatible with the trained model schema."""

    def test_provenance_covers_all_twelve_features(self):
        combined = set(NETWORK_DERIVED_FEATURES) | set(NOT_OBSERVABLE_FROM_PACKETS)
        self.assertEqual(combined, set(FEATURE_NAMES))
        self.assertEqual(len(NETWORK_DERIVED_FEATURES), 7)
        self.assertEqual(len(NOT_OBSERVABLE_FROM_PACKETS), 5)

    def test_adapted_detail_produces_valid_model_vector(self):
        agg = TrafficAggregator(windows=[5])
        for port in range(2000, 2040):
            agg.add(make_packet(dport=port))
        features = agg.compute(5)

        detail = build_sentinel_detail(
            features=features, source_ip="192.168.1.50",
            observed_ports=[80, 443], port_fan_out=40,
        )
        models = ThreatDetectionModels.get_instance()
        vector = models.extract_features_from_event(detail)

        self.assertEqual(vector.shape, (1, len(FEATURE_NAMES)))
        result = models.predict(detail)
        self.assertIn("label", result)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_live_telemetry_is_not_marked_simulated(self):
        raw = build_raw_telemetry(detail={"packet_size": 100}, entity_id="host:192.168.1.50")
        self.assertFalse(raw["is_simulated"])
        self.assertEqual(raw["layer"], "network")


class NetworkRuleTests(unittest.TestCase):
    def setUp(self):
        self.config = get_network_config()
        self.agg = TrafficAggregator(windows=[30])

    def _features(self, count=40, size=100, flags="S", dport_start=3000):
        for i in range(count):
            self.agg.add(make_packet(dport=dport_start + i, size=size, flags=flags))
        return self.agg.compute(30)

    def test_port_scan_is_detected(self):
        features = self._features(count=40)
        hits = evaluate_network_rules(
            features=features, config=self.config, source_ip="192.168.1.50",
            port_fan_out=40, observed_ports=[3000, 3001], deviation={"available": False},
        )
        names = [h["attack_type"] for h in hits]
        self.assertIn("Probe / Reconnaissance", names)
        scan = next(h for h in hits if h["attack_type"] == "Probe / Reconnaissance")
        self.assertEqual(scan["mitre_id"], "T1046")

    def test_normal_traffic_raises_no_rule(self):
        for _ in range(3):
            self.agg.add(make_packet(dport=443, flags="A", size=500))
        features = self.agg.compute(30)
        hits = evaluate_network_rules(
            features=features, config=self.config, source_ip="192.168.1.50",
            port_fan_out=1, observed_ports=[443], deviation={"available": False},
        )
        self.assertEqual(hits, [])

    def test_sensitive_port_access_requires_external_source(self):
        features = self._features(count=5, dport_start=3389)
        internal = evaluate_network_rules(
            features=features, config=self.config, source_ip="192.168.1.50",
            port_fan_out=2, observed_ports=[3389], deviation={"available": False},
            external=False,
        )
        external = evaluate_network_rules(
            features=features, config=self.config, source_ip="203.0.113.7",
            port_fan_out=2, observed_ports=[3389], deviation={"available": False},
            external=True,
        )
        self.assertNotIn("Unauthorized Access", [h["attack_type"] for h in internal])
        self.assertIn("Unauthorized Access", [h["attack_type"] for h in external])


class NetworkApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_status_reports_mode_and_capability_honestly(self):
        res = self.client.get("/api/network/status")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn(body["mode"], {"DEMO", "LIVE"})
        self.assertIn(body["health"], {"MONITORING", "STOPPED", "UNAVAILABLE"})
        self.assertIn("capability", body)
        self.assertIn("capture_possible", body["capability"])

    def test_read_endpoints_available(self):
        for path in ("/api/network/packets", "/api/network/stats", "/api/network/ips",
                     "/api/network/connections", "/api/network/threats",
                     "/api/network/interfaces"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_start_requires_role_header(self):
        res = self.client.post("/api/network/start", json={})
        self.assertEqual(res.status_code, 401)

    def test_start_rejects_unprivileged_role(self):
        res = self.client.post("/api/network/start", json={},
                               headers={"X-Sentinel-Role": "guest"})
        self.assertEqual(res.status_code, 403)

    def test_privileged_start_returns_precise_reason_when_unavailable(self):
        """Without a capture driver the API must fail loudly, not fake success."""
        backend = capture_backend_status()
        res = self.client.post("/api/network/start", json={},
                               headers={"X-Sentinel-Role": "admin"})
        if backend["capture_possible"]:
            self.assertIn(res.status_code, (200, 409))
        else:
            self.assertEqual(res.status_code, 409)
            self.assertIn("capture_unavailable", res.json()["error"]["message"])

    def test_stop_is_privileged_and_idempotent(self):
        self.assertEqual(self.client.post("/api/network/stop").status_code, 401)
        res = self.client.post("/api/network/stop", headers={"X-Sentinel-Role": "admin"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["mode"], "DEMO")

    def test_replay_still_works_alongside_network_subsystem(self):
        """Regression guard: the existing simulation must remain functional."""
        res = self.client.post("/api/replay/reset")
        self.assertEqual(res.status_code, 200)
        step = self.client.post("/api/replay/step")
        self.assertEqual(step.status_code, 200)


if __name__ == "__main__":
    unittest.main()
