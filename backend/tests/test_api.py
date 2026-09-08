"""
API contract tests for the Sentinel AI detection, defense and analytics routes.

These run against the FastAPI app in-process with TestClient, so no live
server or network access is required. Persistence is redirected to a
temporary SQLite file so the tests never touch the configured PostgreSQL
instance.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Force the SQLite fallback before the app module is imported.
os.environ.pop("DATABASE_URL", None)
os.environ["DATABASE_SCHEMA"] = "sentinel_ai"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.ml.dataset_generator import ATTACK_LABELS, FEATURE_NAMES  # noqa: E402

EXPECTED_CLASSES = {
    "Benign",
    "Brute Force",
    "SQL Injection",
    "XSS",
    "DDoS",
    "Probe / Reconnaissance",
    "Malware / C2 Beaconing",
    "Phishing",
    "Unauthorized Access",
}


class ModelTaxonomyTests(unittest.TestCase):
    """The classifier must cover every threat class the product advertises."""

    def test_nine_attack_classes_are_defined(self):
        self.assertEqual(len(ATTACK_LABELS), 9)
        self.assertEqual(set(ATTACK_LABELS.values()), EXPECTED_CLASSES)

    def test_feature_space_is_twelve_dimensional(self):
        self.assertEqual(len(FEATURE_NAMES), 12)
        # Original 8 features must stay first for backward compatibility.
        self.assertEqual(FEATURE_NAMES[0], "packet_size")
        for added in (
            "distinct_ports_touched",
            "url_entropy",
            "outbound_bytes_ratio",
            "off_hours_access",
        ):
            self.assertIn(added, FEATURE_NAMES)


class DetectionApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_reports_database_metadata_without_secrets(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "ONLINE")

        db = body["database"]
        self.assertIn(db["backend"], {"sqlite", "postgresql"})
        # The health payload must never expose connection details.
        serialized = res.text.lower()
        for leak in ("password", "postgresql://", "@db.", "supabase"):
            self.assertNotIn(leak, serialized)

    def test_class_catalog_exposes_all_nine_classes(self):
        res = self.client.get("/api/detect/classes")
        self.assertEqual(res.status_code, 200)
        names = {c["name"] for c in res.json()["classes"]}
        self.assertEqual(names, EXPECTED_CLASSES)

    def test_predict_returns_confidence_and_probability_distribution(self):
        payload = {
            "detail": {
                "packet_size": 1400,
                "protocol": "HTTP",
                "request_rate": 6.0,
                "session_duration": 12.0,
                "payload_pattern_score": 0.95,
                "login_failure_rate": 0.05,
            },
            "source_ip": "203.0.113.10",
            "layer": "network",
        }
        res = self.client.post("/api/detect/predict", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()

        self.assertIn(body["predicted_class"], EXPECTED_CLASSES)
        self.assertGreaterEqual(body["confidence"], 0.0)
        self.assertLessEqual(body["confidence"], 1.0)
        self.assertGreaterEqual(body["risk_score"], 0.0)
        self.assertLessEqual(body["risk_score"], 100.0)
        self.assertIn(body["severity"], {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
        self.assertIn(body["verdict"], {"benign", "suspicious", "malicious"})

        probabilities = body["class_probabilities"]
        self.assertEqual(set(probabilities), EXPECTED_CLASSES)
        self.assertAlmostEqual(sum(probabilities.values()), 1.0, places=2)

    def test_stream_returns_classified_detections(self):
        res = self.client.get("/api/detect/stream?count=5")
        self.assertEqual(res.status_code, 200)
        detections = res.json()["detections"]
        self.assertEqual(len(detections), 5)

        for det in detections:
            self.assertIn(det["predicted_class"], EXPECTED_CLASSES)
            self.assertIn(det["severity"], {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
            self.assertIsInstance(det["auto_blocked"], bool)
            self.assertGreaterEqual(det["confidence"], 0.0)
            self.assertLessEqual(det["confidence"], 1.0)

    def test_stream_count_is_clamped(self):
        res = self.client.get("/api/detect/stream?count=9999")
        self.assertEqual(res.status_code, 200)
        self.assertLessEqual(len(res.json()["detections"]), 50)

    def test_stats_overview_exposes_monitoring_counters(self):
        self.client.get("/api/detect/stream?count=4")
        res = self.client.get("/api/stats/overview")
        self.assertEqual(res.status_code, 200)
        body = res.json()

        for key in (
            "total_events_processed",
            "events_per_second",
            "threats_detected",
            "class_distribution",
            "severity_distribution",
            "eps_history",
        ):
            self.assertIn(key, body)
        self.assertGreater(body["total_events_processed"], 0)


class DefenseApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_block_then_unblock_roundtrip(self):
        ip = "198.51.100.231"
        created = self.client.post(
            "/api/defense/block",
            json={
                "ip": ip,
                "attack_type": "SQL Injection",
                "risk_score": 95,
                "reason": "unit test",
                "mode": "manual",
            },
        )
        self.assertEqual(created.status_code, 200)

        listed = self.client.get("/api/defense/blocklist")
        self.assertEqual(listed.status_code, 200)
        self.assertIn(ip, {e["ip"] for e in listed.json()["entries"]})

        removed = self.client.delete(f"/api/defense/block/{ip}")
        self.assertEqual(removed.status_code, 200)

        after = self.client.get("/api/defense/blocklist")
        self.assertNotIn(ip, {e["ip"] for e in after.json()["entries"]})

    def test_unblocking_unknown_ip_returns_404_envelope(self):
        res = self.client.delete("/api/defense/block/203.0.113.222")
        self.assertEqual(res.status_code, 404)
        # Centralized handler wraps errors in a stable envelope.
        self.assertIn("error", res.json())

    def test_defense_config_updates_threshold(self):
        res = self.client.post("/api/defense/config", json={"threshold": 65})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["threshold"], 65)

        # Restore the default so later assertions are unaffected.
        self.client.post("/api/defense/config", json={"threshold": 80})

    def test_adaptive_policy_reports_learning_state(self):
        res = self.client.get("/api/defense/policy")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("algorithm", body)
        self.assertIn("reward_history", body)
        self.assertTrue(len(body["actions"]) > 0)


class IntegrationsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_integration_status_covers_siem_cloud_and_iot(self):
        res = self.client.get("/api/integrations/status")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(len(body["siem"]) > 0)
        self.assertTrue(len(body["cloud"]) > 0)
        self.assertIn("devices", body["iot"])


class ErrorHandlingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_unknown_incident_returns_error_envelope(self):
        res = self.client.get("/api/incidents/does-not-exist")
        self.assertEqual(res.status_code, 404)
        envelope = res.json()["error"]
        self.assertEqual(envelope["status"], 404)
        self.assertIn("message", envelope)

    def test_invalid_payload_returns_validation_envelope(self):
        res = self.client.post("/api/defense/config", json={"threshold": "not-a-number"})
        self.assertEqual(res.status_code, 422)
        envelope = res.json()["error"]
        self.assertEqual(envelope["type"], "validation_error")
        self.assertTrue(len(envelope["fields"]) > 0)

    def test_request_id_header_is_present(self):
        res = self.client.get("/api/health")
        self.assertIn("X-Request-ID", res.headers)


if __name__ == "__main__":
    unittest.main()
