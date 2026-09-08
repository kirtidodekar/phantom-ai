"""
Tests for four-layer coverage: the application layer promotion, the endpoint and
application sensors, and data-sovereignty reporting.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.pop("DATABASE_URL", None)
os.environ["NETWORK_MONITOR_ENABLED"] = "false"
os.environ["ENDPOINT_SENSOR_ENABLED"] = "false"
os.environ["APPLICATION_SENSOR_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from app.engine.correlator import CrossLayerCorrelator  # noqa: E402
from app.engine.normalizer import VALID_LAYERS, normalize_event  # noqa: E402
from app.engine.trajectory import ThreatTrajectoryEngine  # noqa: E402
from app.main import app  # noqa: E402
from app.sensors.application import ApplicationSensor, score_payload  # noqa: E402
from app.sensors.endpoint import EndpointSensor  # noqa: E402
from app.sensors.manager import data_sovereignty  # noqa: E402


class ApplicationLayerTests(unittest.TestCase):
    """The application layer must be first-class, not folded into identity."""

    def test_four_valid_layers(self):
        self.assertEqual(set(VALID_LAYERS), {"network", "endpoint", "identity", "application"})

    def test_application_layer_is_preserved(self):
        event = normalize_event({
            "layer": "application",
            "entity_id": "user:alice / host:WEB-01",
            "action": "http_request",
            "detail": {"url": "/login"},
        })
        # Regression guard: this used to be silently rewritten to "identity".
        self.assertEqual(event.layer, "application")

    def test_layer_aliases_map_to_application(self):
        for alias in ("app", "web", "http"):
            self.assertEqual(normalize_event({"layer": alias}).layer, "application")

    def test_application_detail_fields_survive_normalization(self):
        event = normalize_event({
            "layer": "application",
            "url": "/search?q=1",
            "status_code": 403,
            "http_method": "GET",
        })
        self.assertEqual(event.detail.get("status_code"), 403)
        self.assertEqual(event.detail.get("http_method"), "GET")


class CrossLayerScoringTests(unittest.TestCase):
    """Four-layer convergence must earn a larger bonus than three."""

    def _score_for_layers(self, layers):
        engine = ThreatTrajectoryEngine()
        for layer in layers:
            engine.process_event(
                event=normalize_event({
                    "layer": layer,
                    "entity_id": "user:alice / host:WKS-1",
                    "action": "observed",
                    "detail": {},
                }),
                ml_res={"label": "Benign", "confidence": 0.1,
                        "is_anomaly": False, "anomaly_score": 0.0},
                rule_hit=None,
            )
        incident = list(engine.active_incidents.values())[0]
        return incident.risk_breakdown.cross_layer_diversity_bonus

    def test_bonus_scales_to_four_layers(self):
        self.assertEqual(self._score_for_layers(["network"]), 0.0)
        self.assertEqual(self._score_for_layers(["network", "endpoint"]), 12.0)
        self.assertEqual(self._score_for_layers(["network", "endpoint", "identity"]), 25.0)
        self.assertEqual(
            self._score_for_layers(["network", "endpoint", "identity", "application"]),
            32.0,
        )

    def test_all_four_layers_converge_on_one_incident(self):
        """Shared entity => one correlated incident, not four."""
        correlator = CrossLayerCorrelator()
        entity = "user:alice / host:WKS-1"
        for layer, action in (("network", "flow"), ("endpoint", "process_create"),
                              ("identity", "login_fail"), ("application", "http_request")):
            correlator.process_raw_telemetry({
                "layer": layer, "entity_id": entity, "action": action,
                "detail": {"url": "/x"}, "is_simulated": False,
            })

        incidents = correlator.trajectory_engine.active_incidents
        self.assertEqual(len(incidents), 1)
        incident = list(incidents.values())[0]
        self.assertEqual(set(incident.layers_involved),
                         {"network", "endpoint", "identity", "application"})
        self.assertGreater(incident.risk_breakdown.cross_layer_diversity_bonus, 25.0)


class ApplicationSensorTests(unittest.TestCase):
    def test_detects_sqli_and_xss_signatures(self):
        sqli = score_payload("/items?id=1 UNION SELECT password FROM users")
        self.assertIn("SQL Injection", sqli["families"])
        self.assertGreater(sqli["payload_pattern_score"], 0.3)

        xss = score_payload("/search?q=<script>alert(1)</script>")
        self.assertIn("XSS", xss["families"])

        clean = score_payload("/api/products?page=2")
        self.assertEqual(clean["families"], [])
        self.assertEqual(clean["payload_pattern_score"], 0.0)

    def test_detects_url_encoded_injection(self):
        """Encoded payloads must not evade the signature scan."""
        encoded = score_payload("/p?id=1%27%20UNION%20SELECT%20pw%20FROM%20users")
        self.assertIn("SQL Injection", encoded["families"])

        double = score_payload("/p?q=%253Cscript%253Ealert(1)%253C/script%253E")
        self.assertIn("XSS", double["families"])
    def test_parses_combined_log_format(self):
        line = ('192.168.1.10 - - [08/Sep/2026:10:00:00 +0000] '
                '"GET /admin?id=1%20OR%201=1 HTTP/1.1" 403 512')
        parsed = ApplicationSensor.parse_line(line)
        self.assertEqual(parsed["client_ip"], "192.168.1.10")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["status"], 403)

    def test_parses_json_log_format(self):
        parsed = ApplicationSensor.parse_line(
            '{"remote_addr":"10.0.0.5","method":"POST","path":"/login","status":401}'
        )
        self.assertEqual(parsed["client_ip"], "10.0.0.5")
        self.assertEqual(parsed["status"], 401)

    def test_malformed_lines_are_ignored(self):
        for bad in ("", "   ", "not a log line", "{broken json"):
            self.assertIsNone(ApplicationSensor.parse_line(bad))

    def test_unavailable_without_log_paths(self):
        sensor = ApplicationSensor()
        sensor.config = type(sensor.config)(access_log_paths=[])
        cap = sensor.capability()
        self.assertFalse(cap["capture_possible"])
        self.assertEqual(cap["reason"], "no_log_paths_configured")

    def test_tails_real_file_and_emits_on_attack(self):
        """End-to-end: real file -> parse -> correlator -> application incident."""
        correlator = CrossLayerCorrelator()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "access.log")
            Path(log_path).write_text("", encoding="utf-8")

            os.environ["APPLICATION_LOG_PATHS"] = log_path
            try:
                sensor = ApplicationSensor(correlator=correlator)
                self.assertTrue(sensor.capability()["capture_possible"])
                sensor.start()

                # Realistic access-log lines: real servers percent-encode the
                # query string, so the payload arrives URL-encoded.
                encoded = "/p?id=1%27%20UNION%20SELECT%20pw%20FROM%20users"
                with open(log_path, "a", encoding="utf-8") as handle:
                    for _ in range(3):
                        handle.write(
                            '203.0.113.9 - - [08/Sep/2026:10:00:00 +0000] '
                            f'"GET {encoded} HTTP/1.1" 200 90\n'
                        )

                emitted = sensor.poll_once()
                sensor.stop()

                self.assertTrue(emitted, "expected an application detection")
                incidents = correlator.trajectory_engine.active_incidents
                self.assertEqual(len(incidents), 1)
                incident = list(incidents.values())[0]
                self.assertIn("application", incident.layers_involved)
                self.assertFalse(incident.is_simulated)
            finally:
                os.environ.pop("APPLICATION_LOG_PATHS", None)


class EndpointSensorTests(unittest.TestCase):
    def test_capability_reports_psutil(self):
        cap = EndpointSensor().capability()
        self.assertEqual(cap["sensor"], "endpoint")
        self.assertIn("capture_possible", cap)

    def test_flags_suspicious_parent_child_chain(self):
        sensor = EndpointSensor()
        record = sensor._build_record(
            "powershell.exe", "winword.exe", "-enc SQBFAFgA", "corp\\alice", False, 4242
        )
        self.assertTrue(record["chain_suspicious"])
        self.assertTrue(record["encoded_command"])
        self.assertTrue(record["is_notable"])

    def test_ignores_ordinary_process(self):
        sensor = EndpointSensor()
        record = sensor._build_record(
            "notepad.exe", "explorer.exe", "notepad.exe file.txt", "corp\\alice", False, 111
        )
        self.assertFalse(record["is_notable"])

    def test_real_process_scan_runs(self):
        """Observes the actual local process table via psutil."""
        sensor = EndpointSensor()
        sensor._prime_baseline()
        self.assertGreater(len(sensor._known_pids), 0)


class SovereigntyTests(unittest.TestCase):
    def test_local_sqlite_is_self_hosted(self):
        os.environ.pop("DATABASE_URL", None)
        report = data_sovereignty()
        self.assertEqual(report["hosting_model"], "self_hosted")
        self.assertFalse(report["sovereignty_properties"]["telemetry_leaves_host"])

    def test_managed_provider_is_flagged(self):
        os.environ["DATABASE_URL"] = "postgresql://u:p@db.example.supabase.co:5432/postgres"
        os.environ["REQUIRE_LOCAL_DATA_RESIDENCY"] = "true"
        try:
            report = data_sovereignty()
            self.assertEqual(report["hosting_model"], "third_party_managed")
            self.assertFalse(report["residency_compliant"])
            self.assertTrue(report["findings"])
        finally:
            os.environ.pop("DATABASE_URL", None)
            os.environ["REQUIRE_LOCAL_DATA_RESIDENCY"] = "false"

    def test_report_never_leaks_credentials(self):
        os.environ["DATABASE_URL"] = "postgresql://admin:SuperSecret123@db.example.supabase.co:5432/postgres"
        try:
            serialized = str(data_sovereignty()).lower()
            self.assertNotIn("supersecret123", serialized)
            self.assertNotIn("admin:", serialized)
        finally:
            os.environ.pop("DATABASE_URL", None)

    def test_local_models_asserted(self):
        props = data_sovereignty()["sovereignty_properties"]
        self.assertTrue(props["models_run_locally"])
        self.assertFalse(props["inference_sent_to_third_party"])


class SensorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_sensor_status_endpoint(self):
        res = self.client.get("/api/sensors/status")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("endpoint", body)
        self.assertIn("application", body)

    def test_coverage_reports_four_layers(self):
        res = self.client.get("/api/sensors/coverage")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["layers_total"], 4)
        self.assertEqual(set(body["layers"]), {"network", "endpoint", "identity", "application"})

    def test_sovereignty_endpoint(self):
        res = self.client.get("/api/sovereignty")
        self.assertEqual(res.status_code, 200)
        self.assertIn("hosting_model", res.json())

    def test_sensor_control_requires_privileged_role(self):
        self.assertEqual(self.client.post("/api/sensors/endpoint/start").status_code, 401)
        self.assertEqual(
            self.client.post("/api/sensors/endpoint/start",
                             headers={"X-Sentinel-Role": "guest"}).status_code,
            403,
        )

    def test_unknown_sensor_returns_404(self):
        res = self.client.get("/api/sensors/bogus/events")
        self.assertEqual(res.status_code, 404)

    def test_endpoint_sensor_start_stop_roundtrip(self):
        hdr = {"X-Sentinel-Role": "admin"}
        start = self.client.post("/api/sensors/endpoint/start", headers=hdr)
        self.assertIn(start.status_code, (200, 409))
        if start.status_code == 200:
            stop = self.client.post("/api/sensors/endpoint/stop", headers=hdr)
            self.assertEqual(stop.status_code, 200)

    def test_application_start_reports_reason_when_unconfigured(self):
        res = self.client.post("/api/sensors/application/start",
                               headers={"X-Sentinel-Role": "admin"})
        self.assertIn(res.status_code, (200, 409))
        if res.status_code == 409:
            self.assertIn("application_sensor_unavailable",
                          res.json()["error"]["message"])


if __name__ == "__main__":
    unittest.main()
