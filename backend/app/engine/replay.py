import time
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Generator, Optional, Tuple
from .correlator import CrossLayerCorrelator
from ..schemas import NormalizedEvent, Incident

DEMO_ENTITY = "user:alice / host:WKS-042"

STAGE_1_BASELINE = [
    {
        "event_id": "evt-demo-001",
        "timestamp_offset_sec": 0,
        "layer": "network",
        "entity_id": DEMO_ENTITY,
        "action": "http_request",
        "detail": {
            "src_ip": "10.0.4.15",
            "dest_ip": "10.0.0.1",
            "packet_size": 450,
            "protocol": "HTTP",
            "request_rate": 2.1,
            "session_duration": 12.0,
            "payload_pattern_score": 0.05,
            "url": "/dashboard/home"
        },
        "source_confidence": "high",
        "is_simulated": True
    },
    {
        "event_id": "evt-demo-002",
        "timestamp_offset_sec": 2,
        "layer": "identity",
        "entity_id": DEMO_ENTITY,
        "action": "auth_login_success",
        "detail": {
            "username": "alice",
            "src_ip": "10.0.4.15",
            "user_role": "analyst",
            "failed_login_count": 0,
            "login_failure_rate": 0.0
        },
        "source_confidence": "high",
        "is_simulated": True
    }
]

STAGE_2_BRUTE_FORCE = [
    {
        "event_id": "evt-demo-003",
        "timestamp_offset_sec": 5,
        "layer": "identity",
        "entity_id": DEMO_ENTITY,
        "action": "auth_login_failed_burst",
        "detail": {
            "username": "alice",
            "src_ip": "198.51.100.88", # unusual external IP
            "failed_login_count": 8,
            "total_login_attempts": 10,
            "login_failure_rate": 0.80,
            "request_rate": 25.0
        },
        "source_confidence": "high",
        "is_simulated": True
    }
]

STAGE_3_UNUSUAL_LOGIN = [
    {
        "event_id": "evt-demo-004",
        "timestamp_offset_sec": 10,
        "layer": "identity",
        "entity_id": DEMO_ENTITY,
        "action": "auth_login_success_anomalous_context",
        "detail": {
            "username": "alice",
            "src_ip": "198.51.100.88", # login succeeded after brute force from external IP!
            "user_role": "analyst",
            "failed_login_count": 0,
            "login_failure_rate": 0.10,
            "privilege_escalation": False,
            "geolocation": "Unknown Autonomous System (AS9941)"
        },
        "source_confidence": "high",
        "is_simulated": True
    }
]

STAGE_4_ENDPOINT_EXPLOIT = [
    {
        "event_id": "evt-demo-005",
        "timestamp_offset_sec": 15,
        "layer": "endpoint",
        "entity_id": DEMO_ENTITY,
        "action": "process_create",
        "detail": {
            "process_name": "powershell.exe",
            "parent_process": "cmd.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc IEV4K... (DownloadString)",
            "is_suspicious_process": True,
            "privilege_escalation": True,
            "user_role": "SYSTEM"
        },
        "source_confidence": "high",
        "is_simulated": True
    }
]

STAGE_5_NETWORK_EXFIL_SQLI = [
    {
        "event_id": "evt-demo-006",
        "timestamp_offset_sec": 20,
        "layer": "network",
        "entity_id": DEMO_ENTITY,
        "action": "http_post_sqli_payload",
        "detail": {
            "src_ip": "10.0.4.15",
            "dest_ip": "198.51.100.99", # C2 Server
            "packet_size": 1850,
            "protocol": "HTTP",
            "request_rate": 8.5,
            "session_duration": 45.0,
            "payload_pattern_score": 0.95,
            "payload": "SELECT * FROM users WHERE '1'='1' UNION SELECT credit_card, ssn FROM customer_db --",
            "url": "/api/v1/query"
        },
        "source_confidence": "high",
        "is_simulated": True
    }
]

DEMO_SCENARIO_STAGES = [
    ("Stage 1: Baseline Normal State", STAGE_1_BASELINE),
    ("Stage 2: Identity Brute Force Attack", STAGE_2_BRUTE_FORCE),
    ("Stage 3: Compromised Account Login", STAGE_3_UNUSUAL_LOGIN),
    ("Stage 4: Endpoint Process Escalation", STAGE_4_ENDPOINT_EXPLOIT),
    ("Stage 5: Network SQLi Data Exfiltration", STAGE_5_NETWORK_EXFIL_SQLI)
]

class IncidentReplayEngine:
    def __init__(self, correlator: CrossLayerCorrelator):
        self.correlator = correlator
        self.current_step = 0
        self.total_steps = len(DEMO_SCENARIO_STAGES)
        self.is_playing = False

    def reset(self):
        self.current_step = 0
        self.is_playing = False
        self.correlator.reset_state()

    def get_all_raw_events(self) -> List[Dict[str, Any]]:
        all_events = []
        base_time = datetime.now(timezone.utc)
        for stage_name, events in DEMO_SCENARIO_STAGES:
            for ev in events:
                ev_copy = dict(ev)
                ev_copy["timestamp"] = (base_time + timedelta(seconds=ev["timestamp_offset_sec"])).strftime("%Y-%m-%dT%H:%M:%SZ")
                ev_copy["stage_name"] = stage_name
                all_events.append(ev_copy)
        return all_events

    def step_next(self) -> Optional[Tuple[str, List[NormalizedEvent], Incident]]:
        """
        Executes next stage in sequence and returns (stage_name, processed_events, incident).
        """
        if self.current_step >= len(DEMO_SCENARIO_STAGES):
            return None

        stage_name, events = DEMO_SCENARIO_STAGES[self.current_step]
        self.current_step += 1

        processed_events = []
        last_incident = None
        base_time = datetime.now(timezone.utc)

        for ev in events:
            ev_copy = dict(ev)
            ev_copy["timestamp"] = (base_time + timedelta(seconds=ev["timestamp_offset_sec"])).strftime("%Y-%m-%dT%H:%M:%SZ")
            norm_event, incident = self.correlator.process_raw_telemetry(ev_copy)
            processed_events.append(norm_event)
            last_incident = incident

        return stage_name, processed_events, last_incident

    def run_full_replay(self) -> Tuple[List[NormalizedEvent], Incident]:
        """
        Runs full 5-stage scenario synchronously and returns all events and final fused incident.
        """
        self.reset()
        all_events = []
        last_incident = None
        while self.current_step < len(DEMO_SCENARIO_STAGES):
            res = self.step_next()
            if res:
                _, events, inc = res
                all_events.extend(events)
                last_incident = inc
        return all_events, last_incident
