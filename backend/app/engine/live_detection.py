"""
Live Detection Engine
=====================

In-memory, fully SANDBOXED live-traffic detection layer for the Sentinel-AI research
platform. It has three responsibilities:

1. **Synthetic live telemetry** - generates realistic network / endpoint / identity
   events (majority benign, minority drawn from the 8 attack classes) and scores each
   one with the *real* trained models (`ThreatDetectionModels.get_instance().predict`).
2. **Risk fusion + rolling analytics** - fuses classifier confidence with the
   Isolation-Forest anomaly intensity into a 0-100 risk score, maps it to a severity
   band and a verdict, and maintains rolling counters (EPS, class/severity histograms,
   average confidence, average latency).
3. **Sandboxed automated response** - an in-memory auto-block list plus a *simulated*
   Deep-Q-Network adaptive policy that recommends a response action per detection and
   nudges the effective auto-block threshold.

Nothing in this module touches real firewalls, hosts, or OS networking. Every response
action is recorded in the sandboxed-actions audit table only.
"""

import random
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..database import log_sandboxed_action
from ..ml.dataset_generator import ATTACK_LABELS, FEATURE_NAMES
from ..ml.models import ThreatDetectionModels

# ---------------------------------------------------------------------------
# Static knowledge bases
# ---------------------------------------------------------------------------

#: Predicted class -> MITRE ATT&CK mapping. Benign traffic maps to nothing.
MITRE_TECHNIQUE_MAP: Dict[str, Dict[str, str]] = {
    "Brute Force": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "XSS": {
        "technique_id": "T1059.007",
        "technique": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
    },
    "Probe / Reconnaissance": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "Malware / C2 Beaconing": {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "Phishing": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
    },
    "Unauthorized Access": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Initial Access",
    },
}

#: Catalogue served by GET /api/detect/classes.
CLASS_CATALOG: List[Dict[str, Any]] = [
    {
        "id": 0,
        "name": "Benign",
        "description": "Normal business traffic: balanced I/O ratio, clean payloads, business-hours access.",
        "layer": "all",
        "severity_hint": "NONE",
    },
    {
        "id": 1,
        "name": "Brute Force",
        "description": "High-rate credential guessing against an authentication endpoint with a very high login failure rate.",
        "layer": "identity",
        "severity_hint": "HIGH",
    },
    {
        "id": 2,
        "name": "SQL Injection",
        "description": "Injected SQL syntax in request payloads targeting a public-facing application or database API.",
        "layer": "application",
        "severity_hint": "CRITICAL",
    },
    {
        "id": 3,
        "name": "XSS",
        "description": "Client-side script injection (script tags / encoded JavaScript) delivered through HTTP parameters.",
        "layer": "application",
        "severity_hint": "HIGH",
    },
    {
        "id": 4,
        "name": "DDoS",
        "description": "Volumetric flood: extreme request rate with small packets and near-zero session duration.",
        "layer": "network",
        "severity_hint": "CRITICAL",
    },
    {
        "id": 5,
        "name": "Probe / Reconnaissance",
        "description": "Horizontal or vertical port scanning: very large distinct-port breadth with tiny, incomplete sessions.",
        "layer": "network",
        "severity_hint": "MEDIUM",
    },
    {
        "id": 6,
        "name": "Malware / C2 Beaconing",
        "description": "Low-and-slow beaconing from a suspicious process with heavily skewed outbound byte ratio (exfiltration).",
        "layer": "endpoint",
        "severity_hint": "CRITICAL",
    },
    {
        "id": 7,
        "name": "Phishing",
        "description": "Credential harvesting via a lookalike or algorithmically generated domain with high URL entropy.",
        "layer": "identity",
        "severity_hint": "HIGH",
    },
    {
        "id": 8,
        "name": "Unauthorized Access",
        "description": "Valid-account misuse: privileged, off-hours session that looks normal but should not be happening.",
        "layer": "identity",
        "severity_hint": "HIGH",
    },
]

MODEL_DESCRIPTOR: Dict[str, Any] = {
    "classifier": "RandomForest",
    "anomaly": "IsolationForest",
    "classes": len(ATTACK_LABELS),
    "features": len(FEATURE_NAMES),
}

_PROTOCOL_BY_CODE = {0: "TCP", 1: "UDP", 2: "ICMP", 3: "HTTP"}

#: Benign action labels per layer. Attack-specific action names live in
#: ``_CLASS_PROFILE_META`` so a benign row is never labelled e.g. "port_scan_burst".
_ACTIONS_BY_LAYER = {
    "network": ["http_request", "network_flow", "dns_query", "tls_session"],
    "endpoint": ["process_create", "file_write", "registry_modify", "service_query"],
    "identity": ["auth_login_success", "token_issued", "session_refresh", "mfa_challenge"],
}

#: Which telemetry layer each class is generated on, and the action label to use.
_CLASS_PROFILE_META: Dict[int, Tuple[str, str]] = {
    0: ("", ""),  # benign: layer/action chosen at random
    1: ("identity", "auth_login_failed_burst"),
    2: ("network", "http_post_sqli_payload"),
    3: ("network", "http_request_script_payload"),
    4: ("network", "network_flow_flood"),
    5: ("network", "port_scan_burst"),
    6: ("endpoint", "beacon_callout"),
    7: ("identity", "credential_form_submit"),
    8: ("identity", "auth_login_success_off_hours"),
}

#: Sampling weights for the synthetic live stream (benign majority).
_STREAM_CLASS_WEIGHTS: Dict[int, float] = {
    0: 0.62,
    1: 0.05,
    2: 0.05,
    3: 0.045,
    4: 0.05,
    5: 0.045,
    6: 0.045,
    7: 0.045,
    8: 0.05,
}

# Severity band cut-offs applied to the fused 0-100 risk score.
SEVERITY_BANDS = ((85.0, "CRITICAL"), (65.0, "HIGH"), (40.0, "MEDIUM"), (0.0, "LOW"))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Simulated Deep Reinforcement Learning response policy
# ---------------------------------------------------------------------------

class AdaptiveResponsePolicy:
    """
    Simulated Deep Q-Network (DQN) response policy.

    This is a *research simulation*: there is no neural network training loop, but the
    policy behaves like a converging epsilon-greedy DQN agent:

    * every scored detection is treated as one environment step / episode,
    * the agent either explores (probability ``epsilon``) or exploits the highest-value
      action for the observed threat class,
    * a shaped reward shows whether the chosen action matched the threat class and the
      observed risk level,
    * Q-values are updated with a TD(0)-style rule ``Q <- Q + alpha * (r - Q)``,
    * ``epsilon`` decays geometrically towards ``EPSILON_MIN`` so the policy becomes
      progressively more deterministic (exploitation).
    """

    ALGORITHM = "Deep Q-Network (DQN)"
    ACTIONS = ["BLOCK_IP", "ISOLATE_HOST", "RATE_LIMIT", "MONITOR", "REVOKE_TOKEN"]

    EPSILON_START = 0.35
    EPSILON_MIN = 0.05
    EPSILON_DECAY = 0.997
    LEARNING_RATE = 0.08

    #: Ground-truth "best" action per threat class, used for reward shaping.
    OPTIMAL_ACTION: Dict[str, str] = {
        "Benign": "MONITOR",
        "Brute Force": "BLOCK_IP",
        "SQL Injection": "BLOCK_IP",
        "XSS": "RATE_LIMIT",
        "DDoS": "RATE_LIMIT",
        "Probe / Reconnaissance": "BLOCK_IP",
        "Malware / C2 Beaconing": "ISOLATE_HOST",
        "Phishing": "REVOKE_TOKEN",
        "Unauthorized Access": "REVOKE_TOKEN",
    }

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()
        self.episodes: int = 0
        self.epsilon: float = self.EPSILON_START
        self.total_reward: float = 0.0
        # Small optimistic priors so the exploitation path is meaningful from step 1.
        self.q_values: Dict[str, float] = {
            "BLOCK_IP": 0.55,
            "ISOLATE_HOST": 0.50,
            "RATE_LIMIT": 0.45,
            "MONITOR": 0.35,
            "REVOKE_TOKEN": 0.40,
        }
        self.selected_count: Dict[str, int] = {action: 0 for action in self.ACTIONS}
        self.reward_history: Deque[Dict[str, float]] = deque(maxlen=60)
        self.last_updated: str = _utc_now_iso()

    # -- internals ---------------------------------------------------------

    def _shaped_reward(self, action: str, predicted_class: str, risk_score: float) -> float:
        """
        Reward in [0.0, 1.0]. Matching the optimal action for the class earns the base
        reward; the risk level then rewards proportionate aggressiveness (aggressive
        actions on high risk, passive monitoring on low risk).
        """
        optimal = self.OPTIMAL_ACTION.get(predicted_class, "MONITOR")
        reward = 0.85 if action == optimal else 0.35

        aggressive = action in ("BLOCK_IP", "ISOLATE_HOST", "REVOKE_TOKEN")
        if risk_score >= 65.0:
            reward += 0.10 if aggressive else -0.20
        elif risk_score < 40.0:
            reward += 0.10 if action == "MONITOR" else -0.15

        reward += self._rng.uniform(-0.04, 0.04)  # environment noise
        return max(0.0, min(1.0, reward))

    # -- public API --------------------------------------------------------

    def _candidate_actions(self, predicted_class: str, risk_score: float) -> List[str]:
        """
        State-conditioned action mask. The observed state is (threat class, risk band),
        so the agent may only exploit actions that are proportionate to that state:
        aggressive containment on high risk, passive observation on low risk.
        """
        candidates = {self.OPTIMAL_ACTION.get(predicted_class, "MONITOR")}
        if risk_score >= 65.0:
            candidates.update(["BLOCK_IP", "ISOLATE_HOST", "REVOKE_TOKEN", "RATE_LIMIT"])
        elif risk_score < 40.0:
            candidates.update(["MONITOR", "RATE_LIMIT"])
        else:
            candidates.update(self.ACTIONS)
        return [a for a in self.ACTIONS if a in candidates]

    def recommend(self, predicted_class: str, risk_score: float) -> str:
        """
        Selects a response action for one detection (one DQN environment step) and
        performs the value update. Returns the selected action name.
        """
        candidates = self._candidate_actions(predicted_class, risk_score)
        if self._rng.random() < self.epsilon:
            action = self._rng.choice(self.ACTIONS)          # explore (unmasked)
        else:
            # Exploit: highest-value action available in the current state.
            action = max(candidates, key=lambda a: self.q_values[a])

        reward = self._shaped_reward(action, predicted_class, risk_score)

        self.episodes += 1
        self.selected_count[action] += 1
        self.q_values[action] += self.LEARNING_RATE * (reward - self.q_values[action])
        self.total_reward += reward
        self.epsilon = max(self.EPSILON_MIN, self.epsilon * self.EPSILON_DECAY)
        self.reward_history.append({"episode": self.episodes, "reward": round(reward, 4)})
        self.last_updated = _utc_now_iso()
        return action

    @property
    def avg_reward(self) -> float:
        if self.episodes == 0:
            return 0.0
        return round(self.total_reward / self.episodes, 4)

    def threshold_nudge(self) -> float:
        """
        Adaptive nudge (in risk points) applied to the configured auto-block threshold.

        A policy that is consistently well-rewarded (avg_reward > 0.5) has earned
        confidence and lowers the bar for blocking (more aggressive); a poorly performing
        policy raises it (more conservative). The nudge is capped at +/-8 points so the
        operator-configured threshold always dominates.
        """
        if self.episodes < 5:
            return 0.0
        return max(-8.0, min(8.0, -(self.avg_reward - 0.5) * 16.0))

    def snapshot(self, base_threshold: float, adaptive_enabled: bool, effective_threshold: float) -> Dict[str, Any]:
        return {
            "algorithm": self.ALGORITHM,
            "episodes": self.episodes,
            "epsilon": round(self.epsilon, 4),
            "avg_reward": self.avg_reward,
            "exploration_rate": round(self.epsilon, 4),
            "reward_history": list(self.reward_history),
            "actions": [
                {
                    "action": action,
                    "q_value": round(self.q_values[action], 4),
                    "selected_count": self.selected_count[action],
                }
                for action in self.ACTIONS
            ],
            "effective_threshold": round(effective_threshold, 2),
            "adaptive_enabled": adaptive_enabled,
            "last_updated": self.last_updated,
        }


# ---------------------------------------------------------------------------
# Live detection engine
# ---------------------------------------------------------------------------

class LiveDetectionEngine:
    """
    In-memory singleton that scores live/simulated telemetry with the trained models and
    owns the sandboxed auto-block list plus the adaptive response policy.
    """

    _instance: Optional["LiveDetectionEngine"] = None

    # Rolling EPS window in seconds.
    EPS_WINDOW_SEC = 10.0
    # Minimum spacing between two eps_history samples.
    EPS_SAMPLE_INTERVAL_SEC = 1.0

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rng = random.Random()
        self.started_at: float = time.time()

        self.models = ThreatDetectionModels.get_instance()
        self.policy = AdaptiveResponsePolicy(self._rng)

        # Rolling analytics
        self.total_events_processed: int = 0
        self.threats_detected: int = 0
        self.benign_count: int = 0
        self.class_distribution: Dict[str, int] = {name: 0 for name in ATTACK_LABELS.values()}
        self.severity_distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        self._confidence_sum: float = 0.0
        self._latency_sum_ms: float = 0.0
        self._event_times: Deque[float] = deque(maxlen=4000)
        self.eps_history: Deque[Dict[str, Any]] = deque(maxlen=60)
        self._last_eps_sample_ts: float = 0.0
        self._threats_at_last_sample: int = 0

        # Sandboxed auto-block subsystem
        self.blocklist: Dict[str, Dict[str, Any]] = {}
        self.config: Dict[str, Any] = {
            "auto_block_enabled": True,
            "threshold": 80.0,
            "adaptive_enabled": True,
        }
        self.auto_blocked_count: int = 0

    @classmethod
    def get_instance(cls) -> "LiveDetectionEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Risk fusion
    # ------------------------------------------------------------------

    @staticmethod
    def fuse_risk_score(
        predicted_class: str,
        confidence: float,
        class_probabilities: Dict[str, float],
        anomaly_intensity: float,
    ) -> float:
        """
        Fuses supervised and unsupervised evidence into a 0-100 risk score.

        ::

            attack_prob   = 1 - P(Benign)                     # aggregate malicious mass
            threat_signal = attack_prob                       # if predicted class is Benign
                          = 0.5*attack_prob + 0.5*confidence  # otherwise
            risk_score    = 100 * clamp(0.70*threat_signal + 0.30*anomaly_intensity, 0, 1)

        The supervised term dominates (70%) because it is class-aware, while the
        Isolation-Forest anomaly intensity contributes the remaining 30% so that
        zero-day-looking traffic still escalates even when the classifier says "Benign".
        """
        attack_prob = max(0.0, 1.0 - float(class_probabilities.get("Benign", 0.0)))
        if predicted_class == "Benign":
            threat_signal = attack_prob
        else:
            threat_signal = 0.5 * attack_prob + 0.5 * float(confidence)

        fused = 0.70 * threat_signal + 0.30 * float(anomaly_intensity)
        return round(100.0 * max(0.0, min(1.0, fused)), 2)

    @staticmethod
    def severity_for(risk_score: float) -> str:
        """Maps a fused risk score to LOW / MEDIUM / HIGH / CRITICAL."""
        for floor, label in SEVERITY_BANDS:
            if risk_score >= floor:
                return label
        return "LOW"

    @staticmethod
    def verdict_for(predicted_class: str, risk_score: float, is_anomaly: bool) -> str:
        """
        Three-state verdict:

        * ``malicious``  - an attack class with a materially high fused risk score,
        * ``suspicious`` - a weak attack signal or an unsupervised anomaly,
        * ``benign``     - nothing actionable.
        """
        is_attack = predicted_class != "Benign"
        if is_attack and risk_score >= 60.0:
            return "malicious"
        if (is_attack and risk_score >= 30.0) or (is_anomaly and risk_score >= 25.0):
            return "suspicious"
        return "benign"

    @staticmethod
    def mitre_for(predicted_class: str) -> Optional[Dict[str, str]]:
        """Returns the MITRE mapping for a predicted class (None for Benign)."""
        info = MITRE_TECHNIQUE_MAP.get(predicted_class)
        return dict(info) if info else None

    def effective_threshold(self) -> float:
        """Operator threshold plus the adaptive DQN nudge, clamped to a sane 50-95 band."""
        base = float(self.config["threshold"])
        if not self.config.get("adaptive_enabled", True):
            return base
        return round(max(50.0, min(95.0, base + self.policy.threshold_nudge())), 2)

    # ------------------------------------------------------------------
    # Core scoring
    # ------------------------------------------------------------------

    def analyze(
        self,
        detail: Dict[str, Any],
        source_ip: Optional[str] = None,
        layer: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scores one event with the real trained models and returns the full detection
        payload (the exact shape served by ``POST /api/detect/predict``).

        Also updates rolling analytics and, when the criteria are met, performs a
        sandboxed auto-block of ``source_ip``.
        """
        started = time.perf_counter()
        ml_res = self.models.predict(detail or {})
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)

        predicted_class = ml_res["label"]
        confidence = float(ml_res["confidence"])
        class_probabilities = ml_res.get("class_probabilities", {})
        anomaly_score = float(ml_res["anomaly_score"])
        is_anomaly = bool(ml_res["is_anomaly"])

        risk_score = self.fuse_risk_score(predicted_class, confidence, class_probabilities, anomaly_score)
        severity = self.severity_for(risk_score)
        verdict = self.verdict_for(predicted_class, risk_score, is_anomaly)
        recommended_action = self.policy.recommend(predicted_class, risk_score)

        self._record_detection(predicted_class, severity, confidence, latency_ms, verdict)

        auto_blocked = False
        if source_ip:
            auto_blocked = self._maybe_auto_block(
                ip=source_ip,
                predicted_class=predicted_class,
                risk_score=risk_score,
                confidence=confidence,
                verdict=verdict,
                recommended_action=recommended_action,
                layer=layer,
            )

        return {
            "predicted_class": predicted_class,
            "confidence": confidence,
            "class_probabilities": class_probabilities,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "verdict": verdict,
            "risk_score": risk_score,
            "severity": severity,
            "mitre": self.mitre_for(predicted_class),
            "recommended_action": recommended_action,
            "feature_importances": ml_res.get("feature_importances", {}),
            "feature_vector": ml_res.get("feature_vector", []),
            "model": dict(MODEL_DESCRIPTOR),
            "latency_ms": latency_ms,
            "_auto_blocked": auto_blocked,   # internal, stripped by the API layer
        }

    # ------------------------------------------------------------------
    # Synthetic live telemetry
    # ------------------------------------------------------------------

    def _random_internal_ip(self) -> str:
        return f"10.0.{self._rng.randint(0, 12)}.{self._rng.randint(2, 250)}"

    def _random_external_ip(self) -> str:
        prefix = self._rng.choice(["203.0.113", "198.51.100", "45.61.187", "185.220.101", "91.219.238"])
        return f"{prefix}.{self._rng.randint(2, 250)}"

    def _synthesize_event(self) -> Dict[str, Any]:
        """
        Builds one random raw telemetry event. The class is sampled from
        ``_STREAM_CLASS_WEIGHTS`` (benign majority) and the feature detail dict mirrors
        the training distributions in ``dataset_generator``.
        """
        rng = self._rng
        classes = list(_STREAM_CLASS_WEIGHTS.keys())
        weights = [_STREAM_CLASS_WEIGHTS[c] for c in classes]
        class_idx = rng.choices(classes, weights=weights, k=1)[0]

        if class_idx == 0:
            layer = rng.choice(["network", "endpoint", "identity"])
            action = rng.choice(_ACTIONS_BY_LAYER[layer])
            detail = {
                "packet_size": max(40.0, rng.gauss(500, 150)),
                "protocol": _PROTOCOL_BY_CODE[rng.choices([0, 1, 3], weights=[0.5, 0.2, 0.3], k=1)[0]],
                "request_rate": rng.uniform(0.5, 5.0),
                "session_duration": rng.expovariate(1 / 30.0),
                "payload_pattern_score": rng.uniform(0.0, 0.15),
                "login_failure_rate": rng.uniform(0.0, 0.1),
                "is_suspicious_process": False,
                "privilege_escalation": rng.random() < 0.1,
                "distinct_ports_touched": rng.randint(1, 5),
                "url_entropy": rng.uniform(0.02, 0.25),
                "outbound_bytes_ratio": max(0.05, rng.gauss(1.0, 0.25)),
                "off_hours_access": 1 if rng.random() < 0.08 else 0,
            }
            src_ip = self._random_internal_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 1:   # Brute Force
            layer, action = _CLASS_PROFILE_META[1]
            detail = {
                "packet_size": max(40.0, rng.gauss(300, 50)),
                "protocol": "HTTP",
                "request_rate": rng.uniform(15.0, 50.0),
                "session_duration": rng.uniform(1.0, 10.0),
                "payload_pattern_score": rng.uniform(0.1, 0.3),
                "login_failure_rate": rng.uniform(0.85, 1.0),
                "is_suspicious_process": False,
                "privilege_escalation": False,
                "distinct_ports_touched": rng.randint(1, 2),
                "url_entropy": rng.uniform(0.05, 0.3),
                "outbound_bytes_ratio": max(0.05, rng.gauss(0.9, 0.2)),
                "off_hours_access": rng.randint(0, 1),
            }
            src_ip = self._random_external_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 2:   # SQL Injection
            layer, action = _CLASS_PROFILE_META[2]
            detail = {
                "packet_size": max(40.0, rng.gauss(1200, 300)),
                "protocol": "HTTP",
                "request_rate": rng.uniform(1.0, 8.0),
                "session_duration": rng.uniform(2.0, 20.0),
                "payload_pattern_score": rng.uniform(0.75, 1.0),
                "login_failure_rate": rng.uniform(0.0, 0.2),
                "is_suspicious_process": rng.random() < 0.3,
                "privilege_escalation": rng.random() < 0.4,
                "distinct_ports_touched": rng.randint(1, 3),
                "url_entropy": rng.uniform(0.25, 0.55),
                "outbound_bytes_ratio": rng.uniform(0.8, 2.5),
                "off_hours_access": 1 if rng.random() < 0.35 else 0,
            }
            src_ip = self._random_external_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 3:   # XSS
            layer, action = _CLASS_PROFILE_META[3]
            detail = {
                "packet_size": max(40.0, rng.gauss(900, 200)),
                "protocol": "HTTP",
                "request_rate": rng.uniform(2.0, 10.0),
                "session_duration": rng.uniform(1.0, 15.0),
                "payload_pattern_score": rng.uniform(0.70, 0.98),
                "login_failure_rate": rng.uniform(0.0, 0.15),
                "is_suspicious_process": False,
                "privilege_escalation": False,
                "distinct_ports_touched": rng.randint(1, 3),
                "url_entropy": rng.uniform(0.3, 0.6),
                "outbound_bytes_ratio": rng.uniform(0.7, 1.8),
                "off_hours_access": 1 if rng.random() < 0.3 else 0,
            }
            src_ip = self._random_external_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 4:   # DDoS
            layer, action = _CLASS_PROFILE_META[4]
            detail = {
                "packet_size": max(40.0, rng.gauss(150, 40)),
                "protocol": _PROTOCOL_BY_CODE[rng.choices([0, 1, 2], weights=[0.4, 0.4, 0.2], k=1)[0]],
                "request_rate": rng.uniform(200.0, 1000.0),
                "session_duration": rng.uniform(0.1, 2.0),
                "payload_pattern_score": rng.uniform(0.0, 0.2),
                "login_failure_rate": 0.0,
                "is_suspicious_process": False,
                "privilege_escalation": False,
                "distinct_ports_touched": rng.randint(1, 3),
                "url_entropy": rng.uniform(0.0, 0.2),
                "outbound_bytes_ratio": rng.uniform(0.05, 0.4),
                "off_hours_access": 1 if rng.random() < 0.4 else 0,
            }
            src_ip = self._random_external_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 5:   # Probe / Reconnaissance
            layer, action = _CLASS_PROFILE_META[5]
            detail = {
                "packet_size": max(40.0, rng.gauss(80, 25)),
                "protocol": _PROTOCOL_BY_CODE[rng.choices([0, 2], weights=[0.75, 0.25], k=1)[0]],
                "request_rate": rng.uniform(8.0, 80.0),
                "session_duration": rng.uniform(0.02, 1.5),
                "payload_pattern_score": rng.uniform(0.0, 0.15),
                "login_failure_rate": rng.uniform(0.0, 0.1),
                "is_suspicious_process": False,
                "privilege_escalation": False,
                "distinct_ports_touched": rng.randint(50, 500),
                "url_entropy": rng.uniform(0.0, 0.15),
                "outbound_bytes_ratio": rng.uniform(1.5, 6.0),
                "off_hours_access": 1 if rng.random() < 0.55 else 0,
            }
            src_ip = self._random_external_ip()
            dest_ip = self._random_internal_ip()

        elif class_idx == 6:   # Malware / C2 Beaconing
            layer, action = _CLASS_PROFILE_META[6]
            detail = {
                "packet_size": max(40.0, rng.gauss(280, 35)),
                "protocol": _PROTOCOL_BY_CODE[rng.choices([0, 3], weights=[0.35, 0.65], k=1)[0]],
                "request_rate": rng.uniform(0.05, 1.5),
                "session_duration": rng.uniform(45.0, 400.0),
                "payload_pattern_score": rng.uniform(0.3, 0.65),
                "login_failure_rate": rng.uniform(0.0, 0.1),
                "is_suspicious_process": True,
                "parent_process": rng.choice(["cmd.exe", "powershell.exe", "wscript.exe"]),
                "privilege_escalation": rng.random() < 0.7,
                "distinct_ports_touched": rng.randint(1, 4),
                "url_entropy": rng.uniform(0.35, 0.75),
                "outbound_bytes_ratio": rng.uniform(5.0, 40.0),
                "off_hours_access": 1 if rng.random() < 0.6 else 0,
            }
            src_ip = self._random_internal_ip()
            dest_ip = self._random_external_ip()

        elif class_idx == 7:   # Phishing
            layer, action = _CLASS_PROFILE_META[7]
            detail = {
                "packet_size": max(40.0, rng.gauss(750, 180)),
                "protocol": "HTTP",
                "request_rate": rng.uniform(0.5, 6.0),
                "session_duration": rng.uniform(3.0, 60.0),
                "payload_pattern_score": rng.uniform(0.2, 0.5),
                "login_failure_rate": rng.uniform(0.0, 0.15),
                "is_suspicious_process": False,
                "privilege_escalation": False,
                "distinct_ports_touched": rng.randint(1, 3),
                "url_entropy": rng.uniform(0.7, 1.0),
                "outbound_bytes_ratio": rng.uniform(1.2, 3.5),
                "off_hours_access": 1 if rng.random() < 0.45 else 0,
            }
            src_ip = self._random_internal_ip()
            dest_ip = self._random_external_ip()

        else:                  # 8 - Unauthorized Access
            layer, action = _CLASS_PROFILE_META[8]
            detail = {
                "packet_size": max(40.0, rng.gauss(520, 130)),
                "protocol": _PROTOCOL_BY_CODE[rng.choices([0, 3], weights=[0.4, 0.6], k=1)[0]],
                "request_rate": rng.uniform(0.5, 6.0),
                "session_duration": rng.uniform(20.0, 300.0),
                "payload_pattern_score": rng.uniform(0.0, 0.25),
                "login_failure_rate": rng.uniform(0.2, 0.5),
                "is_suspicious_process": rng.random() < 0.2,
                "privilege_escalation": True,
                "user_role": "admin",
                "distinct_ports_touched": rng.randint(1, 7),
                "url_entropy": rng.uniform(0.05, 0.3),
                "outbound_bytes_ratio": rng.uniform(0.8, 3.0),
                "off_hours_access": 1,
            }
            src_ip = self._random_external_ip() if rng.random() < 0.6 else self._random_internal_ip()
            dest_ip = self._random_internal_ip()

        return {
            "layer": layer,
            "action": action,
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "detail": detail,
        }

    def generate_stream(self, count: int = 6) -> Dict[str, Any]:
        """
        Generates ``count`` synthetic live events, scores each with the real models and
        returns the payload served by ``GET /api/detect/stream``.
        """
        count = max(1, min(50, int(count)))
        detections: List[Dict[str, Any]] = []

        for _ in range(count):
            raw = self._synthesize_event()
            result = self.analyze(raw["detail"], source_ip=raw["source_ip"], layer=raw["layer"])
            mitre = result["mitre"]
            detections.append({
                "id": f"det-{uuid.uuid4().hex[:10]}",
                "timestamp": _utc_now_iso(),
                "source_ip": raw["source_ip"],
                "dest_ip": raw["dest_ip"],
                "layer": raw["layer"],
                "action": raw["action"],
                "protocol": str(raw["detail"].get("protocol", "TCP")),
                "predicted_class": result["predicted_class"],
                "confidence": result["confidence"],
                "verdict": result["verdict"],
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "anomaly_score": result["anomaly_score"],
                "is_anomaly": result["is_anomaly"],
                "mitre_id": mitre["technique_id"] if mitre else None,
                "recommended_action": result["recommended_action"],
                "auto_blocked": result["_auto_blocked"],
                "packet_size": round(float(raw["detail"].get("packet_size", 0.0)), 2),
                "request_rate": round(float(raw["detail"].get("request_rate", 0.0)), 2),
                "latency_ms": result["latency_ms"],
            })

        return {
            "generated_at": _utc_now_iso(),
            "events_per_second": self.events_per_second(),
            "detections": detections,
        }

    # ------------------------------------------------------------------
    # Rolling analytics
    # ------------------------------------------------------------------

    def _record_detection(
        self,
        predicted_class: str,
        severity: str,
        confidence: float,
        latency_ms: float,
        verdict: str,
    ) -> None:
        with self._lock:
            self.total_events_processed += 1
            self.class_distribution[predicted_class] = self.class_distribution.get(predicted_class, 0) + 1
            self.severity_distribution[severity] = self.severity_distribution.get(severity, 0) + 1
            self._confidence_sum += confidence
            self._latency_sum_ms += latency_ms
            self._event_times.append(time.time())
            if verdict == "benign":
                self.benign_count += 1
            else:
                self.threats_detected += 1
        self._sample_eps_point()

    def events_per_second(self) -> float:
        """Rolling EPS over the last ``EPS_WINDOW_SEC`` seconds."""
        cutoff = time.time() - self.EPS_WINDOW_SEC
        with self._lock:
            recent = sum(1 for t in self._event_times if t >= cutoff)
        return round(recent / self.EPS_WINDOW_SEC, 2)

    def _sample_eps_point(self) -> None:
        """Appends an ``eps_history`` sample at most once per second."""
        now = time.time()
        with self._lock:
            if now - self._last_eps_sample_ts < self.EPS_SAMPLE_INTERVAL_SEC:
                return
            self._last_eps_sample_ts = now
            threats_delta = self.threats_detected - self._threats_at_last_sample
            self._threats_at_last_sample = self.threats_detected
            self.eps_history.append({
                "t": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "eps": self.events_per_second(),
                "threats": threats_delta,
            })

    def stats_overview(self) -> Dict[str, Any]:
        """Payload served by ``GET /api/stats/overview``."""
        self._sample_eps_point()
        metrics = self.models.metrics or {}
        model_accuracy = metrics.get("f1_score") or metrics.get("precision") or 0.0
        with self._lock:
            processed = self.total_events_processed
            avg_conf = round(self._confidence_sum / processed, 4) if processed else 0.0
            avg_latency = round(self._latency_sum_ms / processed, 3) if processed else 0.0
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "total_events_processed": processed,
                "events_per_second": self.events_per_second(),
                "threats_detected": self.threats_detected,
                "benign_count": self.benign_count,
                "auto_blocked_count": self.auto_blocked_count,
                "avg_confidence": avg_conf,
                "avg_latency_ms": avg_latency,
                "model_accuracy": round(float(model_accuracy), 4),
                "class_distribution": dict(self.class_distribution),
                "severity_distribution": dict(self.severity_distribution),
                "eps_history": list(self.eps_history),
            }

    # ------------------------------------------------------------------
    # Sandboxed auto-block subsystem
    # ------------------------------------------------------------------

    def _audit(self, ip: str, mode: str, reason: str) -> None:
        """Persists a block into the sandboxed-actions audit table (never a real firewall)."""
        try:
            log_sandboxed_action(
                action_id=f"act-{uuid.uuid4().hex[:8]}",
                action_type="BLOCK_IP",
                target_id=ip,
                incident_id=f"live-{mode.lower()}-block",
                status="EXECUTED_SANDBOXED",
                message=f"[SANDBOXED] {mode} block applied to {ip}. {reason} No real firewall change executed.",
                timestamp=_utc_now_iso(),
            )
        except Exception as exc:  # audit must never break the detection path
            print(f"[LiveDetection] Audit log failed for {ip}: {exc}")

    def _upsert_block(
        self,
        ip: str,
        attack_type: str,
        risk_score: float,
        confidence: float,
        mode: str,
        reason: str,
    ) -> Dict[str, Any]:
        with self._lock:
            entry = self.blocklist.get(ip)
            if entry:
                # Repeat offender: keep the original blocked_at, escalate the evidence.
                entry["hits"] += 1
                entry["attack_type"] = attack_type or entry["attack_type"]
                entry["risk_score"] = max(float(entry.get("risk_score", 0.0)), round(float(risk_score), 2))
                entry["confidence"] = max(float(entry.get("confidence", 0.0)), round(float(confidence), 4))
                entry["reason"] = reason or entry["reason"]
                entry["mode"] = entry.get("mode", mode)
            else:
                entry = {
                    "ip": ip,
                    "attack_type": attack_type or "Unknown",
                    "risk_score": round(float(risk_score), 2),
                    "confidence": round(float(confidence), 4),
                    "mode": mode,
                    "reason": reason,
                    "blocked_at": _utc_now_iso(),
                    "hits": 1,
                }
                self.blocklist[ip] = entry
            if mode == "AUTO":
                self.auto_blocked_count += 1
            snapshot = dict(entry)
        self._audit(ip, mode, reason)
        return snapshot

    def _maybe_auto_block(
        self,
        ip: str,
        predicted_class: str,
        risk_score: float,
        confidence: float,
        verdict: str,
        recommended_action: str,
        layer: Optional[str] = None,
    ) -> bool:
        """
        Auto-blocks ``ip`` when auto-block is enabled, the verdict is malicious and the
        fused risk score reaches the (optionally policy-adjusted) threshold.
        """
        if not self.config.get("auto_block_enabled", True):
            return False
        if verdict != "malicious":
            return False
        threshold = self.effective_threshold()
        if risk_score < threshold:
            return False

        origin = f" on the {layer} layer" if layer else ""
        reason = (
            f"Auto-blocked: {predicted_class} detected{origin} with risk {risk_score:.1f} "
            f">= threshold {threshold:.1f} (policy action {recommended_action})."
        )
        self._upsert_block(
            ip=ip,
            attack_type=predicted_class,
            risk_score=risk_score,
            confidence=confidence,
            mode="AUTO",
            reason=reason,
        )
        return True

    def manual_block(
        self,
        ip: str,
        attack_type: Optional[str] = None,
        risk_score: Optional[float] = None,
        confidence: Optional[float] = None,
        reason: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyst-driven (or API-driven) sandboxed block. Returns the created/updated entry."""
        return self._upsert_block(
            ip=ip,
            attack_type=attack_type or "Analyst Designated",
            risk_score=risk_score if risk_score is not None else 100.0,
            confidence=confidence if confidence is not None else 1.0,
            mode=(mode or "MANUAL").upper(),
            reason=reason or "Manual analyst block (sandboxed).",
        )

    def unblock(self, ip: str) -> bool:
        """Removes an IP from the sandboxed blocklist. Returns False when absent."""
        with self._lock:
            if ip not in self.blocklist:
                return False
            del self.blocklist[ip]
        self._audit(ip, "UNBLOCK", "Entry removed from sandboxed blocklist.")
        return True

    def get_blocklist(self) -> Dict[str, Any]:
        """Payload served by ``GET /api/defense/blocklist``."""
        with self._lock:
            entries = sorted(self.blocklist.values(), key=lambda e: e["blocked_at"], reverse=True)
            return {
                "auto_block_enabled": bool(self.config["auto_block_enabled"]),
                "threshold": float(self.config["threshold"]),
                "adaptive_enabled": bool(self.config["adaptive_enabled"]),
                "count": len(entries),
                "entries": [dict(e) for e in entries],
            }

    def update_config(
        self,
        auto_block_enabled: Optional[bool] = None,
        threshold: Optional[float] = None,
        adaptive_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Partially updates the auto-block configuration and returns the new config."""
        with self._lock:
            if auto_block_enabled is not None:
                self.config["auto_block_enabled"] = bool(auto_block_enabled)
            if threshold is not None:
                self.config["threshold"] = float(max(0.0, min(100.0, float(threshold))))
            if adaptive_enabled is not None:
                self.config["adaptive_enabled"] = bool(adaptive_enabled)
            config = dict(self.config)
        config["effective_threshold"] = self.effective_threshold()
        return config

    def policy_snapshot(self) -> Dict[str, Any]:
        """Payload served by ``GET /api/defense/policy``."""
        return self.policy.snapshot(
            base_threshold=float(self.config["threshold"]),
            adaptive_enabled=bool(self.config["adaptive_enabled"]),
            effective_threshold=self.effective_threshold(),
        )
