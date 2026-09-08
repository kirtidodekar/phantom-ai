from typing import Dict, Any, Tuple
from ..schemas import NormalizedEvent, Incident
from .normalizer import normalize_event
from .rules import SecurityRulesEngine
from .trajectory import ThreatTrajectoryEngine
from ..ml.models import ThreatDetectionModels

class CrossLayerCorrelator:
    """
    Main orchestration engine. Receives raw telemetry from any source (Network, Endpoint, Identity),
    normalizes it, evaluates ML models & deterministic rules, and passes it to ThreatTrajectoryEngine.
    """
    def __init__(self):
        self.trajectory_engine = ThreatTrajectoryEngine()
        self.ml_models = ThreatDetectionModels.get_instance()
        self.asset_criticality_map: Dict[str, str] = {}  # entity_id -> "Standard" | "High Value Target"

    def process_raw_telemetry(self, raw_telemetry: Dict[str, Any]) -> Tuple[NormalizedEvent, Incident]:
        """
        Process single raw telemetry event through normalization -> ML/Rules -> Correlation -> Trajectory update.
        """
        # 1. Normalize
        event = normalize_event(raw_telemetry)

        # 2. ML Inference (Random Forest + Isolation Forest)
        ml_res = self.ml_models.predict(event.detail)

        # 3. Deterministic Rules Evaluation
        rule_hit = SecurityRulesEngine.evaluate_event(event)

        # 4. Check Asset Criticality
        criticality = self.asset_criticality_map.get(event.entity_id, "Standard")

        # 5. Fuse & Update Threat Trajectory
        incident = self.trajectory_engine.process_event(
            event=event,
            ml_res=ml_res,
            rule_hit=rule_hit,
            asset_criticality=criticality
        )

        return event, incident

    def set_asset_criticality(self, entity_id: str, criticality: str):
        self.asset_criticality_map[entity_id] = criticality
        # If active incident exists for this entity, re-evaluate risk score
        incident_id = self.trajectory_engine.entity_incident_map.get(entity_id)
        if incident_id and incident_id in self.trajectory_engine.active_incidents:
            incident = self.trajectory_engine.active_incidents[incident_id]
            incident.asset_criticality = criticality
            rb = self.trajectory_engine.calculate_transparent_risk_score(incident, criticality)
            incident.threat_score = rb.total_score
            incident.risk_breakdown = rb

    def reset_state(self):
        self.trajectory_engine.reset()
