from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    event_id: str = Field(..., description="Unique event ID e.g. evt-000123")
    timestamp: str = Field(..., description="ISO 8601 timestamp string")
    layer: str = Field(..., description="Telemetry layer: network | endpoint | identity")
    entity_id: str = Field(..., description="Entity identifier e.g. user:alice / host:WKS-042")
    action: str = Field(..., description="Action taken e.g. login_fail, process_create, network_flow")
    detail: Dict[str, Any] = Field(default_factory=dict, description="Layer-specific fields")
    source_confidence: str = Field(default="high", description="high | medium | low")
    
    # Optional metadata populated by engines
    detection_source: Optional[str] = None  # "rf_classifier" | "isolation_forest" | "rule"
    attack_type: Optional[str] = None       # "Brute Force" | "SQL Injection" | "XSS" | "DDoS" | "Anomaly" | "Benign"
    confidence_score: Optional[float] = 0.0
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_id: Optional[str] = None
    is_simulated: bool = True

class FeatureVector(BaseModel):
    packet_size: float = 0.0
    protocol_type: int = 0  # 0: TCP, 1: UDP, 2: ICMP, 3: HTTP
    request_rate: float = 0.0
    session_duration: float = 0.0
    payload_pattern_score: float = 0.0
    login_failure_rate: float = 0.0
    is_suspicious_process: int = 0
    privilege_level: int = 0

class MLClassificationResult(BaseModel):
    label: str
    confidence: float
    feature_importances: Dict[str, float]
    is_anomaly: bool
    anomaly_score: float

class MitreTag(BaseModel):
    tactic: str
    technique: str
    technique_id: str
    description: str

class RiskBreakdown(BaseModel):
    total_score: float
    evidence_score: float
    cross_layer_diversity_bonus: float
    temporal_sequence_score: float
    asset_criticality_boost: float
    benign_context_adjustment: float
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    formula_explanation: str

class AttackGraphNode(BaseModel):
    id: str
    label: str
    type: str  # user | host | process | destination | api
    layer: str
    status: str  # normal | suspicious | compromised

class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    layer: str

class IncidentEvidence(BaseModel):
    event: NormalizedEvent
    rule_name: Optional[str] = None
    ml_confidence: float = 0.0
    contribution_score: float = 0.0

class Incident(BaseModel):
    incident_id: str
    title: str
    status: str = "ACTIVE"  # ACTIVE | INVESTIGATING | RESOLVED | MITIGATED
    created_at: str
    updated_at: str
    primary_entity: str
    affected_entities: List[str]
    layers_involved: List[str]
    threat_score: float
    prev_threat_score: float = 0.0
    score_history: List[Dict[str, Any]] = Field(default_factory=list) # [{"timestamp": ..., "score": ...}]
    risk_breakdown: Optional[RiskBreakdown] = None
    evidences: List[IncidentEvidence] = Field(default_factory=list)
    attack_story: List[str] = Field(default_factory=list)
    mitre_mappings: List[MitreTag] = Field(default_factory=list)
    graph_nodes: List[AttackGraphNode] = Field(default_factory=list)
    graph_edges: List[AttackGraphEdge] = Field(default_factory=list)
    asset_criticality: str = "Standard"  # Standard | High Value Target
    is_simulated: bool = True

class ModelEvaluationMetrics(BaseModel):
    dataset_name: str
    total_samples: int
    train_samples: int
    test_samples: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    confusion_matrix: List[List[int]]
    class_report: Dict[str, Any]
    feature_importances: Dict[str, float]

class AnalystFeedback(BaseModel):
    incident_id: str
    event_id: Optional[str] = None
    feedback_type: str  # USEFUL | FALSE_POSITIVE | BENIGN
    notes: Optional[str] = ""
    tuned_threshold: Optional[float] = None

class SandboxedActionRequest(BaseModel):
    action_type: str  # ISOLATE_HOST | BLOCK_IP | REVOKE_TOKEN
    target_id: str
    incident_id: str

class SandboxedActionResponse(BaseModel):
    action_id: str
    status: str
    message: str
    timestamp: str
    is_sandboxed: bool = True
