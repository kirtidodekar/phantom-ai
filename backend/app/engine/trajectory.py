import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from ..schemas import (
    NormalizedEvent, Incident, IncidentEvidence, RiskBreakdown,
    AttackGraphNode, AttackGraphEdge, MitreTag
)
from .mitre import map_event_to_mitre

class ThreatTrajectoryEngine:
    """
    Manages active stateful Incidents per entity (user/host), fuses evidence across
    Network, Endpoint, and Identity layers, and computes transparent risk trajectory scores.
    """
    def __init__(self):
        self.active_incidents: Dict[str, Incident] = {}  # incident_id -> Incident
        self.entity_incident_map: Dict[str, str] = {}    # entity_id -> incident_id

    def process_event(
        self,
        event: NormalizedEvent,
        ml_res: Dict[str, Any],
        rule_hit: Optional[Dict[str, Any]],
        asset_criticality: str = "Standard"
    ) -> Incident:
        """
        Ingests a normalized event, correlates with existing entity incident or spawns new incident,
        and recalculates the threat trajectory score and graph.
        """
        entity_id = event.entity_id
        incident_id = self.entity_incident_map.get(entity_id)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not incident_id or incident_id not in self.active_incidents:
            incident_id = f"INC-2026-{uuid.uuid4().hex[:6].upper()}"
            self.entity_incident_map[entity_id] = incident_id
            
            user_part = entity_id.split("/")[0].replace("user:", "").strip() if "user:" in entity_id else "alice"
            host_part = entity_id.split("/")[-1].replace("host:", "").strip() if "host:" in entity_id else "WKS-042"

            incident = Incident(
                incident_id=incident_id,
                title=f"Multistage Threat Trajectory on {host_part} ({user_part})",
                status="ACTIVE",
                created_at=now_str,
                updated_at=now_str,
                primary_entity=entity_id,
                affected_entities=[entity_id],
                layers_involved=[event.layer],
                threat_score=0.0,
                prev_threat_score=0.0,
                score_history=[],
                evidences=[],
                attack_story=[],
                mitre_mappings=[],
                graph_nodes=[],
                graph_edges=[],
                asset_criticality=asset_criticality,
                is_simulated=event.is_simulated
            )
            self.active_incidents[incident_id] = incident
        else:
            incident = self.active_incidents[incident_id]
            incident.updated_at = now_str
            if event.layer not in incident.layers_involved:
                incident.layers_involved.append(event.layer)

        # 1. Determine contribution score for this single event
        ml_label = ml_res.get("label", "Benign")
        ml_conf = ml_res.get("confidence", 0.0)
        is_anomaly = ml_res.get("is_anomaly", False)
        anomaly_score = ml_res.get("anomaly_score", 0.0)

        contribution_score = 0.0
        rule_name = rule_hit.get("rule_name") if rule_hit else None

        # ML Supervised Contribution
        if ml_label != "Benign":
            contribution_score += ml_conf * 22.0
        
        # ML Unsupervised Anomaly Contribution
        if is_anomaly:
            contribution_score += anomaly_score * 18.0

        # Deterministic Rule Contribution
        if rule_hit:
            contribution_score += rule_hit.get("weight", 20.0)

        # Populate event metadata
        event.detection_source = "hybrid_ml_rule" if (rule_hit and ml_label != "Benign") else ("rule" if rule_hit else "rf_classifier")
        event.attack_type = rule_hit.get("attack_type") if rule_hit else ml_label
        event.confidence_score = float(max(ml_conf, anomaly_score, 0.5 if rule_hit else 0.0))

        # Add evidence item
        evidence_item = IncidentEvidence(
            event=event,
            rule_name=rule_name,
            ml_confidence=ml_conf,
            contribution_score=round(contribution_score, 2)
        )
        incident.evidences.append(evidence_item)

        # 2. Update MITRE ATT&CK mappings
        mitre_tag = map_event_to_mitre(event.attack_type, rule_hit)
        if not any(m.technique_id == mitre_tag.technique_id for m in incident.mitre_mappings):
            incident.mitre_mappings.append(mitre_tag)

        # 3. Add to Attack Story Timeline
        story_entry = f"[{event.timestamp[11:19]}] [{event.layer.upper()}] Action: '{event.action}' -> {event.attack_type} detected (Source: {event.detection_source}, Confidence: {event.confidence_score:.0%})"
        if rule_name:
            story_entry += f" [Rule: {rule_name}]"
        incident.attack_story.append(story_entry)

        # 4. Calculate Transparent Threat Score
        risk_breakdown = self.calculate_transparent_risk_score(incident, asset_criticality)
        incident.prev_threat_score = incident.threat_score
        incident.threat_score = risk_breakdown.total_score
        incident.risk_breakdown = risk_breakdown

        # Record Score History for trajectory chart
        incident.score_history.append({
            "timestamp": event.timestamp,
            "score": risk_breakdown.total_score,
            "layer": event.layer,
            "action": event.action,
            "attack_type": event.attack_type
        })

        # 5. Rebuild Entity Attack Graph
        self.update_attack_graph(incident)

        return incident

    def calculate_transparent_risk_score(self, incident: Incident, asset_criticality: str) -> RiskBreakdown:
        """
        Calculates transparent Threat Score using formula:
        Threat Score = weighted evidence + cross-layer diversity + temporal sequence strength + asset criticality - benign adjustments
        """
        # A. Sum of evidence contributions
        evidence_score = sum(e.contribution_score for e in incident.evidences)

        # B. Cross-Layer Diversity Bonus across the FOUR telemetry layers
        # (network / endpoint / identity / application).
        # 1 layer = 0, 2 = +12, 3 = +25, 4 = +32
        # Convergence across all four layers is the strongest structural
        # signal the platform can observe, so it earns the largest bonus.
        num_layers = len(set(incident.layers_involved))
        cross_layer_bonus = {0: 0.0, 1: 0.0, 2: 12.0, 3: 25.0}.get(num_layers, 32.0)

        # C. Temporal Sequence Strength
        # Score escalates as event count grows in active window
        num_events = len(incident.evidences)
        temporal_sequence_score = min(20.0, (num_events - 1) * 4.5)

        # D. Asset Criticality Boost
        asset_boost = 15.0 if asset_criticality == "High Value Target" else 0.0

        # E. Benign Context Adjustment
        # Reduce if benign events outweigh anomalies
        benign_count = sum(1 for e in incident.evidences if e.event.attack_type == "Benign" and not e.rule_name)
        benign_adjustment = min(15.0, benign_count * 3.0)

        # Total Raw Score
        raw_total = evidence_score + cross_layer_bonus + temporal_sequence_score + asset_boost - benign_adjustment
        total_score = float(round(min(100.0, max(0.0, raw_total)), 1))

        # Risk Level Category
        if total_score < 30.0:
            risk_level = "LOW"
        elif total_score < 60.0:
            risk_level = "MEDIUM"
        elif total_score < 80.0:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        explanation = (
            f"Threat Score ({total_score}/100 - {risk_level}) = "
            f"Evidence ({evidence_score:.1f}) + Cross-Layer Diversity ({cross_layer_bonus:.1f}) + "
            f"Sequence Strength ({temporal_sequence_score:.1f}) + Critical Asset Boost ({asset_boost:.1f}) - "
            f"Benign Adjustment ({benign_adjustment:.1f})"
        )

        return RiskBreakdown(
            total_score=total_score,
            evidence_score=round(evidence_score, 1),
            cross_layer_diversity_bonus=round(cross_layer_bonus, 1),
            temporal_sequence_score=round(temporal_sequence_score, 1),
            asset_criticality_boost=round(asset_boost, 1),
            benign_context_adjustment=round(benign_adjustment, 1),
            risk_level=risk_level,
            formula_explanation=explanation
        )

    def update_attack_graph(self, incident: Incident):
        """
        Builds graph nodes & edges: User -> Host -> Process -> Destination / API.
        """
        nodes: Dict[str, AttackGraphNode] = {}
        edges: List[AttackGraphEdge] = []

        entity = incident.primary_entity
        user_id = "user:alice"
        host_id = "host:WKS-042"

        if "user:" in entity:
            user_id = entity.split("/")[0].strip()
        if "host:" in entity:
            host_id = entity.split("/")[-1].strip()

        # User node
        nodes[user_id] = AttackGraphNode(
            id=user_id,
            label=user_id,
            type="user",
            layer="identity",
            status="compromised" if any(e.event.layer == "identity" for e in incident.evidences) else "suspicious"
        )

        # Host node
        nodes[host_id] = AttackGraphNode(
            id=host_id,
            label=host_id,
            type="host",
            layer="endpoint",
            status="compromised" if incident.threat_score >= 60.0 else "suspicious"
        )

        # Edge User -> Host
        edges.append(AttackGraphEdge(
            id=f"e-{user_id}-{host_id}",
            source=user_id,
            target=host_id,
            relationship="authenticated_on",
            layer="identity"
        ))

        # Add Process & Network nodes from evidence
        for idx, ev in enumerate(incident.evidences):
            detail = ev.event.detail
            if ev.event.layer == "endpoint":
                proc_name = detail.get("process_name", "powershell.exe")
                proc_node_id = f"proc:{proc_name}"
                if proc_node_id not in nodes:
                    nodes[proc_node_id] = AttackGraphNode(
                        id=proc_node_id,
                        label=proc_name,
                        type="process",
                        layer="endpoint",
                        status="compromised" if ev.rule_name else "suspicious"
                    )
                    edges.append(AttackGraphEdge(
                        id=f"e-{host_id}-{proc_node_id}",
                        source=host_id,
                        target=proc_node_id,
                        relationship="executed_process",
                        layer="endpoint"
                    ))
            elif ev.event.layer == "application":
                endpoint_path = detail.get("url") or detail.get("api_endpoint") or "/"
                api_node_id = f"api:{str(endpoint_path)[:60]}"
                if api_node_id not in nodes:
                    nodes[api_node_id] = AttackGraphNode(
                        id=api_node_id,
                        label=str(endpoint_path)[:60],
                        type="api",
                        layer="application",
                        status="compromised" if ev.rule_name else "suspicious"
                    )
                    edges.append(AttackGraphEdge(
                        id=f"e-{host_id}-{api_node_id}",
                        source=host_id,
                        target=api_node_id,
                        relationship="requested_endpoint",
                        layer="application"
                    ))
            elif ev.event.layer == "network":
                dest_ip = detail.get("dest_ip", "198.51.100.42")
                dest_node_id = f"dest:{dest_ip}"
                if dest_node_id not in nodes:
                    nodes[dest_node_id] = AttackGraphNode(
                        id=dest_node_id,
                        label=dest_ip,
                        type="destination",
                        layer="network",
                        status="compromised" if ev.event.attack_type in ["SQL Injection", "DDoS"] else "suspicious"
                    )
                    # Connect to last process or host
                    last_proc = [n for n in nodes if nodes[n].type == "process"]
                    source_id = last_proc[-1] if last_proc else host_id
                    edges.append(AttackGraphEdge(
                        id=f"e-{source_id}-{dest_node_id}",
                        source=source_id,
                        target=dest_node_id,
                        relationship="network_connection",
                        layer="network"
                    ))

        incident.graph_nodes = list(nodes.values())
        incident.graph_edges = edges

    def reset(self):
        self.active_incidents.clear()
        self.entity_incident_map.clear()
