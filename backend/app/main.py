import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .schemas import (
    NormalizedEvent, Incident, ModelEvaluationMetrics,
    AnalystFeedback, SandboxedActionRequest, SandboxedActionResponse
)
from .engine.correlator import CrossLayerCorrelator
from .engine.replay import IncidentReplayEngine
from .ml.models import ThreatDetectionModels
from .database import init_db, save_feedback, log_sandboxed_action, get_sandboxed_actions

app = FastAPI(
    title="Sentinel-AI Cyber Threat Detection & Early-Warning API",
    description="Cross-Layer Evidence Fusion, Threat Trajectory Scoring & ATT&CK Mapping Platform",
    version="1.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core singletons
correlator = CrossLayerCorrelator()
replay_engine = IncidentReplayEngine(correlator)

@app.on_event("startup")
def on_startup():
    init_db()
    # Pre-run replay engine once so dashboard starts with rich live data immediately
    replay_engine.run_full_replay()

@app.get("/api/health")
def get_health():
    return {
        "status": "ONLINE",
        "system": "Sentinel-AI Threat Trajectory Platform",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_incidents_count": len(correlator.trajectory_engine.active_incidents)
    }

@app.post("/api/telemetry/ingest")
def ingest_telemetry(raw_event: Dict[str, Any]):
    try:
        norm_event, incident = correlator.process_raw_telemetry(raw_event)
        return {
            "status": "ACCEPTED",
            "event_id": norm_event.event_id,
            "associated_incident_id": incident.incident_id,
            "threat_score": incident.threat_score,
            "attack_type": norm_event.attack_type
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/incidents")
def get_incidents():
    incidents_list = list(correlator.trajectory_engine.active_incidents.values())
    # Sort by threat score descending
    incidents_list.sort(key=lambda x: x.threat_score, reverse=True)
    return {
        "count": len(incidents_list),
        "incidents": incidents_list
    }

@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    inc = correlator.trajectory_engine.active_incidents.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc

@app.get("/api/metrics")
def get_model_metrics():
    models = ThreatDetectionModels.get_instance()
    return models.metrics

@app.post("/api/replay/start")
def start_replay():
    all_events, final_incident = replay_engine.run_full_replay()
    return {
        "status": "COMPLETED",
        "stages_processed": 5,
        "total_events": len(all_events),
        "active_incident": final_incident
    }

@app.post("/api/replay/step")
def step_replay():
    res = replay_engine.step_next()
    if not res:
        return {"status": "FINISHED", "stage_name": "Completed", "incident": None}
    stage_name, events, incident = res
    return {
        "status": "STEP_EXECUTED",
        "stage_name": stage_name,
        "events_count": len(events),
        "current_step": replay_engine.current_step,
        "total_steps": replay_engine.total_steps,
        "incident": incident
    }

@app.post("/api/replay/reset")
def reset_replay():
    replay_engine.reset()
    return {"status": "RESET", "message": "Telemetry stream and incident correlation state reset to clean baseline."}

class CriticalityRequest(BaseModel):
    entity_id: str
    criticality: str  # "Standard" | "High Value Target"

@app.post("/api/asset/criticality")
def set_asset_criticality(req: CriticalityRequest):
    correlator.set_asset_criticality(req.entity_id, req.criticality)
    incident_id = correlator.trajectory_engine.entity_incident_map.get(req.entity_id)
    updated_inc = correlator.trajectory_engine.active_incidents.get(incident_id) if incident_id else None
    return {
        "status": "UPDATED",
        "entity_id": req.entity_id,
        "criticality": req.criticality,
        "new_threat_score": updated_inc.threat_score if updated_inc else None
    }

@app.post("/api/feedback")
def submit_feedback(fb: AnalystFeedback):
    now_str = datetime.now(timezone.utc).isoformat()
    save_feedback(fb.feedback_type, fb.incident_id, fb.event_id, fb.notes or "", now_str)
    return {"status": "RECORDED", "incident_id": fb.incident_id}

@app.post("/api/actions/simulate-block")
def simulate_block(req: SandboxedActionRequest):
    now_str = datetime.now(timezone.utc).isoformat()
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    
    msg = f"[SANDBOXED] Action '{req.action_type}' triggered on target '{req.target_id}'. No real firewall or network change executed."
    
    log_sandboxed_action(
        action_id=action_id,
        action_type=req.action_type,
        target_id=req.target_id,
        incident_id=req.incident_id,
        status="EXECUTED_SANDBOXED",
        message=msg,
        timestamp=now_str
    )

    # Update active incident status if applicable
    inc = correlator.trajectory_engine.active_incidents.get(req.incident_id)
    if inc:
        inc.status = "MITIGATED (SANDBOXED)"
        inc.attack_story.append(f"[{now_str[11:19]}] [ANALYST ACTION] Sandboxed mitigation '{req.action_type}' applied to target {req.target_id}.")

    return SandboxedActionResponse(
        action_id=action_id,
        status="EXECUTED_SANDBOXED",
        message=msg,
        timestamp=now_str,
        is_sandboxed=True
    )

@app.get("/api/baseline/diff/{incident_id}")
def get_baseline_diff(incident_id: str):
    inc = correlator.trajectory_engine.active_incidents.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    return {
        "incident_id": incident_id,
        "baseline_state": {
            "failed_login_rate": "0.0% (Normal)",
            "request_rate": "2.1 req/sec (Normal)",
            "process_execution": "User level standard apps (explorer.exe)",
            "network_destination": "Internal LAN (10.0.0.0/8)",
            "threat_score": 15.0
        },
        "current_anomalous_state": {
            "failed_login_rate": "80.0% (Burst Brute Force from 198.51.100.88)",
            "request_rate": "25.0 req/sec Spike",
            "process_execution": "cmd.exe -> powershell.exe -enc (SYSTEM privilege)",
            "network_destination": "External C2 IP 198.51.100.99 (SQLi Payload Exfiltration)",
            "threat_score": inc.threat_score
        },
        "deltas": [
            "Authentication origin shifted from Internal Subnet to External Untrusted ASN",
            "Process execution tree spawned privilege escalation shell",
            "Database query contained SQL keyword signatures & payload anomaly"
        ]
    }
