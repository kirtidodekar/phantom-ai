import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from .schemas import (
    NormalizedEvent, Incident, ModelEvaluationMetrics,
    AnalystFeedback, SandboxedActionRequest, SandboxedActionResponse
)
from .engine.correlator import CrossLayerCorrelator
from .engine.replay import IncidentReplayEngine
from .engine.live_detection import LiveDetectionEngine, CLASS_CATALOG, MITRE_TECHNIQUE_MAP
from .engine.integrations import get_integrations_status
from .ml.models import ThreatDetectionModels
from .database import (
    get_database_status,
    get_sandboxed_actions,
    init_db,
    log_sandboxed_action,
    save_feedback,
)
from .observability import configure_logging, install_observability, log_event
from .network.routes import router as network_router
from .network.monitor import NetworkMonitorService
from .sensors.routes import router as sensors_router
from .sensors.manager import SensorManager

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

# Structured JSON logging, request tracing and centralized error envelopes.
configure_logging()
install_observability(app)

# Core singletons
correlator = CrossLayerCorrelator()
replay_engine = IncidentReplayEngine(correlator)
live_engine = LiveDetectionEngine.get_instance()

# Live network monitoring service. It receives the SAME correlator instance the
# replay engine uses, so real network evidence and simulated telemetry flow
# through one correlation/scoring engine (never two competing pipelines).
network_monitor = NetworkMonitorService.get_instance(correlator=correlator)

# Network telemetry routes (/api/network/*). Existing routes are untouched.
app.include_router(network_router)

# Endpoint + application sensors share the SAME correlator, so evidence from all
# four telemetry layers converges in one correlation and scoring engine.
sensor_manager = SensorManager.get_instance(correlator=correlator)
app.include_router(sensors_router)

@app.on_event("startup")
def on_startup():
    """
    Boots persistence and seeds the correlation engine.

    Persistence failures are logged and re-raised so a misconfigured database
    surfaces immediately rather than silently degrading. Seeding the replay is
    best-effort: the API stays available even if demo data cannot be generated.
    """
    # Persistence is initialized best-effort. A database outage must NOT take
    # the SOC platform offline: detection, correlation, scoring and replay all
    # operate in memory. The failure is logged and surfaced through
    # /api/health -> database so the dashboard reports degraded state honestly
    # instead of pretending everything is fine.
    try:
        init_db()
        status = get_database_status()
        log_event(
            "info",
            "database_ready",
            db_backend=status.get("backend"),
            schema=status.get("schema"),
        )
    except Exception:
        status = get_database_status()
        log_event(
            "error",
            "database_initialization_failed",
            db_backend=status.get("backend"),
            db_error=status.get("error"),
            impact="persistence_disabled_api_still_serving",
        )

    # Demo seeding is OPT-IN. When disabled (the default) the platform starts
    # with an EMPTY incident set so the dashboard shows only real observed
    # telemetry. Simulated replay remains fully available on demand through the
    # /api/replay/* endpoints and the navbar controls.
    if os.getenv("DEMO_SEED_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
        try:
            replay_engine.run_full_replay()
            log_event(
                "warning",
                "replay_seeded_simulated_data",
                incidents=len(correlator.trajectory_engine.active_incidents),
                note="incidents are flagged is_simulated=true",
            )
        except Exception:
            log_event("warning", "replay_seed_failed")
    else:
        log_event("info", "demo_seed_disabled", note="starting with real telemetry only")

    # Prepare network telemetry tables and optionally auto-start capture.
    try:
        from .network import persistence as network_persistence
        table_status = network_persistence.init_network_tables()
        log_event("info", "network_tables_ready",
                  initialized=table_status.get("initialized"),
                  db_error=table_status.get("error"))
    except Exception:
        log_event("warning", "network_tables_init_failed")

    if network_monitor.config.enabled:
        try:
            started = network_monitor.start()
            log_event("info", "network_autostart_ok", interface=started.get("interface"))
        except Exception as error:
            # Capture problems must never prevent the API from serving.
            log_event("warning", "network_autostart_failed", reason=str(error)[:200])
    else:
        log_event("info", "network_monitor_disabled",
                  hint="Set NETWORK_MONITOR_ENABLED=true to enable live capture")

    # Optional auto-start for the endpoint and application sensors. Failures are
    # logged and never block the API from serving.
    for sensor_name, sensor_obj, flag in (
        ("endpoint", sensor_manager.endpoint, "ENDPOINT_SENSOR_ENABLED"),
        ("application", sensor_manager.application, "APPLICATION_SENSOR_ENABLED"),
    ):
        if os.getenv(flag, "false").strip().lower() in {"1", "true", "yes", "on"}:
            try:
                sensor_obj.start()
                log_event("info", "sensor_autostart_ok", sensor=sensor_name)
            except Exception as error:
                log_event("warning", "sensor_autostart_failed",
                          sensor=sensor_name, reason=str(error)[:200])

    log_event("info", "api_startup_complete")

@app.get("/api/health")
def get_health():
    return {
        "status": "ONLINE",
        "system": "Sentinel-AI Threat Trajectory Platform",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_incidents_count": len(correlator.trajectory_engine.active_incidents),
        "database": get_database_status(),
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

# ===========================================================================
# Live Detection API (9-class classifier, 12-feature vector)
# ===========================================================================

class PredictRequest(BaseModel):
    """
    Body for POST /api/detect/predict.

    Either send `{"detail": {...feature fields...}}` or post a bare feature dict -
    any keys outside of `detail` / `source_ip` / `layer` are collected as the detail
    payload so simple clients can post features at the top level.
    """
    model_config = ConfigDict(extra="allow")

    detail: Optional[Dict[str, Any]] = None
    source_ip: Optional[str] = None
    layer: Optional[str] = None

    def resolved_detail(self) -> Dict[str, Any]:
        if self.detail:
            return dict(self.detail)
        return dict(self.model_extra or {})


@app.post("/api/detect/predict")
def detect_predict(req: PredictRequest):
    """
    Scores a single event with the trained RandomForest (9 classes) + IsolationForest
    models and returns the fused risk assessment, MITRE mapping and recommended
    (sandboxed) response action.
    """
    try:
        result = live_engine.analyze(
            detail=req.resolved_detail(),
            source_ip=req.source_ip,
            layer=req.layer
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Prediction failed: {e}")

    # Strip engine-internal fields that are not part of the public contract
    return {k: v for k, v in result.items() if not k.startswith("_")}


@app.get("/api/detect/stream")
def detect_stream(count: int = 6):
    """
    Generates a batch of simulated live telemetry events (benign majority), scores each
    with the real models, and returns the detection rows. `count` is clamped to 1-50.
    """
    return live_engine.generate_stream(count)


@app.get("/api/detect/classes")
def detect_classes():
    """Returns the 9 supported threat classes with MITRE mapping and layer hints."""
    classes = []
    for entry in CLASS_CATALOG:
        mitre = MITRE_TECHNIQUE_MAP.get(entry["name"])
        classes.append({
            "id": entry["id"],
            "name": entry["name"],
            "description": entry["description"],
            "mitre_id": mitre["technique_id"] if mitre else None,
            "layer": entry["layer"],
            "severity_hint": entry["severity_hint"]
        })
    return {"classes": classes}


@app.get("/api/stats/overview")
def stats_overview():
    """Rolling live-detection analytics: EPS, class/severity histograms, latency, accuracy."""
    return live_engine.stats_overview()


# ===========================================================================
# Sandboxed Automated Defense API (auto-block list + adaptive DRL policy)
# ===========================================================================

class BlockRequest(BaseModel):
    """Body for POST /api/defense/block. Everything except `ip` is optional."""
    ip: str = Field(..., description="Target IPv4/IPv6 address to block (sandboxed)")
    attack_type: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    reason: Optional[str] = None
    mode: Optional[str] = None  # AUTO | MANUAL (defaults to MANUAL)


class DefenseConfigRequest(BaseModel):
    """Body for POST /api/defense/config. All fields optional (partial update)."""
    auto_block_enabled: Optional[bool] = None
    threshold: Optional[float] = None
    adaptive_enabled: Optional[bool] = None


@app.get("/api/defense/blocklist")
def get_blocklist():
    """Current sandboxed blocklist plus the active auto-block configuration."""
    return live_engine.get_blocklist()


@app.post("/api/defense/block")
def create_block(req: BlockRequest):
    """
    Adds (or escalates) a sandboxed block for an IP. No real firewall/OS networking is
    touched - the action is recorded in the sandboxed-actions audit table only.
    """
    if not req.ip or not req.ip.strip():
        raise HTTPException(status_code=400, detail="Field 'ip' must not be empty")
    return live_engine.manual_block(
        ip=req.ip.strip(),
        attack_type=req.attack_type,
        risk_score=req.risk_score,
        confidence=req.confidence,
        reason=req.reason,
        mode=req.mode
    )


@app.delete("/api/defense/block/{ip}")
def delete_block(ip: str):
    """Removes an IP from the sandboxed blocklist."""
    if not live_engine.unblock(ip):
        raise HTTPException(status_code=404, detail=f"IP {ip} is not in the blocklist")
    return {"status": "UNBLOCKED", "ip": ip}


@app.post("/api/defense/config")
def update_defense_config(req: DefenseConfigRequest):
    """Partially updates the auto-block configuration and returns the new configuration."""
    return live_engine.update_config(
        auto_block_enabled=req.auto_block_enabled,
        threshold=req.threshold,
        adaptive_enabled=req.adaptive_enabled
    )


@app.get("/api/defense/policy")
def get_defense_policy():
    """Simulated Deep Q-Network adaptive response policy state (research simulation)."""
    return live_engine.policy_snapshot()


# ===========================================================================
# Integration Fabric (SIEM / Cloud / IoT) - representative simulated inventory
# ===========================================================================

@app.get("/api/integrations/status")
def integrations_status():
    """SIEM forwarder, cloud ingest and IoT/OT fleet status for the integrations view."""
    return get_integrations_status()
