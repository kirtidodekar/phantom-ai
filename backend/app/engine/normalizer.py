import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from ..schemas import NormalizedEvent

# The four telemetry layers Sentinel AI fuses. Kept in one place so every
# component agrees on what a valid layer is.
VALID_LAYERS = ("network", "endpoint", "identity", "application")

def normalize_event(raw_data: Dict[str, Any]) -> NormalizedEvent:
    """
    Normalizes raw telemetry into the standard Sentinel-AI event envelope schema.
    Schema:
    {
      "event_id": "evt-000123",
      "timestamp": "2026-01-14T09:32:11Z",
      "layer": "endpoint",              // network | endpoint | identity
      "entity_id": "user:alice / host:WKS-042",
      "action": "process_create",
      "detail": { ...layer-specific fields... },
      "source_confidence": "high"
    }
    """
    event_id = raw_data.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
    
    timestamp = raw_data.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
    # Application is a FIRST-CLASS layer alongside network, endpoint and
    # identity. It was previously collapsed into identity, which made
    # application signals invisible to cross-layer correlation and scoring.
    layer = str(raw_data.get("layer", "network")).lower()
    if layer in ("app", "web", "http"):
        layer = "application"
    if layer not in VALID_LAYERS:
        layer = "network"
        
    entity_id = raw_data.get("entity_id")
    if not entity_id:
        user = raw_data.get("user") or raw_data.get("username") or "alice"
        host = raw_data.get("host") or raw_data.get("hostname") or "WKS-042"
        entity_id = f"user:{user} / host:{host}"
        
    action = raw_data.get("action") or "telemetry_observed"
    detail = raw_data.get("detail") or raw_data.get("data") or {}
    
    # If top-level keys exist, copy to detail
    for key in ["packet_size", "protocol", "request_rate", "failed_login_count", "process_name", "parent_process", "src_ip", "dest_ip", "payload", "url", "http_method", "status_code", "user_agent", "url_entropy", "payload_pattern_score"]:
        if key in raw_data and key not in detail:
            detail[key] = raw_data[key]
            
    source_confidence = raw_data.get("source_confidence", "high")
    is_simulated = raw_data.get("is_simulated", True)

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        layer=layer,
        entity_id=entity_id,
        action=action,
        detail=detail,
        source_confidence=source_confidence,
        is_simulated=is_simulated
    )
