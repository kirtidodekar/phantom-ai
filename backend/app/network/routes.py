"""
FastAPI routes for the network telemetry subsystem.

Mounted under /api/network, following the existing REST conventions. Read
endpoints are open to the dashboard; CONTROL endpoints (start/stop) are
restricted to privileged roles because packet capture is a sensitive
capability.

Authorization note: the platform currently identifies the operator role on the
client. Until a server-side session store exists, control endpoints require an
explicit role header and reject everything else. This is enforced server-side
so the control surface cannot be driven by an unprivileged caller.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .monitor import NetworkMonitorService

router = APIRouter(prefix="/api/network", tags=["network"])

# Roles permitted to control packet capture.
PRIVILEGED_ROLES = {"admin", "soc", "soc analyst", "soc tier-2 analyst",
                    "ir commander", "detection engineer", "security engineer"}


class StartMonitorRequest(BaseModel):
    interface: Optional[str] = Field(default=None, description="Interface name or 'auto'")
    capture_filter: Optional[str] = Field(default=None, description="BPF capture filter")


def _service() -> NetworkMonitorService:
    return NetworkMonitorService.get_instance()


def _require_privileged_role(role_header: Optional[str]) -> str:
    """Enforces role-based access on monitoring control endpoints."""
    role = (role_header or "").strip().lower()
    if not role:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Sentinel-Role header. Packet monitoring control requires an authorized role.",
        )
    if role not in PRIVILEGED_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role_header}' is not authorized to control packet capture.",
        )
    return role


# --------------------------------------------------------------------------
# Read endpoints
# --------------------------------------------------------------------------

@router.get("/status")
def network_status():
    """Monitor health, capability, counters and effective configuration."""
    return _service().status()


@router.get("/interfaces")
def network_interfaces():
    """Capture-capable interfaces detected on the host."""
    service = _service()
    from .capture import list_interfaces
    return {"capability": service.capability(), "interfaces": list_interfaces()}


@router.get("/packets")
def network_packets(limit: int = Query(default=100, ge=1, le=500)):
    """Recent packet METADATA only - payloads are never captured or stored."""
    return _service().packets(limit=limit)


@router.get("/stats")
def network_stats():
    """Rolling window aggregates, baseline, deviation and rate history."""
    return _service().stats()


@router.get("/ips")
def network_ips(limit: int = Query(default=20, ge=1, le=100)):
    """Live per-IP intelligence for source and destination addresses."""
    return _service().ips(limit=limit)


@router.get("/connections")
def network_connections(limit: int = Query(default=50, ge=1, le=200)):
    """Most recently active flows."""
    return _service().connections(limit=limit)


@router.get("/threats")
def network_threats(limit: int = Query(default=50, ge=1, le=200)):
    """Network detections with MITRE mapping and correlated incident IDs."""
    return _service().network_threats(limit=limit)


# --------------------------------------------------------------------------
# Control endpoints (privileged)
# --------------------------------------------------------------------------

@router.post("/start")
def start_monitoring(
    request: StartMonitorRequest,
    x_sentinel_role: Optional[str] = Header(default=None, alias="X-Sentinel-Role"),
):
    """
    Starts LIVE packet capture on an authorized interface.

    Returns 409 with a precise, actionable reason when the host cannot capture
    (missing Npcap/libpcap, no permission, unknown interface). The service never
    reports success it cannot deliver.
    """
    _require_privileged_role(x_sentinel_role)
    service = _service()
    try:
        return service.start(interface=request.interface, capture_filter=request.capture_filter)
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.post("/stop")
def stop_monitoring(
    x_sentinel_role: Optional[str] = Header(default=None, alias="X-Sentinel-Role"),
):
    """Stops LIVE capture and returns the platform to DEMO/replay mode."""
    _require_privileged_role(x_sentinel_role)
    return _service().stop()


@router.post("/reset")
def reset_monitoring(
    x_sentinel_role: Optional[str] = Header(default=None, alias="X-Sentinel-Role"),
):
    """Clears in-memory network statistics. Replay and incidents are untouched."""
    _require_privileged_role(x_sentinel_role)
    return _service().reset()
