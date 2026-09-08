"""
FastAPI routes for the endpoint and application sensors, layer coverage and
data-sovereignty reporting.

Mounted under /api/sensors and /api/sovereignty. Control endpoints reuse the
same privileged-role enforcement as packet capture, because host process and
log observation is equally sensitive.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query

from ..network.routes import PRIVILEGED_ROLES
from .manager import SensorManager, data_sovereignty

router = APIRouter(prefix="/api", tags=["sensors"])


def _manager() -> SensorManager:
    return SensorManager.get_instance()


def _require_privileged_role(role_header: Optional[str]) -> str:
    role = (role_header or "").strip().lower()
    if not role:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Sentinel-Role header. Sensor control requires an authorized role.",
        )
    if role not in PRIVILEGED_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role_header}' is not authorized to control telemetry sensors.",
        )
    return role


def _sensor_or_404(name: str):
    manager = _manager()
    if name == "endpoint":
        return manager.endpoint
    if name == "application":
        return manager.application
    raise HTTPException(status_code=404, detail=f"Unknown sensor '{name}'. Use 'endpoint' or 'application'.")


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------

@router.get("/sensors/status")
def sensors_status():
    """Status and capability for the endpoint and application sensors."""
    return _manager().status()


@router.get("/sensors/coverage")
def sensors_coverage():
    """
    Live coverage across all four telemetry layers.

    Reports which layers are genuinely being observed right now, not merely
    which the platform supports.
    """
    manager = _manager()
    network_status = None
    try:
        from ..network.monitor import NetworkMonitorService
        network_status = NetworkMonitorService.get_instance().status()
    except Exception:
        network_status = None
    return manager.coverage(network_status=network_status)


@router.get("/sensors/{name}/events")
def sensor_events(name: str, limit: int = Query(default=30, ge=1, le=200)):
    """Recent observations recorded by a sensor."""
    return {"sensor": name, "events": _sensor_or_404(name).events(limit=limit)}


@router.get("/sovereignty")
def sovereignty():
    """
    Data-sovereignty posture for the current deployment.

    States where telemetry actually resides and flags offshore storage instead
    of asserting compliance.
    """
    return data_sovereignty()


# --------------------------------------------------------------------------
# Control (privileged)
# --------------------------------------------------------------------------

@router.post("/sensors/{name}/start")
def start_sensor(
    name: str,
    x_sentinel_role: Optional[str] = Header(default=None, alias="X-Sentinel-Role"),
):
    """
    Starts a telemetry sensor.

    Returns 409 with a precise reason when the host cannot support it (missing
    library, no readable log paths) rather than reporting a false success.
    """
    _require_privileged_role(x_sentinel_role)
    sensor = _sensor_or_404(name)
    try:
        return sensor.start()
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.post("/sensors/{name}/stop")
def stop_sensor(
    name: str,
    x_sentinel_role: Optional[str] = Header(default=None, alias="X-Sentinel-Role"),
):
    """Stops a telemetry sensor."""
    _require_privileged_role(x_sentinel_role)
    return _sensor_or_404(name).stop()
