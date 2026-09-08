"""
Sensor manager and data-sovereignty reporting.

Owns the endpoint and application sensors and exposes a single coverage view
across all FOUR telemetry layers, plus an honest assessment of where collected
data actually resides.
"""

from __future__ import annotations

import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from .application import ApplicationSensor
from .config import get_sensor_config
from .endpoint import EndpointSensor

# Hostname suffixes that indicate managed/offshore infrastructure. Used only to
# classify residency for the operator - no connection details are exposed.
_MANAGED_SUFFIXES = ("supabase.co", "supabase.com", "rds.amazonaws.com",
                     "azure.com", "neon.tech", "planetscale.com", "render.com")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", ""}


class SensorManager:
    """Singleton coordinating the non-network telemetry sensors."""

    _instance: Optional["SensorManager"] = None

    def __init__(self, correlator=None):
        self.correlator = correlator
        self.endpoint = EndpointSensor(correlator=correlator)
        self.application = ApplicationSensor(correlator=correlator)

    @classmethod
    def get_instance(cls, correlator=None) -> "SensorManager":
        if cls._instance is None:
            cls._instance = cls(correlator=correlator)
        elif correlator is not None and cls._instance.correlator is None:
            cls._instance.correlator = correlator
            cls._instance.endpoint.correlator = correlator
            cls._instance.application.correlator = correlator
        return cls._instance

    # ---------------- coverage ----------------

    def coverage(self, network_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Reports live coverage across all four layers.

        This is the honest answer to "which signals is this platform actually
        observing right now" - as opposed to which it merely supports.
        """
        ep = self.endpoint.status()
        app = self.application.status()

        network_live = bool(network_status and network_status.get("monitoring"))
        network_possible = bool(
            network_status
            and (network_status.get("capability") or {}).get("capture_possible")
        )

        layers = {
            "network": {
                "live": network_live,
                "available": network_possible,
                "sensor": "packet_capture",
                "detects": ["Port scan / recon", "DoS / DDoS", "Beaconing",
                            "Suspicious connections", "Traffic anomalies"],
            },
            "endpoint": {
                "live": ep["running"],
                "available": ep["capability"]["capture_possible"],
                "sensor": "process_monitor",
                "detects": ["Suspicious process chains", "Encoded commands",
                            "Privilege anomalies"],
            },
            "identity": {
                "live": False,
                "available": True,
                "sensor": "rest_ingest",
                "detects": ["Brute force", "Off-hours access", "Unauthorized access"],
                "note": "Populated via /api/telemetry/ingest from an IdP or auth log shipper.",
            },
            "application": {
                "live": app["running"],
                "available": app["capability"]["capture_possible"],
                "sensor": "access_log_tail",
                "detects": ["SQL injection", "XSS", "Path traversal",
                            "Authorization probing", "Error spikes"],
            },
        }

        live_count = sum(1 for v in layers.values() if v["live"])
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "layers": layers,
            "layers_live": live_count,
            "layers_total": 4,
            "cross_layer_ready": live_count >= 2,
            "note": (
                "Cross-layer correlation requires at least two live layers sharing "
                "an entity. Set NETWORK_LOCAL_ENTITY so all local sensors agree."
            ),
        }

    def status(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint.status(),
            "application": self.application.status(),
            "entity": get_sensor_config().entity,
        }


def data_sovereignty() -> Dict[str, Any]:
    """
    Reports where collected telemetry physically resides.

    Digital sovereignty is a deployment property, not a code property. This
    function states the truth about the current configuration rather than
    claiming compliance: it classifies the datastore as self-hosted or
    third-party managed and flags offshore storage of security telemetry.
    """
    url = (os.getenv("DATABASE_URL") or "").strip()
    declared_region = (os.getenv("DATA_RESIDENCY_REGION") or "").strip()
    require_local = (os.getenv("REQUIRE_LOCAL_DATA_RESIDENCY") or "false").strip().lower() in {
        "1", "true", "yes", "on"
    }

    host = ""
    backend = "sqlite"
    if url:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except Exception:
            host = ""
        backend = "postgresql" if url.lower().startswith(("postgresql://", "postgres://")) else "other"

    if not url:
        hosting, jurisdiction = "self_hosted", "on_premise_file"
    elif host in _LOCAL_HOSTS:
        hosting, jurisdiction = "self_hosted", "on_premise"
    elif any(host.endswith(sfx) for sfx in _MANAGED_SUFFIXES):
        hosting, jurisdiction = "third_party_managed", "offshore_or_managed_cloud"
    else:
        hosting, jurisdiction = "external", "operator_declared"

    findings = []
    compliant = True
    if hosting == "third_party_managed":
        compliant = not require_local
        findings.append(
            "Security telemetry is stored on third-party managed infrastructure. "
            "For a sovereignty-constrained deployment, host PostgreSQL within your "
            "own jurisdiction and set DATABASE_URL to that instance."
        )
    if not declared_region and hosting != "self_hosted":
        findings.append("DATA_RESIDENCY_REGION is not declared for an external datastore.")

    return {
        "hosting_model": hosting,
        "jurisdiction_class": jurisdiction,
        "datastore_backend": backend,
        "declared_region": declared_region or None,
        "requires_local_residency": require_local,
        "residency_compliant": compliant,
        "findings": findings,
        "sovereignty_properties": {
            "models_run_locally": True,
            "inference_sent_to_third_party": False,
            "external_threat_intel_calls": False,
            "self_hostable_end_to_end": True,
            "open_standards": ["MITRE ATT&CK", "libpcap/BPF", "PostgreSQL", "OpenAPI"],
            "telemetry_leaves_host": hosting != "self_hosted",
        },
        "host_platform": platform.system(),
        "observing_host": socket.gethostname(),
    }
