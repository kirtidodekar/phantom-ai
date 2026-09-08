"""
Integration Status Provider
===========================

Representative (simulated) telemetry-integration inventory for the Sentinel-AI demo:
SIEM forwarders, cloud ingest regions and an IoT/OT device fleet.

The inventory is built once at import time from a fixed seed, so the shape and the
device list are stable across requests; only the time-derived counters (events
forwarded, last sync age) advance. No outbound connections are ever made.
"""

import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_RNG = random.Random(1337)
_STARTED_AT = time.time()

# --- SIEM forwarders --------------------------------------------------------
# (name, vendor, protocol, baseline forwarded events, events/sec rate, latency ms, status)
_SIEM_TEMPLATES = [
    ("Splunk Enterprise Security", "Splunk", "HTTP Event Collector (HEC/TLS)", 1_482_930, 42.0, 38, "CONNECTED"),
    ("IBM QRadar", "IBM", "LEEF over Syslog TLS", 986_412, 27.5, 64, "CONNECTED"),
    ("Microsoft Sentinel", "Microsoft", "Azure Monitor / CEF", 1_204_775, 33.0, 51, "CONNECTED"),
    ("Elastic Security", "Elastic", "Elastic Common Schema (Beats)", 774_318, 19.5, 29, "DEGRADED"),
]

# --- Cloud ingest regions ---------------------------------------------------
_CLOUD_TEMPLATES = [
    ("AWS", "us-east-1", "HEALTHY", 12, 3.4, True),
    ("AWS", "eu-west-1", "HEALTHY", 6, 1.8, True),
    ("Azure", "westeurope", "HEALTHY", 8, 2.1, True),
    ("GCP", "asia-south1", "SCALING", 5, 1.2, True),
]

# --- IoT / OT fleet ---------------------------------------------------------
_IOT_PROTOCOLS = ["MQTT", "CoAP", "Zigbee", "BLE"]

_IOT_TEMPLATES = [
    ("IP Camera", "MQTT", "v4.2.1"),
    ("IP Camera", "MQTT", "v4.1.7"),
    ("Smart Thermostat", "Zigbee", "v2.8.0"),
    ("Smart Thermostat", "Zigbee", "v2.6.3"),
    ("PLC Controller", "CoAP", "v1.19.4"),
    ("PLC Controller", "CoAP", "v1.17.0"),
    ("Infusion Pump", "BLE", "v6.0.2"),
    ("Infusion Pump", "BLE", "v5.9.1"),
    ("Patient Monitor", "MQTT", "v3.3.5"),
    ("Badge Reader", "Zigbee", "v1.4.9"),
    ("HVAC Gateway", "CoAP", "v2.2.2"),
    ("Smart Lock", "BLE", "v1.8.0"),
]


def _build_iot_fleet() -> List[Dict[str, Any]]:
    """Builds the deterministic IoT/OT device inventory (seeded once at import)."""
    devices: List[Dict[str, Any]] = []
    for idx, (device_type, protocol, firmware) in enumerate(_IOT_TEMPLATES, start=1):
        risk = round(_RNG.uniform(4.0, 88.0), 1)
        if risk >= 70.0:
            status = "AT_RISK"
        elif _RNG.random() < 0.12:
            status = "OFFLINE"
        else:
            status = "ONLINE"
        devices.append({
            "id": f"iot-{idx:03d}",
            "type": device_type,
            "protocol": protocol,
            "ip": f"10.20.{(idx % 6) + 1}.{40 + idx}",
            "status": status,
            "risk_score": risk,
            "firmware": firmware,
        })
    return devices


_IOT_FLEET = _build_iot_fleet()


def get_integrations_status() -> Dict[str, Any]:
    """
    Payload served by ``GET /api/integrations/status``.

    SIEM ``events_forwarded`` grows from a fixed baseline at the connector's nominal
    rate for the process uptime, so the dashboard shows movement without random jitter.
    """
    uptime = max(0.0, time.time() - _STARTED_AT)
    now = datetime.now(timezone.utc)

    siem = []
    for offset, (name, vendor, protocol, baseline, rate, latency_ms, status) in enumerate(_SIEM_TEMPLATES):
        forwarded = int(baseline + rate * uptime)
        siem.append({
            "name": name,
            "vendor": vendor,
            "status": status,
            "protocol": protocol,
            "events_forwarded": forwarded,
            "last_sync": (now - timedelta(seconds=5 + offset * 7)).isoformat(),
            "latency_ms": latency_ms,
        })

    cloud = [
        {
            "provider": provider,
            "region": region,
            "status": status,
            "nodes": nodes,
            "ingest_gbps": ingest,
            "autoscale": autoscale,
        }
        for provider, region, status, nodes, ingest, autoscale in _CLOUD_TEMPLATES
    ]

    online = sum(1 for d in _IOT_FLEET if d["status"] in ("ONLINE", "AT_RISK"))
    at_risk = sum(1 for d in _IOT_FLEET if d["status"] == "AT_RISK")

    return {
        "siem": siem,
        "cloud": cloud,
        "iot": {
            "total_devices": len(_IOT_FLEET),
            "online": online,
            "at_risk": at_risk,
            "protocols": list(_IOT_PROTOCOLS),
            "devices": [dict(d) for d in _IOT_FLEET],
        },
    }
