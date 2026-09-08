"""
Sentinel AI - telemetry sensors for the endpoint and application layers.

The network layer has a real packet sensor (app.network). This package adds the
two remaining live sources so cross-layer correlation can fire on REAL data
instead of only during simulated replay:

    endpoint     process / privilege / local-connection observation (psutil)
    application  web access-log tailing (SQLi, XSS, auth-failure signals)

Both sensors emit standard Sentinel telemetry through the SAME correlator entry
point used by the REST ingest endpoint, so scoring, MITRE mapping, attack
graphs and the audit trail are the existing implementations.

Everything is observation-only. No process is killed, injected into, or
modified; no log file is ever written to.
"""

from .config import SensorConfig, get_sensor_config  # noqa: F401
