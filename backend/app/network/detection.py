"""
Deterministic network detection rules.

These complement - never replace - the existing SecurityRulesEngine. Each rule
returns the SAME dictionary shape the platform rules engine already emits
(rule_name / attack_type / weight / mitre_*), so the trajectory engine and the
existing MITRE mapper consume them with no special-casing.

SCOPE DISCIPLINE
Only behaviours genuinely observable from IP/TCP/UDP headers are asserted here:
port scanning, volumetric DoS, SYN floods, traffic bursts and suspicious
connection patterns. Content-dependent verdicts (SQL injection, XSS, phishing,
malware payloads) are deliberately NOT claimed from packet headers - they
remain the responsibility of the application and endpoint telemetry paths.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .config import NetworkConfig
from .models import WindowFeatures

# Ports that commonly indicate remote-access exposure when contacted externally.
_SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
                    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC"}


def detect_port_scan(
    features: WindowFeatures,
    config: NetworkConfig,
    port_fan_out: int,
    source_ip: str,
) -> Optional[Dict[str, Any]]:
    """A single source touching many distinct ports in a short window."""
    if port_fan_out < config.port_scan_unique_ports:
        return None

    excess = port_fan_out / max(1, config.port_scan_unique_ports)
    return {
        "rule_name": "Network Port Scan / Service Enumeration",
        "severity": "HIGH" if excess >= 2 else "MEDIUM",
        "attack_type": "Probe / Reconnaissance",
        "weight": min(30.0, 18.0 + excess * 4.0),
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Service Discovery",
        "mitre_id": "T1046",
        "description": (
            f"Source {source_ip} contacted {port_fan_out} distinct destination ports "
            f"within {features.window_seconds}s (threshold {config.port_scan_unique_ports})."
        ),
    }


def detect_dos(
    features: WindowFeatures,
    config: NetworkConfig,
    source_ip: str,
) -> Optional[Dict[str, Any]]:
    """Volumetric packet/connection rate abuse."""
    pps_hit = features.packets_per_second >= config.dos_packets_per_second
    cps_hit = features.connections_per_second >= config.dos_connections_per_second
    if not (pps_hit or cps_hit):
        return None

    return {
        "rule_name": "Volumetric Denial-of-Service Traffic Rate",
        "severity": "HIGH",
        "attack_type": "DDoS",
        "weight": 26.0,
        "mitre_tactic": "Impact",
        "mitre_technique": "Network Denial of Service",
        "mitre_id": "T1498",
        "description": (
            f"Abnormal traffic rate from {source_ip}: "
            f"{features.packets_per_second:.1f} pkt/s, "
            f"{features.connections_per_second:.1f} conn/s."
        ),
    }


def detect_syn_flood(
    features: WindowFeatures,
    config: NetworkConfig,
    source_ip: str,
) -> Optional[Dict[str, Any]]:
    """Half-open connection abuse: high SYN rate with few completions."""
    if features.tcp_syn_rate < config.syn_flood_rate:
        return None

    return {
        "rule_name": "TCP SYN Flood Pattern",
        "severity": "HIGH",
        "attack_type": "DDoS",
        "weight": 24.0,
        "mitre_tactic": "Impact",
        "mitre_technique": "Network Denial of Service",
        "mitre_id": "T1498",
        "description": (
            f"SYN rate {features.tcp_syn_rate:.1f}/s from {source_ip} with "
            f"{features.failed_connections} reset flows in window."
        ),
    }


def detect_traffic_burst(
    features: WindowFeatures,
    config: NetworkConfig,
    deviation: Dict[str, Any],
    source_ip: str,
) -> Optional[Dict[str, Any]]:
    """Sharp deviation from the learned traffic baseline."""
    if not deviation.get("available"):
        return None
    if features.traffic_burst_rate < config.burst_multiplier:
        return None

    return {
        "rule_name": "Traffic Volume Baseline Deviation",
        "severity": "MEDIUM",
        "attack_type": "Anomaly",
        "weight": 16.0,
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Traffic Anomaly",
        "mitre_id": "T1046",
        "description": (
            f"Traffic from {source_ip} is {features.traffic_burst_rate:.1f}x the learned "
            f"baseline ({deviation.get('deviation_percent')}% deviation)."
        ),
    }


def detect_suspicious_connection(
    features: WindowFeatures,
    observed_ports: List[int],
    source_ip: str,
    external: bool,
) -> Optional[Dict[str, Any]]:
    """External contact with sensitive remote-access services."""
    hits = sorted({p for p in observed_ports if p in _SENSITIVE_PORTS})
    if not hits or not external:
        return None

    names = ", ".join(f"{p}/{_SENSITIVE_PORTS[p]}" for p in hits[:4])
    return {
        "rule_name": "External Access to Sensitive Service Port",
        "severity": "MEDIUM",
        "attack_type": "Unauthorized Access",
        "weight": 18.0,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "External Remote Services",
        "mitre_id": "T1133",
        "description": (
            f"External source {source_ip} contacted sensitive service ports: {names}."
        ),
    }


def detect_beaconing(
    features: WindowFeatures,
    source_ip: str,
) -> Optional[Dict[str, Any]]:
    """Egress-dominant low-variance traffic suggestive of C2 beaconing."""
    if features.outbound_bytes_ratio < 8.0 or features.packet_count < 12:
        return None

    return {
        "rule_name": "Egress-Dominant Beaconing Pattern",
        "severity": "MEDIUM",
        "attack_type": "Malware / C2 Beaconing",
        "weight": 20.0,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol",
        "mitre_id": "T1071",
        "description": (
            f"Outbound/inbound byte ratio {features.outbound_bytes_ratio:.1f}:1 from "
            f"{source_ip} across {features.packet_count} packets."
        ),
    }


def evaluate_network_rules(
    features: WindowFeatures,
    config: NetworkConfig,
    source_ip: str,
    port_fan_out: int,
    observed_ports: List[int],
    deviation: Dict[str, Any],
    external: bool = False,
) -> List[Dict[str, Any]]:
    """
    Runs every network rule and returns the hits ordered by weight.

    Multiple rules may fire for the same window; the caller escalates using the
    strongest hit while retaining the rest as supporting evidence.
    """
    candidates = [
        detect_port_scan(features, config, port_fan_out, source_ip),
        detect_dos(features, config, source_ip),
        detect_syn_flood(features, config, source_ip),
        detect_traffic_burst(features, config, deviation, source_ip),
        detect_suspicious_connection(features, observed_ports, source_ip, external),
        detect_beaconing(features, source_ip),
    ]
    hits = [c for c in candidates if c]
    hits.sort(key=lambda h: h.get("weight", 0.0), reverse=True)
    return hits
