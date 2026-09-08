from typing import Dict, Any
from ..schemas import MitreTag

MITRE_DATABASE = {
    "Brute Force": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "description": "Adversaries may attempt to gain access to valid credentials by systematically password guessing."
    },
    "SQL Injection": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "description": "Adversaries may attempt to exploit a vulnerability in a web application to gain initial access."
    },
    "XSS": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "description": "Adversaries may inject client-side scripts into web pages viewed by users."
    },
    "DDoS": {
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service",
        "technique_id": "T1499",
        "description": "Adversaries may perform Endpoint or Network DoS to disrupt service availability."
    },
    "Suspicious Process": {
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands."
    },
    "Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "technique": "Exploitation for Privilege Escalation",
        "technique_id": "T1068",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevated privileges."
    },
    "Probe / Reconnaissance": {
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "description": "Adversaries may enumerate reachable hosts, services and open ports to plan follow-on activity."
    },
    "Malware / C2 Beaconing": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "description": "Adversaries may use application layer protocols for command-and-control traffic that blends with normal activity."
    },
    "Phishing": {
        "tactic": "Initial Access",
        "technique": "Phishing",
        "technique_id": "T1566",
        "description": "Adversaries may send malicious content to obtain credentials or execute code on a target host."
    },
    "Unauthorized Access": {
        "tactic": "Initial Access",
        "technique": "Valid Accounts / External Remote Services",
        "technique_id": "T1078",
        "description": "Adversaries may use legitimate credentials or exposed remote services to access systems without authorization."
    },
    "Network Denial of Service": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
        "description": "Adversaries may degrade availability by saturating network bandwidth or connection capacity."
    },
    "Anomaly": {
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information / Zero-Day Pattern",
        "technique_id": "T1027",
        "description": "Unsupervised Isolation Forest detected behavioral deviation from established baseline."
    }
}

def map_event_to_mitre(attack_type: str, fallback_rule_mitre: Dict[str, str] = None) -> MitreTag:
    """
    Returns structured MitreTag for a given attack type or rule payload.
    """
    if fallback_rule_mitre and "mitre_id" in fallback_rule_mitre:
        return MitreTag(
            tactic=fallback_rule_mitre.get("mitre_tactic", "Initial Access"),
            technique=fallback_rule_mitre.get("mitre_technique", "Unknown Technique"),
            technique_id=fallback_rule_mitre.get("mitre_id", "T1000"),
            description=fallback_rule_mitre.get("description", "Security rule match")
        )

    info = MITRE_DATABASE.get(attack_type) or MITRE_DATABASE["Anomaly"]
    return MitreTag(
        tactic=info["tactic"],
        technique=info["technique"],
        technique_id=info["technique_id"],
        description=info["description"]
    )
