import re
from typing import Optional, Dict, Any
from ..schemas import NormalizedEvent

class SecurityRulesEngine:
    @staticmethod
    def evaluate_event(event: NormalizedEvent) -> Optional[Dict[str, Any]]:
        """
        Evaluates normalized event against deterministic security rules.
        Returns rule alert details or None if no rule triggered.
        """
        layer = event.layer
        action = event.action
        detail = event.detail
        
        # 1. Identity Layer: Brute Force Rule
        if layer == "identity" or action in ["login_fail", "auth_attempt"]:
            failed_count = detail.get("failed_login_count", 0)
            failure_rate = detail.get("login_failure_rate", 0.0)
            if failed_count >= 5 or failure_rate >= 0.7:
                return {
                    "rule_name": "Identity Brute Force Threshold Exceeded",
                    "severity": "HIGH",
                    "attack_type": "Brute Force",
                    "weight": 25.0,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "Brute Force",
                    "mitre_id": "T1110",
                    "description": f"Observed {failed_count} consecutive authentication failures (failure rate: {failure_rate:.0%})."
                }

        # 2. Network/Application Layer: SQL Injection Rule
        if layer in ["network", "identity"] or "payload" in detail or "url" in detail:
            payload = str(detail.get("payload", "")) + " " + str(detail.get("url", ""))
            sql_keywords = [r"UNION\s+SELECT", r"OR\s+1=1", r"--", r"DROP\s+TABLE", r"SELECT\s+.*\s+FROM"]
            for pattern in sql_keywords:
                if re.search(pattern, payload, re.IGNORECASE):
                    return {
                        "rule_name": "SQL Injection Signature Match",
                        "severity": "CRITICAL",
                        "attack_type": "SQL Injection",
                        "weight": 30.0,
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "Exploit Public-Facing Application",
                        "mitre_id": "T1190",
                        "description": f"SQL injection signature pattern detected in HTTP request payload."
                    }

        # 3. Network/Application Layer: XSS Rule
        if layer in ["network", "identity"] or "payload" in detail:
            payload = str(detail.get("payload", ""))
            xss_keywords = [r"<script.*?>", r"javascript:", r"onerror\s*=", r"onload\s*="]
            for pattern in xss_keywords:
                if re.search(pattern, payload, re.IGNORECASE):
                    return {
                        "rule_name": "Cross-Site Scripting (XSS) Signature Match",
                        "severity": "HIGH",
                        "attack_type": "XSS",
                        "weight": 20.0,
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "Exploit Public-Facing Application",
                        "mitre_id": "T1190",
                        "description": f"Cross-site scripting payload pattern identified."
                    }

        # 4. Network Layer: DDoS Rate Threshold Rule
        if layer == "network":
            req_rate = detail.get("request_rate", detail.get("req_per_sec", 0.0))
            if req_rate > 150.0:
                return {
                    "rule_name": "DDoS Volumetric Traffic Spike",
                    "severity": "HIGH",
                    "attack_type": "DDoS",
                    "weight": 25.0,
                    "mitre_tactic": "Impact",
                    "mitre_technique": "Endpoint Denial of Service",
                    "mitre_id": "T1499",
                    "description": f"Abnormal ingress request rate of {req_rate:.1f} req/sec detected."
                }

        # 5. Endpoint Layer: Suspicious Process Parent-Child Rule
        if layer == "endpoint" or action in ["process_create", "exec"]:
            proc = str(detail.get("process_name", "")).lower()
            parent = str(detail.get("parent_process", "")).lower()
            cmdline = str(detail.get("command_line", "")).lower()
            
            suspicious_parents = ["cmd.exe", "w3wp.exe", "nginx.exe", "apache2.exe", "excel.exe"]
            suspicious_children = ["powershell.exe", "wscript.exe", "certutil.exe", "vssadmin.exe", "bitsadmin.exe"]
            
            if (parent in suspicious_parents and proc in suspicious_children) or "enc" in cmdline or "downloadstring" in cmdline:
                return {
                    "rule_name": "Suspicious Process Spawning & Shell Execution",
                    "severity": "CRITICAL",
                    "attack_type": "Suspicious Process",
                    "weight": 35.0,
                    "mitre_tactic": "Execution",
                    "mitre_technique": "Command and Scripting Interpreter",
                    "mitre_id": "T1059",
                    "description": f"Suspicious parent-child execution: {parent} spawned {proc} with command args '{cmdline}'."
                }

        return None
