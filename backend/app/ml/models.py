import os
import joblib
import numpy as np
from datetime import datetime
from typing import Dict, Any, Optional
from .dataset_generator import FEATURE_NAMES, ATTACK_LABELS
from .trainer import train_and_evaluate_models, MODEL_DIR

# Business-hours window used to derive `off_hours_access` when a timestamp is available.
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 19


def _parse_hour(raw_timestamp: Any) -> Optional[int]:
    """
    Best-effort extraction of the hour-of-day from a timestamp value.
    Accepts datetime objects, ISO 8601 strings (with or without 'Z') and epoch seconds.
    Returns None when the value cannot be interpreted.
    """
    if raw_timestamp is None:
        return None
    if isinstance(raw_timestamp, datetime):
        return raw_timestamp.hour
    if isinstance(raw_timestamp, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw_timestamp)).hour
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(raw_timestamp, str):
        try:
            return datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00")).hour
        except ValueError:
            return None
    return None


class ThreatDetectionModels:
    _instance = None

    def __init__(self):
        self.rf_model = None
        self.iso_model = None
        self.metrics = None
        self.load_or_train()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_or_train(self):
        rf_path = os.path.join(MODEL_DIR, "random_forest.joblib")
        iso_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
        
        if not (os.path.exists(rf_path) and os.path.exists(iso_path)):
            print("[ML Engine] Saved models not found. Initializing training pipeline...")
            self.metrics = train_and_evaluate_models()
        else:
            self.metrics = train_and_evaluate_models()  # re-evaluate to populate metrics
            
        self.rf_model = joblib.load(rf_path)
        self.iso_model = joblib.load(iso_path)

    @property
    def num_classes(self) -> int:
        return len(ATTACK_LABELS)

    @property
    def num_features(self) -> int:
        return len(FEATURE_NAMES)

    def extract_features_from_event(self, detail: Dict[str, Any]) -> np.ndarray:
        """
        Converts a layer detail dictionary into the standard 12-element feature vector.

        The four newer features (`distinct_ports_touched`, `url_entropy`,
        `outbound_bytes_ratio`, `off_hours_access`) fall back to benign-looking
        defaults so legacy replay/telemetry events that never carried them keep
        scoring exactly as before.
        """
        packet_size = float(detail.get("packet_size", 500))
        protocol_str = str(detail.get("protocol", "TCP")).upper()
        protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "HTTPS": 3}
        protocol_type = protocol_map.get(protocol_str, 0)
        
        request_rate = float(detail.get("request_rate", detail.get("req_per_sec", 1.0)))
        session_duration = float(detail.get("session_duration", 10.0))
        payload_pattern_score = float(detail.get("payload_pattern_score", 0.0))
        login_failure_rate = float(detail.get("login_failure_rate", detail.get("failed_login_count", 0) / max(1, detail.get("total_login_attempts", 1))))
        is_suspicious_process = 1 if detail.get("is_suspicious_process", False) or detail.get("parent_process") in ["cmd.exe", "powershell.exe", "wscript.exe"] else 0
        privilege_level = 1 if detail.get("privilege_escalation", False) or detail.get("user_role") in ["admin", "SYSTEM", "root"] else 0

        # --- Extended features (safe, benign-looking defaults) ---
        distinct_ports_touched = float(detail.get(
            "distinct_ports_touched",
            detail.get("scanned_ports", detail.get("port_count", 1))
        ))
        url_entropy = float(detail.get("url_entropy", detail.get("domain_entropy", 0.1)))
        outbound_bytes_ratio = float(detail.get("outbound_bytes_ratio", 1.0))

        off_hours_raw = detail.get("off_hours_access")
        if off_hours_raw is not None:
            off_hours_access = 1 if bool(off_hours_raw) else 0
        else:
            # Derive from an explicit hour or any timestamp carried by the event,
            # otherwise assume the request happened during business hours.
            hour_of_day = detail.get("hour_of_day")
            if isinstance(hour_of_day, (int, float)) and not isinstance(hour_of_day, bool):
                hour = int(hour_of_day) % 24
            else:
                hour = _parse_hour(detail.get("timestamp") or detail.get("event_time"))
            off_hours_access = 0 if hour is None else int(not (BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END))

        vec = np.array([[
            packet_size,
            protocol_type,
            request_rate,
            session_duration,
            payload_pattern_score,
            login_failure_rate,
            is_suspicious_process,
            privilege_level,
            max(1.0, distinct_ports_touched),
            float(np.clip(url_entropy, 0.0, 1.0)),
            max(0.01, outbound_bytes_ratio),
            off_hours_access
        ]])
        return vec

    def predict(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs both Supervised Known-Attack Classification (Random Forest, 9 classes)
        and Unsupervised Zero-Day Anomaly Detection (Isolation Forest).
        """
        X_feat = self.extract_features_from_event(detail)
        
        # 1. Supervised RF Prediction
        probs = self.rf_model.predict_proba(X_feat)[0]
        predicted_class_idx = int(np.argmax(probs))
        confidence = float(probs[predicted_class_idx])
        attack_label = ATTACK_LABELS.get(predicted_class_idx, "Unknown")

        # Full per-class probability distribution keyed by human-readable class name.
        # rf_model.classes_ holds the label indices actually seen during training.
        class_probabilities: Dict[str, float] = {name: 0.0 for name in ATTACK_LABELS.values()}
        for cls_idx, prob in zip(self.rf_model.classes_, probs):
            class_probabilities[ATTACK_LABELS.get(int(cls_idx), f"Class {cls_idx}")] = float(round(float(prob), 4))
        
        # 2. Unsupervised Isolation Forest Prediction
        # decision_function: lower means more anomalous (negative)
        iso_score = float(self.iso_model.decision_function(X_feat)[0])
        is_anomaly = bool(self.iso_model.predict(X_feat)[0] == -1)
        # Normalize anomaly score 0.0 (normal) to 1.0 (highly anomalous)
        anomaly_intensity = float(np.clip(1.0 - (iso_score + 0.5), 0.0, 1.0))
        
        # Feature importances for explainability
        importances = self.rf_model.feature_importances_
        feat_imp_dict = {feat: float(round(imp, 4)) for feat, imp in zip(FEATURE_NAMES, importances)}
        
        return {
            "label": attack_label,
            "confidence": float(round(confidence, 4)),
            "class_probabilities": class_probabilities,
            "is_anomaly": is_anomaly,
            "anomaly_score": float(round(anomaly_intensity, 4)),
            "feature_importances": feat_imp_dict,
            "feature_vector": X_feat[0].tolist()
        }
