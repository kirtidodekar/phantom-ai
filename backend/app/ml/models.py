import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from .dataset_generator import FEATURE_NAMES, ATTACK_LABELS
from .trainer import train_and_evaluate_models, MODEL_DIR

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

    def extract_features_from_event(self, detail: Dict[str, Any]) -> np.ndarray:
        """
        Converts layer detail dictionary into standard 8-element feature vector.
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
        
        vec = np.array([[
            packet_size,
            protocol_type,
            request_rate,
            session_duration,
            payload_pattern_score,
            login_failure_rate,
            is_suspicious_process,
            privilege_level
        ]])
        return vec

    def predict(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs both Supervised Known-Attack Classification (Random Forest)
        and Unsupervised Zero-Day Anomaly Detection (Isolation Forest).
        """
        X_feat = self.extract_features_from_event(detail)
        
        # 1. Supervised RF Prediction
        probs = self.rf_model.predict_proba(X_feat)[0]
        predicted_class_idx = int(np.argmax(probs))
        confidence = float(probs[predicted_class_idx])
        attack_label = ATTACK_LABELS.get(predicted_class_idx, "Unknown")
        
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
            "is_anomaly": is_anomaly,
            "anomaly_score": float(round(anomaly_intensity, 4)),
            "feature_importances": feat_imp_dict,
            "feature_vector": X_feat[0].tolist()
        }
