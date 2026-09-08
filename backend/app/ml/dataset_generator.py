import numpy as np
import pandas as pd
from typing import Tuple

FEATURE_NAMES = [
    "packet_size",
    "protocol_type",       # 0: TCP, 1: UDP, 2: ICMP, 3: HTTP
    "request_rate",        # requests per sec
    "session_duration",    # in seconds
    "payload_pattern_score", # 0.0 clean to 1.0 suspicious (e.g. SQLi/XSS keywords)
    "login_failure_rate", # 0.0 to 1.0
    "is_suspicious_process", # 0 or 1 (e.g. cmd -> powershell)
    "privilege_level"      # 0: user, 1: admin/system
]

ATTACK_LABELS = {
    0: "Benign",
    1: "Brute Force",
    2: "SQL Injection",
    3: "XSS",
    4: "DDoS"
}

def generate_synthetic_dataset(num_samples: int = 3000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic synthetic network/endpoint dataset mimicking NSL-KDD / CIC-IDS2017 distribution.
    Features:
    - packet_size (bytes)
    - protocol_type (0: TCP, 1: UDP, 2: ICMP, 3: HTTP)
    - request_rate (req/sec)
    - session_duration (sec)
    - payload_pattern_score (0.0 to 1.0)
    - login_failure_rate (0.0 to 1.0)
    - is_suspicious_process (0 or 1)
    - privilege_level (0 or 1)
    - label: 0 (Benign ~ 80%), 1 (Brute Force ~ 5%), 2 (SQLi ~ 5%), 3 (XSS ~ 5%), 4 (DDoS ~ 5%)
    """
    np.random.seed(random_state)
    
    # 80% Benign, 5% Brute Force, 5% SQLi, 5% XSS, 5% DDoS
    n_benign = int(num_samples * 0.80)
    n_brute = int(num_samples * 0.05)
    n_sqli = int(num_samples * 0.05)
    n_xss = int(num_samples * 0.05)
    n_ddos = num_samples - (n_benign + n_brute + n_sqli + n_xss)

    rows = []

    # 1. Benign Traffic
    for _ in range(n_benign):
        rows.append({
            "packet_size": np.random.normal(500, 150),
            "protocol_type": np.random.choice([0, 1, 3], p=[0.5, 0.2, 0.3]),
            "request_rate": np.random.uniform(0.5, 5.0),
            "session_duration": np.random.exponential(30.0),
            "payload_pattern_score": np.random.uniform(0.0, 0.15),
            "login_failure_rate": np.random.uniform(0.0, 0.1),
            "is_suspicious_process": 0,
            "privilege_level": np.random.choice([0, 1], p=[0.9, 0.1]),
            "label": 0
        })

    # 2. Brute Force (Identity layer attack)
    for _ in range(n_brute):
        rows.append({
            "packet_size": np.random.normal(300, 50),
            "protocol_type": 3, # HTTP / Auth API
            "request_rate": np.random.uniform(15.0, 50.0), # high request rate on auth
            "session_duration": np.random.uniform(1.0, 10.0),
            "payload_pattern_score": np.random.uniform(0.1, 0.3),
            "login_failure_rate": np.random.uniform(0.85, 1.0), # very high failure rate
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "label": 1
        })

    # 3. SQL Injection (Application/Network layer attack)
    for _ in range(n_sqli):
        rows.append({
            "packet_size": np.random.normal(1200, 300), # larger payload with SQL keywords
            "protocol_type": 3, # HTTP
            "request_rate": np.random.uniform(1.0, 8.0),
            "session_duration": np.random.uniform(2.0, 20.0),
            "payload_pattern_score": np.random.uniform(0.75, 1.0), # high SQL signature score
            "login_failure_rate": np.random.uniform(0.0, 0.2),
            "is_suspicious_process": np.random.choice([0, 1], p=[0.7, 0.3]),
            "privilege_level": np.random.choice([0, 1], p=[0.6, 0.4]),
            "label": 2
        })

    # 4. XSS (Application/Network layer attack)
    for _ in range(n_xss):
        rows.append({
            "packet_size": np.random.normal(900, 200),
            "protocol_type": 3, # HTTP
            "request_rate": np.random.uniform(2.0, 10.0),
            "session_duration": np.random.uniform(1.0, 15.0),
            "payload_pattern_score": np.random.uniform(0.70, 0.98), # script tag patterns
            "login_failure_rate": np.random.uniform(0.0, 0.15),
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "label": 3
        })

    # 5. DDoS (Network layer volumetric attack)
    for _ in range(n_ddos):
        rows.append({
            "packet_size": np.random.normal(150, 40), # small flood packets
            "protocol_type": np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2]),
            "request_rate": np.random.uniform(200.0, 1000.0), # extreme request rate
            "session_duration": np.random.uniform(0.1, 2.0),
            "payload_pattern_score": np.random.uniform(0.0, 0.2),
            "login_failure_rate": 0.0,
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "label": 4
        })

    df = pd.DataFrame(rows)
    # Clip numerical ranges appropriately
    df["packet_size"] = df["packet_size"].clip(lower=40)
    df["request_rate"] = df["request_rate"].clip(lower=0.1)
    df["session_duration"] = df["session_duration"].clip(lower=0.01)
    df["payload_pattern_score"] = df["payload_pattern_score"].clip(0.0, 1.0)
    df["login_failure_rate"] = df["login_failure_rate"].clip(0.0, 1.0)

    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return df

def rebalance_dataset(X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Handles class imbalance using SMOTE if available, or target oversampling / class weighting.
    """
    try:
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(random_state=42, k_neighbors=3)
        X_res, y_res = smote.fit_resample(X, y)
        return X_res, y_res
    except ImportError:
        # Fallback to random oversampling for minority classes
        unique_classes, counts = np.unique(y, return_counts=True)
        max_count = max(counts)
        X_list, y_list = [X], [y]
        for cls in unique_classes:
            cls_idx = np.where(y == cls)[0]
            if len(cls_idx) < max_count:
                num_to_add = max_count - len(cls_idx)
                chosen = np.random.choice(cls_idx, size=num_to_add, replace=True)
                X_list.append(X[chosen])
                y_list.append(y[chosen])
        X_res = np.vstack(X_list)
        y_res = np.concatenate(y_list)
        # Shuffle
        perm = np.random.permutation(len(y_res))
        return X_res[perm], y_res[perm]
