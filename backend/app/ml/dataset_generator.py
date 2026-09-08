import numpy as np
import pandas as pd
from typing import Tuple

# 12-element feature vector. The first 8 features are the original Sentinel-AI
# feature space (kept in order for backward compatibility with saved telemetry);
# the last 4 were added to make the 4 new attack classes linearly separable.
FEATURE_NAMES = [
    "packet_size",
    "protocol_type",       # 0: TCP, 1: UDP, 2: ICMP, 3: HTTP
    "request_rate",        # requests per sec
    "session_duration",    # in seconds
    "payload_pattern_score", # 0.0 clean to 1.0 suspicious (e.g. SQLi/XSS keywords)
    "login_failure_rate", # 0.0 to 1.0
    "is_suspicious_process", # 0 or 1 (e.g. cmd -> powershell)
    "privilege_level",      # 0: user, 1: admin/system
    "distinct_ports_touched",  # port-scan breadth -> Probe / Reconnaissance
    "url_entropy",             # 0.0-1.0 randomized / lookalike domain -> Phishing
    "outbound_bytes_ratio",    # egress/ingress ratio -> Malware C2 beaconing / exfil
    "off_hours_access"         # 0 or 1 -> Unauthorized Access
]

# 9 threat classes. Indices 0-4 are frozen for backward compatibility.
ATTACK_LABELS = {
    0: "Benign",
    1: "Brute Force",
    2: "SQL Injection",
    3: "XSS",
    4: "DDoS",
    5: "Probe / Reconnaissance",
    6: "Malware / C2 Beaconing",
    7: "Phishing",
    8: "Unauthorized Access"
}

# Approximate class proportions used by the synthetic generator.
# Benign remains the majority class (~58%); the remaining ~42% is split across
# the 8 attack classes so every class gets enough support to train on.
CLASS_PROPORTIONS = {
    0: 0.58,   # Benign
    1: 0.055,  # Brute Force
    2: 0.055,  # SQL Injection
    3: 0.05,   # XSS
    4: 0.055,  # DDoS
    5: 0.05,   # Probe / Reconnaissance
    6: 0.05,   # Malware / C2 Beaconing
    7: 0.05,   # Phishing
    8: 0.055   # Unauthorized Access (remainder is assigned to this class)
}


def generate_synthetic_dataset(num_samples: int = 6000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic synthetic network/endpoint/identity dataset mimicking the
    NSL-KDD / CIC-IDS2017 feature distribution, extended to 9 classes and 12 features.

    Features (12):
    - packet_size (bytes)
    - protocol_type (0: TCP, 1: UDP, 2: ICMP, 3: HTTP)
    - request_rate (req/sec)
    - session_duration (sec)
    - payload_pattern_score (0.0 to 1.0)
    - login_failure_rate (0.0 to 1.0)
    - is_suspicious_process (0 or 1)
    - privilege_level (0 or 1)
    - distinct_ports_touched (count of unique destination ports in the flow window)
    - url_entropy (0.0 to 1.0 - Shannon entropy of the requested host/URL, normalized)
    - outbound_bytes_ratio (egress bytes / ingress bytes)
    - off_hours_access (0 or 1 - request outside the 07:00-19:00 business window)

    Labels (9): 0 Benign (~58%), 1 Brute Force, 2 SQL Injection, 3 XSS, 4 DDoS,
    5 Probe / Reconnaissance, 6 Malware / C2 Beaconing, 7 Phishing, 8 Unauthorized Access.
    """
    np.random.seed(random_state)

    counts = {cls: int(num_samples * prop) for cls, prop in CLASS_PROPORTIONS.items()}
    # Assign any rounding remainder to the last class so len(df) == num_samples exactly
    counts[8] = num_samples - sum(v for k, v in counts.items() if k != 8)

    rows = []

    # ------------------------------------------------------------------
    # 0. Benign traffic - low port breadth, clean URLs, balanced I/O ratio,
    #    mostly business-hours access.
    # ------------------------------------------------------------------
    for _ in range(counts[0]):
        rows.append({
            "packet_size": np.random.normal(500, 150),
            "protocol_type": np.random.choice([0, 1, 3], p=[0.5, 0.2, 0.3]),
            "request_rate": np.random.uniform(0.5, 5.0),
            "session_duration": np.random.exponential(30.0),
            "payload_pattern_score": np.random.uniform(0.0, 0.15),
            "login_failure_rate": np.random.uniform(0.0, 0.1),
            "is_suspicious_process": 0,
            "privilege_level": np.random.choice([0, 1], p=[0.9, 0.1]),
            "distinct_ports_touched": np.random.randint(1, 6),
            "url_entropy": np.random.uniform(0.02, 0.25),
            "outbound_bytes_ratio": np.random.normal(1.0, 0.25),
            "off_hours_access": np.random.choice([0, 1], p=[0.92, 0.08]),
            "label": 0
        })

    # ------------------------------------------------------------------
    # 1. Brute Force (Identity layer) - password spraying against auth API.
    # ------------------------------------------------------------------
    for _ in range(counts[1]):
        rows.append({
            "packet_size": np.random.normal(300, 50),
            "protocol_type": 3,  # HTTP / Auth API
            "request_rate": np.random.uniform(15.0, 50.0),  # high request rate on auth
            "session_duration": np.random.uniform(1.0, 10.0),
            "payload_pattern_score": np.random.uniform(0.1, 0.3),
            "login_failure_rate": np.random.uniform(0.85, 1.0),  # very high failure rate
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "distinct_ports_touched": np.random.randint(1, 3),
            "url_entropy": np.random.uniform(0.05, 0.3),
            "outbound_bytes_ratio": np.random.normal(0.9, 0.2),
            "off_hours_access": np.random.choice([0, 1], p=[0.5, 0.5]),
            "label": 1
        })

    # ------------------------------------------------------------------
    # 2. SQL Injection (Application / Network layer).
    # ------------------------------------------------------------------
    for _ in range(counts[2]):
        rows.append({
            "packet_size": np.random.normal(1200, 300),  # larger payload with SQL keywords
            "protocol_type": 3,  # HTTP
            "request_rate": np.random.uniform(1.0, 8.0),
            "session_duration": np.random.uniform(2.0, 20.0),
            "payload_pattern_score": np.random.uniform(0.75, 1.0),  # high SQL signature score
            "login_failure_rate": np.random.uniform(0.0, 0.2),
            "is_suspicious_process": np.random.choice([0, 1], p=[0.7, 0.3]),
            "privilege_level": np.random.choice([0, 1], p=[0.6, 0.4]),
            "distinct_ports_touched": np.random.randint(1, 4),
            "url_entropy": np.random.uniform(0.25, 0.55),  # payload noise in query string
            "outbound_bytes_ratio": np.random.uniform(0.8, 2.5),
            "off_hours_access": np.random.choice([0, 1], p=[0.65, 0.35]),
            "label": 2
        })

    # ------------------------------------------------------------------
    # 3. XSS (Application / Network layer).
    # ------------------------------------------------------------------
    for _ in range(counts[3]):
        rows.append({
            "packet_size": np.random.normal(900, 200),
            "protocol_type": 3,  # HTTP
            "request_rate": np.random.uniform(2.0, 10.0),
            "session_duration": np.random.uniform(1.0, 15.0),
            "payload_pattern_score": np.random.uniform(0.70, 0.98),  # script tag patterns
            "login_failure_rate": np.random.uniform(0.0, 0.15),
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "distinct_ports_touched": np.random.randint(1, 4),
            "url_entropy": np.random.uniform(0.3, 0.6),  # encoded script payload in URL
            "outbound_bytes_ratio": np.random.uniform(0.7, 1.8),
            "off_hours_access": np.random.choice([0, 1], p=[0.7, 0.3]),
            "label": 3
        })

    # ------------------------------------------------------------------
    # 4. DDoS (Network layer volumetric flood).
    # ------------------------------------------------------------------
    for _ in range(counts[4]):
        rows.append({
            "packet_size": np.random.normal(150, 40),  # small flood packets
            "protocol_type": np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2]),
            "request_rate": np.random.uniform(200.0, 1000.0),  # extreme request rate
            "session_duration": np.random.uniform(0.1, 2.0),
            "payload_pattern_score": np.random.uniform(0.0, 0.2),
            "login_failure_rate": 0.0,
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "distinct_ports_touched": np.random.randint(1, 4),  # hammering few ports
            "url_entropy": np.random.uniform(0.0, 0.2),
            "outbound_bytes_ratio": np.random.uniform(0.05, 0.4),  # mostly ingress flood
            "off_hours_access": np.random.choice([0, 1], p=[0.6, 0.4]),
            "label": 4
        })

    # ------------------------------------------------------------------
    # 5. Probe / Reconnaissance (Network layer) - horizontal/vertical port scan:
    #    huge port breadth, tiny packets, near-zero session duration.
    # ------------------------------------------------------------------
    for _ in range(counts[5]):
        rows.append({
            "packet_size": np.random.normal(80, 25),  # SYN / ICMP probes
            "protocol_type": np.random.choice([0, 2], p=[0.75, 0.25]),  # TCP SYN or ICMP
            "request_rate": np.random.uniform(8.0, 80.0),
            "session_duration": np.random.uniform(0.02, 1.5),  # never completes a session
            "payload_pattern_score": np.random.uniform(0.0, 0.15),  # no payload to match
            "login_failure_rate": np.random.uniform(0.0, 0.1),
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "distinct_ports_touched": np.random.randint(50, 501),  # scan breadth signature
            "url_entropy": np.random.uniform(0.0, 0.15),
            "outbound_bytes_ratio": np.random.uniform(1.5, 6.0),  # many SYNs, few replies
            "off_hours_access": np.random.choice([0, 1], p=[0.45, 0.55]),
            "label": 5
        })

    # ------------------------------------------------------------------
    # 6. Malware / C2 Beaconing (Endpoint + Network) - low-and-slow regular
    #    beacons from a suspicious process with heavy egress skew (exfil).
    # ------------------------------------------------------------------
    for _ in range(counts[6]):
        rows.append({
            "packet_size": np.random.normal(280, 35),  # fixed-size beacon frames
            "protocol_type": np.random.choice([0, 3], p=[0.35, 0.65]),  # TCP or HTTP(S) C2
            "request_rate": np.random.uniform(0.05, 1.5),  # deliberately low volume
            "session_duration": np.random.uniform(45.0, 400.0),  # long-lived channel
            "payload_pattern_score": np.random.uniform(0.3, 0.65),  # obfuscated/encoded
            "login_failure_rate": np.random.uniform(0.0, 0.1),
            "is_suspicious_process": 1,  # spawned by cmd/powershell/wscript
            "privilege_level": np.random.choice([0, 1], p=[0.3, 0.7]),
            "distinct_ports_touched": np.random.randint(1, 5),
            "url_entropy": np.random.uniform(0.35, 0.75),  # DGA-ish but not lookalike
            "outbound_bytes_ratio": np.random.uniform(5.0, 40.0),  # exfil signature
            "off_hours_access": np.random.choice([0, 1], p=[0.4, 0.6]),
            "label": 6
        })

    # ------------------------------------------------------------------
    # 7. Phishing (Identity + Application) - lookalike / randomized domain,
    #    plausible HTTP session, credentials usually accepted on first try.
    # ------------------------------------------------------------------
    for _ in range(counts[7]):
        rows.append({
            "packet_size": np.random.normal(750, 180),
            "protocol_type": 3,  # HTTP(S) landing page
            "request_rate": np.random.uniform(0.5, 6.0),
            "session_duration": np.random.uniform(3.0, 60.0),  # short-to-mid dwell
            "payload_pattern_score": np.random.uniform(0.2, 0.5),  # credential form, no exploit
            "login_failure_rate": np.random.uniform(0.0, 0.15),  # victim submits valid creds
            "is_suspicious_process": 0,
            "privilege_level": 0,
            "distinct_ports_touched": np.random.randint(1, 4),
            "url_entropy": np.random.uniform(0.7, 1.0),  # randomized/lookalike host
            "outbound_bytes_ratio": np.random.uniform(1.2, 3.5),  # POSTed credentials
            "off_hours_access": np.random.choice([0, 1], p=[0.55, 0.45]),
            "label": 7
        })

    # ------------------------------------------------------------------
    # 8. Unauthorized Access (Identity layer) - "looks normal but should not be
    #    happening": valid-account use at odd hours with elevated privilege and
    #    only a couple of failed attempts before success.
    # ------------------------------------------------------------------
    for _ in range(counts[8]):
        rows.append({
            "packet_size": np.random.normal(520, 130),  # indistinguishable from normal
            "protocol_type": np.random.choice([0, 3], p=[0.4, 0.6]),
            "request_rate": np.random.uniform(0.5, 6.0),
            "session_duration": np.random.uniform(20.0, 300.0),
            "payload_pattern_score": np.random.uniform(0.0, 0.25),
            "login_failure_rate": np.random.uniform(0.2, 0.5),  # a few failures, then success
            "is_suspicious_process": np.random.choice([0, 1], p=[0.8, 0.2]),
            "privilege_level": 1,  # admin/SYSTEM session
            "distinct_ports_touched": np.random.randint(1, 8),
            "url_entropy": np.random.uniform(0.05, 0.3),
            "outbound_bytes_ratio": np.random.uniform(0.8, 3.0),
            "off_hours_access": 1,  # outside business window
            "label": 8
        })

    df = pd.DataFrame(rows)
    # Clip numerical ranges appropriately
    df["packet_size"] = df["packet_size"].clip(lower=40)
    df["request_rate"] = df["request_rate"].clip(lower=0.1)
    df["session_duration"] = df["session_duration"].clip(lower=0.01)
    df["payload_pattern_score"] = df["payload_pattern_score"].clip(0.0, 1.0)
    df["login_failure_rate"] = df["login_failure_rate"].clip(0.0, 1.0)
    df["distinct_ports_touched"] = df["distinct_ports_touched"].clip(lower=1)
    df["url_entropy"] = df["url_entropy"].clip(0.0, 1.0)
    df["outbound_bytes_ratio"] = df["outbound_bytes_ratio"].clip(lower=0.01)
    df["off_hours_access"] = df["off_hours_access"].clip(0, 1)

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
