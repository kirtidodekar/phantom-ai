# 🛡️ Sentinel AI

### AI-Based Cyber Threat Detection & Early-Warning System

> **One-Line Pitch:**
> **Sentinel AI transforms scattered weak cyber signals into an explainable, evolving threat story—helping security teams identify which behavior is becoming dangerous before they are buried in isolated alerts.**

---

## 📌 Overview

Modern Security Operations Centers (SOCs) generate thousands of alerts across **network, endpoint, identity, and application layers**. The problem is not simply detecting anomalies—it is understanding **when individually weak signals collectively indicate an evolving attack**.

**Sentinel AI** is a lightweight, explainable cyber threat detection and early-warning platform that correlates heterogeneous telemetry into **high-context security incidents**.

Instead of treating every event as an isolated alert, Sentinel AI:

* Detects known attack patterns using supervised machine learning.
* Identifies previously unseen behavioral deviations using unsupervised anomaly detection.
* Correlates signals across multiple security layers.
* Builds an evolving threat trajectory rather than a static alert.
* Explains *why* an incident is considered risky.
* Maps detected behavior to **MITRE ATT&CK** techniques.
* Provides analysts with contextual tools such as **"What Changed?"**, attack stories, and incident replay.

### 🎯 Core Problem

> **How can we distinguish a harmless anomaly from the beginning of a coordinated attack?**

### 💡 Sentinel AI's Approach

> **Detect → Correlate → Reason → Explain → Respond**

---

# 🏗️ System Architecture

Sentinel AI deliberately separates **anomaly detection** from **security reasoning**.

This enables the system to detect both known threats and novel behavior while keeping the final risk decision transparent and auditable.

```text
┌──────────────────────────────────────────────────────────┐
│                    TELEMETRY SOURCES                     │
│     Network │ Endpoint │ Identity │ Application          │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│              EVENT NORMALIZATION ENGINE                  │
│        Common Event Envelope / Standard Schema            │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│             FEATURE EXTRACTION & BASELINE                │
│        Entity Profiles │ Historical Behavior              │
└────────────────────────────┬─────────────────────────────┘
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
┌─────────────────────────┐   ┌──────────────────────────┐
│ Supervised Detection    │   │ Unsupervised Detection   │
│                         │   │                          │
│ Random Forest           │   │ Isolation Forest         │
│ Known Attack Patterns   │   │ Novel Anomalies          │
└────────────┬────────────┘   └────────────┬─────────────┘
             │                             │
             └──────────────┬──────────────┘
                            ▼
┌──────────────────────────────────────────────────────────┐
│                  DETERMINISTIC RULE ENGINE                │
│      Security Rules │ Thresholds │ Context Validation     │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│               CROSS-SIGNAL CORRELATION ENGINE             │
│       Entity Linking │ Temporal Correlation │ Evidence    │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│              THREAT TRAJECTORY & RISK MODEL              │
│          Dynamic Score │ Confidence │ Severity             │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                 MITRE ATT&CK MAPPING                     │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                    SOC COMMAND DASHBOARD                  │
│  Incidents │ Attack Story │ Risk Timeline │ What Changed │
│  Entity Graph │ MITRE Mapping │ Simulated Response       │
└──────────────────────────────────────────────────────────┘
```

---

# 🔑 Key Features

## 1. 🔗 Cross-Layer Evidence Fusion

Sentinel AI correlates events across:

* Network
* Endpoint
* Identity
* Application

Events are linked using shared entities such as:

```text
user_id
host_id
ip_address
process_id
destination_ip
```

This allows the system to recognize relationships that would be missed when examining individual alerts independently.

---

## 2. 📈 Evolving Threat Trajectory

Instead of assigning a fixed severity to an isolated event, Sentinel AI maintains a **dynamic threat score from 0–100**.

The score can increase as additional evidence appears:

```text
Normal
  ↓
Failed Login
  ↓
Unusual Login
  ↓
Suspicious Process
  ↓
External Network Connection
  ↓
Cross-Layer Correlation
  ↓
HIGH-RISK INCIDENT
```

This creates an **early-warning mechanism** rather than a simple alert-generation system.

---

## 3. 🤖 Dual-Track Detection Engine

### Known Threat Detection

A supervised **Random Forest classifier** identifies attack patterns learned from benchmark cybersecurity datasets.

Potential attack categories include:

* Brute Force
* DDoS
* SQL Injection
* Other known malicious traffic patterns

### Novel Behavior Detection

An **Isolation Forest** identifies behavioral deviations that may not match known attack signatures.

This provides a second detection path for:

> **"This behavior is unusual, even if we don't know exactly what attack it represents."**

---

## 4. 🧠 Explainable Risk Scoring

Sentinel AI does not rely solely on an opaque ML probability.

The final threat score is calculated using an auditable evidence model.

```text
Threat Score
     │
     ├── Weighted Evidence
     ├── Cross-Layer Convergence
     ├── Temporal Strength
     ├── Asset Criticality
     └── Benign Context Reduction
```

### Example

```text
Endpoint Anomaly          +24
Network Anomaly           +21
Identity Anomaly          +15
Cross-Layer Convergence   +12
Asset Criticality         +10
                         ───
Total                     82/100
Severity                  HIGH
```

Every score can therefore be traced back to the evidence that contributed to it.

---

## 5. 🕸️ Interactive Attack Story & Entity Graph

The dashboard represents relationships between entities such as:

```text
User
  │
  ▼
Host
  │
  ▼
Process
  │
  ▼
Destination IP
```

The graph distinguishes between:

* **Observed evidence** — directly received telemetry.
* **Inferred relationships** — relationships identified through detection/correlation logic.

This makes the investigation process easier to understand for SOC analysts and demonstration judges.

---

## 6. 🔍 "What Changed?" Counterfactual Analysis

Instead of simply saying:

> **"This event is anomalous."**

Sentinel AI answers:

> **"How is this behavior different from the entity's normal behavior?"**

The dashboard compares current activity against historical baselines, allowing analysts to quickly understand:

* What changed?
* When did it change?
* How unusual is it?
* Which entity changed?
* Which signals contributed to the risk increase?

---

## 7. ⏪ Incident Replay Mode

Sentinel AI includes a controlled scenario engine capable of replaying predefined multi-stage attack scenarios.

Example:

```text
Stage 1 → Failed Authentication
Stage 2 → Suspicious Login
Stage 3 → Malicious Process
Stage 4 → External Connection
Stage 5 → Cross-Layer Correlation
Stage 6 → High-Risk Incident
```

Playback speeds can be accelerated for demonstrations and testing.

---

## 8. 🧪 Sandboxed Response Simulation

Analysts can trigger simulated containment actions without affecting real infrastructure.

Example:

```text
[ Simulate Block Target IP ]
```

The action updates the simulated incident state rather than modifying a real firewall or network environment.

> **No destructive or real-world infrastructure actions are performed by the demo system.**

---

# 📦 Normalized Event Schema

All telemetry sources are converted into a common event envelope before entering the detection and correlation pipeline.

```json
{
  "event_id": "evt-000123",
  "timestamp": "2026-01-14T09:32:11Z",
  "layer": "endpoint",
  "entity_id": "host:WKS-042",
  "user_id": "alice",
  "action": "process_create",
  "detail": {
    "process": "powershell.exe",
    "parent": "winword.exe",
    "cmdline": "-enc <base64_payload>"
  },
  "source_confidence": "high"
}
```

### Why Normalize Events?

A common schema allows different telemetry sources to be processed consistently.

```text
Network Event ─┐
Endpoint Event ├──► Common Event Schema ──► Correlation
Identity Event ┤
Application ───┘
```

---

# 🧮 Explainable Threat Model

The conceptual risk model is:

```text
Threat Score =
    Weighted Evidence
  + Cross-Layer Convergence
  + Temporal Strength
  + Asset Criticality
  - Benign Context
```

The resulting score is normalized to a **0–100 range**.

### Example

```text
Endpoint Anomaly          24
Network Anomaly           21
Identity Anomaly          15
Cross-Layer Convergence   12
Asset Criticality         10
────────────────────────────
Threat Score              82/100

Severity: HIGH
```

The important design principle is that **ML contributes evidence, while the security reasoning layer determines how evidence combines into an incident.**

---

# 🛡️ Attack Detection & MITRE ATT&CK Mapping

| Threat Category               | Detection Method                         | Telemetry Source       | MITRE ATT&CK                                 |
| ----------------------------- | ---------------------------------------- | ---------------------- | -------------------------------------------- |
| **Brute Force**               | Random Forest + failed-login rule        | Identity / Application | `T1110`                                      |
| **SQL Injection**             | ML classification + payload features     | Application / Network  | `T1190`                                      |
| **XSS**                       | ML classification + application features | Application / Network  | Context-dependent                            |
| **DDoS**                      | Random Forest + request-rate rule        | Network                | `T1498`                                      |
| **Novel / Zero-Day Behavior** | Isolation Forest + correlation           | Cross-Layer            | Technique assigned after behavioral analysis |

> **Note:** MITRE ATT&CK mappings are assigned according to the observed behavior. An anomaly itself is not automatically a MITRE technique; the system maps the underlying behavior where sufficient evidence exists.

---

# 🧰 Technology Stack

| Layer                   | Technology                      |
| ----------------------- | ------------------------------- |
| **Programming**         | Python, JavaScript              |
| **Machine Learning**    | scikit-learn                    |
| **ML Models**           | Random Forest, Isolation Forest |
| **Data Processing**     | pandas, NumPy                   |
| **Imbalanced Learning** | imbalanced-learn / SMOTE        |
| **Backend API**         | FastAPI                         |
| **Database**            | SQLite / PostgreSQL             |
| **Frontend**            | React + Vite                    |
| **Styling**             | Tailwind CSS                    |
| **Icons**               | Lucide Icons                    |
| **Charts**              | Recharts / Plotly               |
| **Entity Graph**        | React Flow / Cytoscape.js       |
| **Security Framework**  | MITRE ATT&CK                    |
| **Datasets**            | CIC-IDS2017, NSL-KDD            |
| **Version Control**     | Git + GitHub                    |

---

# 📊 Detection Strategy

Sentinel AI combines three complementary mechanisms:

| Layer                   | Purpose                      | Strength                            |
| ----------------------- | ---------------------------- | ----------------------------------- |
| **Supervised ML**       | Detect known attack patterns | High precision for learned patterns |
| **Unsupervised ML**     | Detect behavioral deviations | Novel/unknown behavior              |
| **Deterministic Rules** | Apply security context       | Transparent and controllable        |
| **Correlation Engine**  | Combine evidence             | Converts alerts into incidents      |
| **Risk Model**          | Prioritize incidents         | Explainable severity                |

### Why a Hybrid Architecture?

No single detection technique is sufficient.

```text
Known Attacks
     │
     ▼
Supervised ML ───────┐
                     │
Novel Behavior       │
     │               │
     ▼               │
Isolation Forest ────┤
                     ▼
              Evidence Fusion
                     │
                     ▼
              Security Reasoning
                     │
                     ▼
             Correlated Incident
```

---

# 🧪 Demo Scenario

The following scenario demonstrates how multiple weak signals can evolve into one high-confidence incident.

### Step 1 — Normal Baseline

The entity operates within its normal behavioral range.

```text
Threat Score: 12
Status: NORMAL
```

### Step 2 — Identity Burst

Multiple failed authentication attempts are detected.

```text
Threat Score: 31
Status: LOW / MEDIUM
```

### Step 3 — Unusual Authentication

A successful authentication occurs outside the established behavioral baseline.

```text
Threat Score: 48
Status: MEDIUM
```

### Step 4 — Suspicious Endpoint Activity

Endpoint telemetry detects an unusual process relationship:

```text
winword.exe
      │
      └──► powershell.exe
             └──► encoded command
```

```text
Threat Score: 67
Status: HIGH
```

### Step 5 — Network Convergence

The affected host communicates with a previously unseen external destination.

The correlation engine links the new evidence to the existing incident.

### Step 6 — Unified Incident

Instead of creating four unrelated alerts, Sentinel AI generates:

```text
ONE CORRELATED INCIDENT

Threat Score: 86/100
Severity: HIGH

Evidence:
✓ Identity anomaly
✓ Authentication anomaly
✓ Endpoint anomaly
✓ Network anomaly
✓ Temporal correlation
✓ Cross-layer convergence
```

### Step 7 — Analyst Investigation

The analyst can inspect:

* Threat trajectory
* Entity graph
* Evidence timeline
* MITRE ATT&CK mapping
* "What Changed?"
* Contributing signals

### Step 8 — Simulated Response

The analyst triggers:

```text
[ Simulate Block Target IP ]
```

The action is performed only within the sandboxed demonstration environment.

---

# 🚀 Getting Started

## Prerequisites

Make sure the following are installed:

* Python **3.10+**
* Node.js **18+**
* npm
* Git

---

## 1. Clone the Repository

```bash
git clone https://github.com/Sakshi867/sentinel-ai.git
cd sentinel-ai
```

---

## 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### macOS / Linux

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Train and preprocess the models:

```bash
python train_models.py
```

Start the FastAPI server:

```bash
uvicorn main:app --reload --port 8000
```

Backend API:

```text
http://localhost:8000
```

---

## 3. Frontend Setup

Open another terminal:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Open:

```text
http://localhost:5173
```

---

# 📁 Suggested Project Structure

```text
sentinel-ai/
│
├── backend/
│   ├── main.py
│   ├── train_models.py
│   ├── requirements.txt
│   │
│   ├── models/
│   │   ├── random_forest.pkl
│   │   └── isolation_forest.pkl
│   │
│   ├── data/
│   │   └── processed/
│   │
│   ├── services/
│   │   ├── detection.py
│   │   ├── correlation.py
│   │   ├── risk_engine.py
│   │   └── mitre_mapping.py
│   │
│   └── schemas/
│       └── events.py
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── utils/
│   │
│   ├── package.json
│   └── vite.config.js
│
├── datasets/
│   └── README.md
│
├── docs/
│   └── architecture.md
│
├── LICENSE
└── README.md
```

---

# 🎯 What Makes Sentinel AI Different?

Traditional security monitoring often follows:

```text
Event → Alert → Analyst
```

Sentinel AI focuses on:

```text
Event
  ↓
Detection
  ↓
Correlation
  ↓
Context
  ↓
Threat Trajectory
  ↓
Explainable Incident
  ↓
Analyst Action
```

### Key Differentiators

| Traditional Alerting         | Sentinel AI                   |
| ---------------------------- | ----------------------------- |
| Thousands of isolated alerts | Correlated incidents          |
| Static severity              | Evolving threat trajectory    |
| Single-layer analysis        | Cross-layer evidence fusion   |
| Known signatures             | Known + novel behavior        |
| Black-box score              | Explainable evidence          |
| "Something is wrong"         | "Here's what changed and why" |
| Alert-centric                | Incident-centric              |
| Manual investigation         | Guided investigation          |

---

# 🔐 Security & Safety

Sentinel AI is designed as a **defensive cybersecurity research and demonstration platform**.

The prototype:

* Uses controlled or benchmark telemetry.
* Does not require access to production infrastructure.
* Does not automatically execute destructive actions.
* Uses sandboxed response simulations.
* Keeps analyst actions reversible within the demonstration environment.

---

# 📚 Data & Research Sources

The project can be evaluated using established cybersecurity datasets and security standards, including:

* **CIC-IDS2017**
* **NSL-KDD**
* **MITRE ATT&CK**
* **MITRE ATT&CK STIX**

Dataset licenses and usage requirements should be reviewed before redistribution.

---

# 🗺️ Future Scope

Potential extensions include:

* Real-time streaming telemetry ingestion.
* Online baseline adaptation.
* Graph-based attack-path reasoning.
* Threat intelligence enrichment.
* LLM-assisted incident summarization.
* Automated MITRE ATT&CK technique extraction.
* SIEM integration.
* SOAR integration.
* Multi-tenant SOC support.
* Federated anomaly detection.
* Analyst feedback loops for continuous model improvement.

---

# 🏆 Project Vision

> **Sentinel AI is not designed to generate more alerts. It is designed to make existing signals meaningful.**

By combining **machine learning, behavioral baselines, cross-layer correlation, explainable risk scoring, and attack-story visualization**, Sentinel AI aims to reduce alert fatigue and help analysts identify **when normal-looking events begin forming a dangerous pattern**.

---

# 📄 License

This project is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for details.

---

## 👥 Contributors

**Sentinel AI Team**

Built as a cybersecurity AI research and hackathon project.
