# Requirements Document

## Introduction

This specification upgrades the existing Sentinel AI defensive research and demonstration platform without replacing the working FastAPI, React, machine-learning, incident-correlation, replay, or sandboxed-response behavior. The upgrade completes interrupted integration work, makes the backend authoritative for live detection and defense state, introduces non-destructive PostgreSQL/Supabase persistence, and verifies the complete system on the established ports.

The approved scope is an upgrade of the repository at `e:\New folder (81)\sentinel-ai\sentinel-ai`; the scope is not a greenfield rewrite. No credential, connection secret, token, or previously supplied Supabase value may appear in this specification or in tracked source files.

## Current-State Audit

| Area | Audit status | Existing foundation to preserve | Upgrade gap to close |
|---|---|---|---|
| API runtime | Present | `backend/app/main.py` exposes a FastAPI application and all existing incident, replay, feedback, baseline, detection, defense, and integration routes. | Split cross-cutting concerns into modular contracts/services without changing paths or introducing Flask. |
| Machine learning | Present, naming partially inconsistent | `ThreatDetectionModels`, `dataset_generator.py`, and `trainer.py` use real scikit-learn Random Forest and Isolation Forest models over 12 features and 9 labels. | Publish the exact approved canonical class names, retain stable model indices through aliases, validate inputs, and add comprehensive tests. |
| Live detection | Present, in-memory | `engine/live_detection.py` produces prediction, simulated stream, rolling statistics, policy, and blocklist payloads. | Persist required state, centralize errors/logging, align thresholds/taxonomy, and make stream provenance explicit. |
| Defense | Broken frontend integration and split authority | Backend defense endpoints and frontend `lib/defense.jsx` exist. | `DefenseProvider` is not mounted although Live Monitor and Auto Defense consume the context; local seed state diverges from the backend and some actions are issued twice. |
| Persistence | Partial | `database.py` supports PostgreSQL URLs, TLS enforcement, the `sentinel_ai` default schema, non-destructive table creation, and SQLite when `DATABASE_URL` is empty. | Add versioned migrations, repositories for new state, startup hydration, structured failures, and broader integration tests. |
| API client | Partial | `frontend/src/lib/api.js` centralizes many route helpers. | Remaining components call `fetch` directly; current helpers silently convert transport failures into data-like fallbacks, preventing consistent error states. |
| Notifications | Present, partially wired | Notification provider, toasts, center, and unread state exist. | Connect authoritative critical detections, defense actions, and service failures without duplicate alerts. |
| Enterprise UI | Substantially present | Live Monitor, Threat Classification, Auto Defense, Integrations, navbar tabs, shared primitives, light tokens, and a professional Landing Page exist. | Repair provider/routing integration, replace hard-coded metrics, normalize remote payloads, label demo data, complete accessibility/error states, and remove theme inconsistencies. |
| Tests | Insufficient | Two SQLite/database unit tests pass; frontend production build passes. | Add backend and frontend unit/integration coverage, API contract tests, accessibility checks, secret scans, and finite end-to-end smoke validation. |
| Quality baseline | Partial | Frontend build succeeds and current backend database tests pass. | Resolve relevant lint warnings, verify runtime routes, and address the large-bundle warning through safe code splitting where practical. |

## Glossary

- **Sentinel_AI_Platform**: The complete FastAPI backend, React frontend, machine-learning engines, persistence adapters, and sandboxed demonstration behavior in this repository.
- **API_Runtime**: The existing FastAPI application served by Uvicorn on TCP port 8000.
- **Compatibility_Layer**: Route and contract behavior that keeps existing API consumers and existing dashboard workflows operational during the upgrade.
- **Detection_Engine**: The Python service that extracts 12 model features, invokes both trained scikit-learn models, fuses model evidence, and returns a detection result.
- **Random_Forest_Model**: The trained scikit-learn supervised classifier that returns probabilities for the nine threat classes.
- **Isolation_Forest_Model**: The trained scikit-learn anomaly detector that returns anomaly status and normalized anomaly intensity.
- **Canonical_Class**: One value from this exact taxonomy: `Benign`, `SQL Injection`, `XSS`, `Brute Force`, `Malware/C2`, `Phishing`, `DoS/DDoS`, `Probe/Reconnaissance`, or `Unauthorized Access`.
- **Legacy_Class_Alias**: An existing label such as `DDoS`, `Malware / C2 Beaconing`, or `Probe / Reconnaissance` that maps to one Canonical_Class without changing the trained model index.
- **Detection_Result**: The public prediction payload containing class probabilities, confidence, anomaly evidence, fused risk, severity, MITRE context, model metadata, and measured inference latency.
- **Live_Stream**: A polling API and frontend view that generates demo telemetry and scores every event with the real trained models.
- **Sandbox**: The demonstration-only response boundary that records decisions but does not alter a firewall, operating system, cloud resource, identity provider, or external network.
- **Defense_Service**: The backend-authoritative service for automatic and manual sandboxed IP blocks, configuration, policy simulation, and audit history.
- **Effective_Threshold**: The risk threshold used for automatic block decisions after an optional adaptive-policy adjustment.
- **Defense_Audit_Record**: A persistent append-only record of a block, repeat hit, unblock, configuration change, or policy action.
- **Adaptive_Policy**: The explicitly simulated Deep Q-Network-style response policy; the Adaptive_Policy is not represented as a trained production reinforcement-learning agent.
- **Persistence_Layer**: The provider-neutral repository and migration code that uses PostgreSQL when `DATABASE_URL` is configured and SQLite only when `DATABASE_URL` is absent or empty.
- **PostgreSQL_Database**: A PostgreSQL-compatible service, including Supabase PostgreSQL, reached exclusively through `DATABASE_URL` with TLS.
- **Migration_Manager**: Versioned, idempotent schema-upgrade code that creates or alters missing objects without dropping, truncating, or replacing existing data.
- **API_Client**: `frontend/src/lib/api.js`, the single browser transport boundary for backend requests and normalized API errors.
- **Defense_Store**: The React context that owns synchronized defense loading, mutation, and error state while treating the backend as authoritative.
- **Notification_Service**: The React provider, toast viewport, and persistent notification center used for operational alerts.
- **Light_SOC_Theme**: The existing light security-operations visual language based on white surfaces, slate text, blue primary actions, semantic risk colors, visible focus states, and reduced-motion support.
- **Structured_Error**: A safe API error containing an HTTP status, stable code, human-readable message, and request identifier without a stack trace or secret.
- **Structured_Log**: A machine-readable log event with timestamp, level, event name, request identifier, and non-sensitive context.
- **Demo_Data**: Synthetic or representative data that is visibly labeled and never presented as production telemetry.
- **Smoke_Validator**: A finite automated check that starts or connects to the two local services, verifies critical routes and UI delivery, and terminates cleanly.

## Requirements

### Requirement 1: Preserve the Existing FastAPI Platform

**User Story:** As a current Sentinel AI user, I want the upgrade to preserve established workflows and contracts, so that new capabilities do not break the working demonstration.

#### Acceptance Criteria

1. THE API_Runtime SHALL remain the only backend HTTP application for the Sentinel_AI_Platform.
2. THE API_Runtime SHALL use FastAPI served through Uvicorn rather than a second Flask application.
3. THE Compatibility_Layer SHALL preserve every existing route method and path documented in the Existing Route Inventory section of the design document.
4. WHEN an existing client sends a valid request accepted before the upgrade, THE Compatibility_Layer SHALL return a semantically equivalent successful response.
5. WHEN the API_Runtime starts, THE Sentinel_AI_Platform SHALL initialize persistence and the existing replay-backed dashboard state without deleting stored records.
6. IF an existing incident, replay, feedback, baseline, or analyst-action operation fails, THEN THE API_Runtime SHALL return a Structured_Error with the appropriate non-2xx status.
7. THE Sentinel_AI_Platform SHALL preserve current incident correlation, attack trajectory, MITRE mapping, replay, analyst feedback, baseline comparison, and sandboxed analyst-action behavior.

### Requirement 2: Produce Real-Time Dual-Model Predictions

**User Story:** As a SOC analyst, I want each event scored by supervised and unsupervised models, so that known attacks and unusual behavior are visible together.

#### Acceptance Criteria

1. WHEN a valid prediction request is received, THE Detection_Engine SHALL invoke the trained Random_Forest_Model and the trained Isolation_Forest_Model.
2. WHEN both model outputs are available, THE Detection_Engine SHALL return one Detection_Result containing `predicted_class`, `confidence`, `class_probabilities`, `is_anomaly`, `anomaly_score`, `verdict`, `risk_score`, `severity`, `mitre`, `recommended_action`, `feature_importances`, `feature_vector`, `model`, and `latency_ms`.
3. THE Detection_Engine SHALL publish exactly nine Canonical_Class values.
4. THE Detection_Engine SHALL map every Legacy_Class_Alias to exactly one Canonical_Class at API and UI boundaries.
5. THE Detection_Engine SHALL retain stable trained-model class indices while applying Canonical_Class display names.
6. WHEN the Random_Forest_Model returns probabilities, THE Detection_Engine SHALL return one probability in the inclusive range 0.0 through 1.0 for every Canonical_Class.
7. WHEN the Detection_Engine returns all class probabilities, THE Detection_Engine SHALL keep the probability sum within 0.01 of 1.0.
8. WHEN the Isolation_Forest_Model returns a score, THE Detection_Engine SHALL normalize `anomaly_score` to the inclusive range 0.0 through 1.0.
9. WHEN inference completes, THE Detection_Engine SHALL return `latency_ms` as the measured non-negative elapsed inference time in milliseconds.
10. WHEN a legacy telemetry event omits one of the four extended features, THE Detection_Engine SHALL apply the existing benign-compatible default for the missing feature.
11. IF a prediction payload contains an invalid numeric value or unsupported structure, THEN THE API_Runtime SHALL return a Structured_Error with HTTP status 400 or 422.
12. WHEN valid saved model artifacts are available, THE Detection_Engine SHALL load the saved artifacts without retraining the models during API startup.

### Requirement 3: Expose Live Detection and Analytics APIs

**User Story:** As a dashboard client, I want stable detection and analytics contracts, so that every enterprise view can render authoritative data.

#### Acceptance Criteria

1. WHEN `POST /api/detect/predict` receives a valid payload, THE API_Runtime SHALL return the PredictionResponse contract defined in the design document.
2. WHEN `GET /api/detect/stream` receives `count` below 1, THE API_Runtime SHALL generate 1 scored detection.
3. WHEN `GET /api/detect/stream` receives `count` above 50, THE API_Runtime SHALL generate 50 scored detections.
4. WHEN `GET /api/detect/stream` generates a detection, THE Live_Stream SHALL score the detection through both trained models.
5. WHEN `GET /api/detect/stream` returns Demo_Data, THE Live_Stream SHALL identify the returned detections as simulated.
6. WHEN `GET /api/detect/classes` succeeds, THE API_Runtime SHALL return all nine Canonical_Class catalog entries with stable identifiers, descriptions, MITRE identifiers, layer hints, and severity hints.
7. WHEN `GET /api/stats/overview` succeeds, THE API_Runtime SHALL return uptime, event throughput, detection counts, blocked-IP count, average confidence, average latency, model quality, class distribution, severity distribution, and throughput history.
8. WHILE scored events are processed, THE Detection_Engine SHALL update rolling statistics once per processed event.
9. THE Compatibility_Layer SHALL preserve `GET /api/metrics` as the model-evaluation report source.
10. IF a required model artifact cannot be loaded, THEN THE API_Runtime SHALL report an unavailable detection service without fabricating a live model response.

### Requirement 4: Enforce Sandboxed Automated Defense

**User Story:** As a security administrator, I want configurable automatic classification and blocking of malicious source addresses, so that high-risk activity is contained safely in the demonstration.

#### Acceptance Criteria

1. WHEN a detection has a source IP, a `malicious` verdict, and a risk score at or above the Effective_Threshold, THE Defense_Service SHALL add or update a sandboxed block entry for the source IP.
2. WHEN a detection has a `benign` verdict, THE Defense_Service SHALL resolve the automatic response to monitoring without adding a block entry.
3. WHILE automatic blocking is disabled, THE Defense_Service SHALL record detections without adding automatic block entries.
4. WHERE adaptive defense is enabled, THE Defense_Service SHALL calculate an Effective_Threshold in the inclusive range 50.0 through 95.0.
5. WHERE adaptive defense is disabled, THE Defense_Service SHALL use the configured threshold as the Effective_Threshold.
6. WHEN a defense configuration update supplies a threshold, THE Defense_Service SHALL clamp the configured threshold to the inclusive range 0.0 through 100.0.
7. WHEN a valid manual IPv4 or IPv6 block request is received, THE Defense_Service SHALL add or update one sandboxed block entry.
8. IF a manual block request contains an invalid IP address, THEN THE API_Runtime SHALL return a Structured_Error with HTTP status 422.
9. WHEN an existing IP address is blocked again, THE Defense_Service SHALL preserve the original block timestamp and increment the hit count.
10. WHEN an existing block entry is removed, THE Defense_Service SHALL remove the active entry and append an unblock Defense_Audit_Record.
11. WHEN any block, repeat hit, unblock, configuration change, or policy action occurs, THE Defense_Service SHALL append a Defense_Audit_Record containing timestamp, action, target, mode, reason, risk context, and sandbox status.
12. THE Defense_Service SHALL mark every defense action as sandboxed.
13. THE Defense_Service SHALL perform zero firewall, operating-system networking, cloud-control-plane, identity-provider, or external-service mutations.
14. WHEN `GET /api/defense/blocklist`, `POST /api/defense/block`, `DELETE /api/defense/block/{ip}`, `POST /api/defense/config`, or `GET /api/defense/policy` succeeds, THE API_Runtime SHALL return the exact contract defined in the design document.
15. THE Adaptive_Policy SHALL be labeled as a research simulation in API metadata and user-visible content.

### Requirement 5: Persist Platform and Defense State Safely

**User Story:** As a platform operator, I want durable provider-neutral persistence, so that audit and application state survive restarts without risking existing data.

#### Acceptance Criteria

1. WHEN `DATABASE_URL` contains a PostgreSQL URL, THE Persistence_Layer SHALL use the configured PostgreSQL_Database.
2. WHEN the Persistence_Layer uses the PostgreSQL_Database, THE Persistence_Layer SHALL require `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full`.
3. WHEN the Persistence_Layer uses the PostgreSQL_Database, THE Persistence_Layer SHALL place Sentinel AI objects in the dedicated `sentinel_ai` schema.
4. WHEN `DATABASE_URL` is absent or empty, THE Persistence_Layer SHALL use the local SQLite database.
5. IF `DATABASE_URL` is configured but PostgreSQL connection, authentication, DNS, permission, or TLS validation fails, THEN THE Persistence_Layer SHALL fail the configured operation without switching to SQLite.
6. WHEN the API_Runtime starts, THE Migration_Manager SHALL apply pending migrations in ascending version order.
7. WHEN a migration has already been recorded, THE Migration_Manager SHALL skip the recorded migration.
8. THE Migration_Manager SHALL preserve existing rows while creating or altering required schema objects.
9. THE Persistence_Layer SHALL persist normalized events, incidents, analyst feedback, sandboxed actions, defense configuration, active blocks, and defense audit history.
10. WHEN the API_Runtime restarts, THE Defense_Service SHALL hydrate active block entries and defense configuration from the Persistence_Layer.
11. WHEN the API_Runtime health route succeeds, THE Persistence_Layer SHALL report only backend type, connection state, schema, and a safe error category.
12. THE repository `.gitignore` SHALL ignore local `.env` files and runtime database files.
13. THE tracked `backend/.env.example` SHALL contain placeholders only for `DATABASE_URL` and the `sentinel_ai` schema.
14. THE Sentinel_AI_Platform SHALL obtain PostgreSQL credentials only from environment configuration.
15. IF a database error contains a URL, password, token, host credential, or connection detail, THEN THE Persistence_Layer SHALL redact the sensitive value from API responses and Structured_Logs.

### Requirement 6: Centralize API, State, Errors, and Logs

**User Story:** As a developer, I want modular boundaries and consistent failures, so that the upgrade remains maintainable and diagnosable.

#### Acceptance Criteria

1. THE API_Client SHALL be the only frontend module that calls the browser `fetch` API for Sentinel AI backend routes.
2. WHEN an HTTP request fails, THE API_Client SHALL return or throw one normalized client error containing status, code, message, and request identifier.
3. IF a response body is not valid JSON, THEN THE API_Client SHALL return a normalized client error without exposing the raw response body as trusted UI content.
4. WHEN a frontend view uses Demo_Data after an API failure, THE frontend view SHALL display an explicit offline or simulated-data indicator.
5. THE Defense_Store SHALL use backend blocklist and configuration responses as authoritative state.
6. WHEN the application root renders dashboard routes, THE Sentinel_AI_Platform SHALL mount the Defense_Store provider before any defense consumer renders.
7. WHEN one defense mutation succeeds, THE Defense_Store SHALL update local state once from the authoritative response.
8. IF one defense mutation fails, THEN THE Defense_Store SHALL retain the last confirmed state and expose a visible error.
9. THE API_Runtime SHALL convert uncaught request failures into Structured_Errors through centralized exception handling.
10. WHEN the API_Runtime handles a request, THE API_Runtime SHALL attach or propagate one request identifier.
11. WHEN the API_Runtime completes a request, THE API_Runtime SHALL emit one Structured_Log containing method, route, status, latency, and request identifier.
12. WHEN the Detection_Engine completes inference, THE Detection_Engine SHALL emit a Structured_Log containing model names, Canonical_Class, verdict, severity, and latency without raw payload content.
13. WHEN the Defense_Service changes state, THE Defense_Service SHALL emit a Structured_Log containing action, sandbox status, and non-sensitive target context.
14. THE Structured_Log formatter SHALL exclude authorization headers, cookies, database URLs, passwords, tokens, and raw telemetry payloads.

### Requirement 7: Deliver Authoritative Live Monitoring

**User Story:** As a SOC analyst, I want a responsive live monitoring console, so that throughput, detections, model quality, and automated response remain visible in one view.

#### Acceptance Criteria

1. WHEN the Live Monitor route opens, THE Live_Stream SHALL begin polling the configured detection stream through the API_Client.
2. WHILE Live Monitor polling is active, THE Live Monitor SHALL display events per second, threat count, class distribution, average confidence, average latency, and blocked-IP count.
3. WHEN a detection row renders, THE Live Monitor SHALL display timestamp, source IP, layer, Canonical_Class, confidence, risk, MITRE identifier, and response state.
4. WHEN a user pauses the Live_Stream, THE Live Monitor SHALL retain the current feed without issuing new stream requests.
5. WHEN a user resumes the Live_Stream, THE Live Monitor SHALL resume requests at the selected 700 ms, 1500 ms, or 3000 ms cadence.
6. WHEN a user changes search, class, or threat-only filters, THE Live Monitor SHALL filter existing rows without changing backend state.
7. WHEN the stream contains no rows, THE Live Monitor SHALL render a labeled empty state.
8. WHILE stream data is loading, THE Live Monitor SHALL render a non-blocking loading state.
9. IF a stream request fails, THEN THE Live Monitor SHALL render a visible error or explicitly labeled Demo_Data state.
10. WHEN a manual block succeeds from a detection row, THE Live Monitor SHALL display the authoritative sandboxed block state returned by the Defense_Service.
11. WHEN a live inference request succeeds, THE Live Monitor SHALL display all nine class probabilities, confidence, anomaly score, fused risk, recommended action, and measured latency.

### Requirement 8: Notify Administrators of Critical Events

**User Story:** As an administrator, I want prioritized operational alerts, so that critical detections and response actions are not missed.

#### Acceptance Criteria

1. WHEN a new detection has `CRITICAL` severity, THE Notification_Service SHALL create a critical toast and one notification-center entry.
2. WHEN an automatic sandboxed block succeeds, THE Notification_Service SHALL create one warning or critical notification containing source IP, Canonical_Class, risk score, and sandbox label.
3. WHEN a manual block or unblock succeeds, THE Notification_Service SHALL create one action-result notification.
4. IF the Detection_Engine, Persistence_Layer, or Defense_Service becomes unavailable, THEN THE Notification_Service SHALL create one service-degradation notification per failure episode.
5. WHEN a duplicate event identifier has already produced a notification, THE Notification_Service SHALL suppress a second notification for the duplicate identifier.
6. WHEN a user opens the notification center, THE Notification_Service SHALL mark current entries as read.
7. WHEN a user clears the notification center, THE Notification_Service SHALL remove displayed entries without deleting Defense_Audit_Records.
8. WHILE a toast is displayed, THE Notification_Service SHALL provide a keyboard-accessible dismiss control.

### Requirement 9: Complete the Enterprise Frontend Experience

**User Story:** As a Sentinel AI user, I want a coherent enterprise console, so that monitoring, model analysis, response, and integrations feel like one accessible product.

#### Acceptance Criteria

1. THE navbar SHALL route to Overview, Live Monitor, Attack Path, Threat Story, Forensics, Response, Auto Defense, Threat Classification, Model Health, and Integrations views.
2. WHEN a navbar route is selected, THE frontend SHALL render exactly one corresponding workspace view without a provider error.
3. WHEN the Threat Classification view loads, THE frontend SHALL display all nine Canonical_Class entries and current per-class model metrics.
4. WHEN the Model Health view loads, THE frontend SHALL render API-provided precision, recall, F1, false-positive rate, sample counts, class report, and feature importances rather than fixed metric values.
5. WHEN the Auto Defense view loads, THE frontend SHALL display authoritative configuration, active blocks, audit context, and Adaptive_Policy simulation state.
6. WHEN the Integrations view loads, THE frontend SHALL display SIEM, cloud, and IoT status from `GET /api/integrations/status` or visibly labeled Demo_Data.
7. THE Landing Page SHALL present a professional product overview, platform capabilities, architecture, sandbox disclosure, and clear entry actions.
8. THE Landing Page SHALL avoid presenting illustrative confidence, latency, availability, or mitigation values as measured production guarantees.
9. THE Light_SOC_Theme SHALL style every dashboard and landing component with shared surface, typography, spacing, focus, status, and risk tokens.
10. WHILE viewport width is between 320 CSS pixels and 2560 CSS pixels, THE frontend SHALL avoid page-level horizontal overflow.
11. WHEN a keyboard user navigates interactive controls, THE frontend SHALL expose a visible focus indicator and an accessible name for each control.
12. WHERE motion reduction is requested by the operating system, THE frontend SHALL disable non-essential animation.
13. WHEN a page request is pending, THE frontend SHALL render a labeled loading state.
14. WHEN a page request returns no records, THE frontend SHALL render a labeled empty state.
15. IF a page request fails, THEN THE frontend SHALL render a recoverable error state with a retry action or an explicitly labeled offline mode.

### Requirement 10: Report Integration Fabric Status

**User Story:** As an enterprise architect, I want consistent SIEM, cloud, and IoT integration status, so that deployment and telemetry coverage are understandable.

#### Acceptance Criteria

1. WHEN `GET /api/integrations/status` succeeds, THE API_Runtime SHALL return `siem`, `cloud`, and `iot` sections matching the IntegrationStatusResponse contract.
2. WHEN SIEM connector status is returned, THE API_Runtime SHALL include connector name, vendor, status, protocol, forwarded-event count, last synchronization timestamp, and latency.
3. WHEN cloud status is returned, THE API_Runtime SHALL include provider, region, status, node count, ingest rate, and autoscale state.
4. WHEN IoT status is returned, THE API_Runtime SHALL include aggregate counts, supported protocols, and device records.
5. WHEN integration inventory is simulated, THE API_Runtime SHALL identify the integration response as Demo_Data.
6. THE Integration Service SHALL perform zero outbound SIEM, cloud, or IoT connections in the demonstration configuration.
7. WHEN the frontend normalizes integration status values, THE frontend SHALL handle the existing uppercase backend status values without losing semantic color or labels.

### Requirement 11: Verify Quality, Security, and Runtime Operation

**User Story:** As a maintainer, I want automated regression and smoke validation, so that the upgraded system can be restarted with confidence.

#### Acceptance Criteria

1. THE backend test suite SHALL include unit tests for feature extraction, canonical class mapping, risk fusion, threshold handling, IP validation, migration ordering, and secret redaction.
2. THE backend test suite SHALL include API integration tests for every existing and upgraded endpoint.
3. THE persistence integration tests SHALL verify SQLite fallback when `DATABASE_URL` is empty.
4. THE persistence integration tests SHALL verify PostgreSQL selection and TLS enforcement without using a real credential in source code.
5. THE frontend test suite SHALL include unit tests for API error normalization, detection normalization, class aggregation, notification deduplication, and defense state transitions.
6. THE frontend test suite SHALL include integration tests for provider composition, navbar route rendering, live-monitor states, model-quality data rendering, defense synchronization, and integration-status normalization.
7. THE frontend accessibility tests SHALL detect missing accessible names, invalid roles, and critical automated accessibility violations in upgraded views.
8. THE end-to-end test suite SHALL include successful, loading, empty, API-error, and offline-demo scenarios.
9. THE end-to-end test suite SHALL verify that critical detections create notifications and qualifying malicious detections create sandboxed block entries.
10. THE regression test suite SHALL verify that every pre-upgrade route remains reachable with the preserved method.
11. THE secret-scan validation SHALL inspect tracked source, generated frontend assets, API error bodies, and captured logs for credential material.
12. WHEN the backend is restarted on `127.0.0.1:8000`, THE Smoke_Validator SHALL verify `GET /api/health` and each upgraded API route.
13. WHEN the frontend is restarted on `127.0.0.1:3000`, THE Smoke_Validator SHALL verify the Landing Page and every navbar view.
14. WHEN both services are restarted, THE Smoke_Validator SHALL verify frontend-to-backend proxy communication through `/api`.
15. WHEN validation completes, THE test runner SHALL terminate finite test processes and report pass or failure without leaving a watcher active.
16. THE upgrade validation SHALL include backend tests, frontend tests, frontend lint, frontend production build, API contract tests, and the Smoke_Validator.
