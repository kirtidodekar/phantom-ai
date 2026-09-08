/**
 * Sentinel AI — centralized, modular API client.
 *
 * All backend access flows through this module so transport concerns
 * (base URL, JSON handling, error normalization, graceful offline fallback)
 * live in one place. Components import named helpers rather than sprinkling
 * `fetch('/api/...')` calls, which keeps the UI decoupled from the transport
 * and makes the app easy to repoint at another deployment.
 */

const BASE = '/api';

async function request(path, { method = 'GET', body, signal, role } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  // Privileged operations carry the operator role; the server enforces it.
  if (role) headers['X-Sentinel-Role'] = role;

  const res = await fetch(`${BASE}${path}`, {
    method,
    signal,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    // Prefer the structured error envelope the API returns.
    let message = res.statusText;
    try {
      const parsed = JSON.parse(await res.text());
      message = parsed?.error?.message || parsed?.detail || message;
    } catch {
      /* non-JSON body: keep statusText */
    }
    throw new Error(message);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

/**
 * Wrap a request so callers can opt into a fallback value when the backend
 * is unreachable. Keeps the dashboard populated instead of throwing.
 */
async function safe(promise, fallback = null) {
  try {
    return await promise;
  } catch (err) {
    if (import.meta?.env?.DEV) {
      console.warn('[sentinel-api]', err.message);
    }
    return fallback;
  }
}

export const api = {
  /* ---------- system ---------- */
  health: () => safe(request('/health'), { status: 'OFFLINE' }),

  /* ---------- incidents ---------- */
  getIncidents: () => safe(request('/incidents'), { count: 0, incidents: [] }),
  getIncident: (id) => safe(request(`/incidents/${id}`)),

  /* ---------- ML models ---------- */
  getMetrics: () => safe(request('/metrics')),
  getBaselineDiff: (id) => safe(request(`/baseline/diff/${id}`)),

  /* ---------- real-time AI detection ---------- */
  /** Run the RandomForest + IsolationForest ensemble on one telemetry detail. */
  predict: (payload) => safe(request('/detect/predict', { method: 'POST', body: payload })),
  /** Pull a batch of freshly generated + model-classified live detections. */
  getDetectionStream: (count = 6) => safe(request(`/detect/stream?count=${count}`), { detections: [] }),
  /** Catalog of supported attack classes. */
  getThreatClasses: () => safe(request('/detect/classes'), { classes: [] }),
  /** Aggregate monitoring counters for the dashboard. */
  getStatsOverview: () => safe(request('/stats/overview')),

  /* ---------- automatic IP blocking / adaptive defense ---------- */
  getBlocklist: () => safe(request('/defense/blocklist'), { entries: [], auto_block_enabled: true, threshold: 80 }),
  blockIp: (payload) => safe(request('/defense/block', { method: 'POST', body: payload })),
  unblockIp: (ip) => safe(request(`/defense/block/${encodeURIComponent(ip)}`, { method: 'DELETE' })),
  setDefenseConfig: (payload) => safe(request('/defense/config', { method: 'POST', body: payload })),
  getDefensePolicy: () => safe(request('/defense/policy')),

  /* ---------- live network telemetry ---------- */
  /** Monitor health, capability probe, counters and effective configuration. */
  getNetworkStatus: () => safe(request('/network/status')),
  /** Capture-capable interfaces detected on the monitoring host. */
  getNetworkInterfaces: () => safe(request('/network/interfaces'), { interfaces: [] }),
  /** Recent packet METADATA (never payloads). */
  getNetworkPackets: (limit = 100) => safe(request(`/network/packets?limit=${limit}`), { packets: [] }),
  /** Rolling window aggregates, baseline and deviation. */
  getNetworkStats: () => safe(request('/network/stats')),
  /** Per-IP intelligence for sources and destinations. */
  getNetworkIps: (limit = 20) => safe(request(`/network/ips?limit=${limit}`), { top_sources: [], top_destinations: [] }),
  /** Active flow table. */
  getNetworkConnections: (limit = 50) => safe(request(`/network/connections?limit=${limit}`), { connections: [] }),
  /** Network detections with MITRE mapping and correlated incident IDs. */
  getNetworkThreats: (limit = 50) => safe(request(`/network/threats?limit=${limit}`), { threats: [] }),

  /**
   * Monitoring controls are privileged. The operator role is sent explicitly and
   * enforced server-side. These intentionally do NOT swallow errors: the caller
   * must surface the precise reason (missing driver, permissions, interface).
   */
  startNetworkMonitor: (payload, role) =>
    request('/network/start', { method: 'POST', body: payload || {}, role }),
  stopNetworkMonitor: (role) => request('/network/stop', { method: 'POST', role }),
  resetNetworkMonitor: (role) => request('/network/reset', { method: 'POST', role }),

  /* ---------- endpoint + application sensors (four-layer coverage) ---------- */
  getSensorStatus: () => safe(request('/sensors/status')),
  getLayerCoverage: () => safe(request('/sensors/coverage')),
  getSensorEvents: (name, limit = 30) =>
    safe(request(`/sensors/${name}/events?limit=${limit}`), { events: [] }),
  /** Privileged; surfaces the precise failure reason instead of failing soft. */
  startSensor: (name, role) => request(`/sensors/${name}/start`, { method: 'POST', role }),
  stopSensor: (name, role) => request(`/sensors/${name}/stop`, { method: 'POST', role }),

  /* ---------- data sovereignty ---------- */
  getSovereignty: () => safe(request('/sovereignty')),

  /* ---------- enterprise integrations ---------- */
  getIntegrations: () => safe(request('/integrations/status')),

  /* ---------- telemetry + replay ---------- */
  ingest: (event) => safe(request('/telemetry/ingest', { method: 'POST', body: event })),
  startReplay: () => safe(request('/replay/start', { method: 'POST' })),
  stepReplay: () => safe(request('/replay/step', { method: 'POST' })),
  resetReplay: () => safe(request('/replay/reset', { method: 'POST' })),

  /* ---------- analyst actions ---------- */
  setCriticality: (entity_id, criticality) =>
    safe(request('/asset/criticality', { method: 'POST', body: { entity_id, criticality } })),
  submitFeedback: (payload) => safe(request('/feedback', { method: 'POST', body: payload })),
  simulateBlock: (action_type, target_id, incident_id) =>
    safe(request('/actions/simulate-block', { method: 'POST', body: { action_type, target_id, incident_id } })),
};

export default api;
