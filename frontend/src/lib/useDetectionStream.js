import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';

/**
 * Real-time detection stream — shared, transport-agnostic model layer for the
 * Live Monitor and Threat Classification consoles.
 *
 * Responsibilities kept in this module (so the pages stay presentational):
 *  - the canonical 9-class attack taxonomy + 12-feature model contract
 *  - polling `/detect/stream` on an analyst-selectable cadence
 *  - normalizing whatever field names the backend emits into one detection shape
 *  - generating representative detections when the backend is offline, so the
 *    console keeps streaming instead of rendering an empty table
 *  - deriving KPI counters, per-class aggregates and a throughput series
 */

/* ------------------------------------------------------------------ */
/* Model contract                                                      */
/* ------------------------------------------------------------------ */
export const MODEL_INFO = {
  supervised: 'RandomForest',
  unsupervised: 'IsolationForest',
  classCount: 9,
  featureCount: 12,
};

export const DETECTION_METHOD = {
  RF: 'Supervised RF',
  ISO: 'Unsupervised IsoForest',
  HYBRID: 'Hybrid RF + IsoForest',
};

/**
 * The 9 canonical classes. `iconKey` is resolved to a lucide component inside
 * the pages so this module stays JSX-free and importable from anywhere.
 */
export const ATTACK_CLASSES = [
  {
    name: 'Benign',
    iconKey: 'benign',
    mitre: null,
    layer: 'endpoint',
    severity: 'low',
    method: DETECTION_METHOD.RF,
    color: '#16805C',
    scoreRange: [2, 22],
    confidenceRange: [0.9, 0.995],
    weight: 0.5,
    description: 'Normal baseline traffic and authenticated activity that matches the learned host profile.',
  },
  {
    name: 'Brute Force',
    iconKey: 'bruteForce',
    mitre: 'T1110',
    layer: 'identity',
    severity: 'high',
    method: DETECTION_METHOD.RF,
    color: '#7C3AED',
    scoreRange: [62, 86],
    confidenceRange: [0.78, 0.97],
    weight: 0.09,
    description: 'High-volume credential guessing — elevated login failure rate against a single account or endpoint.',
  },
  {
    name: 'SQL Injection',
    iconKey: 'sqlInjection',
    mitre: 'T1190',
    layer: 'application',
    severity: 'critical',
    method: DETECTION_METHOD.RF,
    color: '#C43D4B',
    scoreRange: [80, 97],
    confidenceRange: [0.82, 0.99],
    weight: 0.07,
    description: 'Injected SQL grammar in request payloads targeting a public-facing application parameter.',
  },
  {
    name: 'XSS',
    iconKey: 'xss',
    mitre: 'T1059.007',
    layer: 'application',
    severity: 'high',
    method: DETECTION_METHOD.RF,
    color: '#B7791F',
    scoreRange: [58, 82],
    confidenceRange: [0.75, 0.96],
    weight: 0.06,
    description: 'Script payload reflected or stored through user input, aiming for in-browser execution.',
  },
  {
    name: 'DDoS',
    iconKey: 'ddos',
    mitre: 'T1498',
    layer: 'network',
    severity: 'high',
    method: DETECTION_METHOD.RF,
    color: '#0E7490',
    scoreRange: [66, 90],
    confidenceRange: [0.85, 0.99],
    weight: 0.06,
    description: 'Volumetric flood — extreme request rate with small, short-lived packets from distributed sources.',
  },
  {
    name: 'Probe / Reconnaissance',
    iconKey: 'probe',
    mitre: 'T1046',
    layer: 'network',
    severity: 'medium',
    method: DETECTION_METHOD.HYBRID,
    color: '#2563EB',
    scoreRange: [34, 56],
    confidenceRange: [0.7, 0.93],
    weight: 0.09,
    description: 'Service and port enumeration — many distinct ports touched with very short sessions.',
  },
  {
    name: 'Malware / C2 Beaconing',
    iconKey: 'malware',
    mitre: 'T1071',
    layer: 'endpoint',
    severity: 'critical',
    method: DETECTION_METHOD.ISO,
    color: '#9F1239',
    scoreRange: [84, 99],
    confidenceRange: [0.8, 0.98],
    weight: 0.05,
    description: 'Periodic outbound callbacks from a suspicious process to a rare external destination.',
  },
  {
    name: 'Phishing',
    iconKey: 'phishing',
    mitre: 'T1566',
    layer: 'identity',
    severity: 'medium',
    method: DETECTION_METHOD.HYBRID,
    color: '#DB2777',
    scoreRange: [44, 68],
    confidenceRange: [0.72, 0.94],
    weight: 0.04,
    description: 'Credential-harvesting lure — high-entropy lookalike URL delivered to an internal identity.',
  },
  {
    name: 'Unauthorized Access',
    iconKey: 'unauthorized',
    mitre: 'T1078',
    layer: 'identity',
    severity: 'critical',
    method: DETECTION_METHOD.HYBRID,
    color: '#4F46E5',
    scoreRange: [78, 95],
    confidenceRange: [0.76, 0.97],
    weight: 0.04,
    description: 'Valid but out-of-policy account use — privileged session established outside business hours.',
  },
];

export const CLASS_BY_NAME = ATTACK_CLASSES.reduce((acc, c) => {
  acc[c.name] = c;
  return acc;
}, {});

const UNKNOWN_CLASS = {
  name: 'Unknown',
  iconKey: 'benign',
  mitre: null,
  layer: 'network',
  severity: 'medium',
  method: DETECTION_METHOD.ISO,
  color: '#64748B',
  scoreRange: [40, 70],
  confidenceRange: [0.6, 0.9],
  weight: 0,
  description: 'Class reported by the model that is outside the published taxonomy.',
};

export function classMeta(name) {
  return CLASS_BY_NAME[name] || { ...UNKNOWN_CLASS, name: name || 'Unknown' };
}

/** Pill tone per telemetry layer — identity violet, endpoint blue, process/app amber, network rose. */
export const LAYER_TONE = {
  identity: 'violet',
  endpoint: 'primary',
  process: 'warning',
  application: 'warning',
  network: 'danger',
};

export const PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP'];

/** The 12 model features, with UI metadata for the inference console. */
export const FEATURE_SPECS = [
  { key: 'packet_size', label: 'Packet size', kind: 'range', min: 40, max: 4000, step: 10, def: 520, unit: 'B', hint: 'Mean payload size on the flow' },
  { key: 'request_rate', label: 'Request rate', kind: 'range', min: 0.1, max: 1000, step: 0.1, def: 3.2, unit: '/s', hint: 'Requests per second' },
  { key: 'session_duration', label: 'Session duration', kind: 'range', min: 0.05, max: 600, step: 0.05, def: 28, unit: 's', hint: 'Flow lifetime' },
  { key: 'payload_pattern_score', label: 'Payload pattern score', kind: 'range', min: 0, max: 1, step: 0.01, def: 0.08, unit: '', hint: 'SQL / script signature density' },
  { key: 'login_failure_rate', label: 'Login failure rate', kind: 'range', min: 0, max: 1, step: 0.01, def: 0.04, unit: '', hint: 'Failed auths / attempts' },
  { key: 'distinct_ports_touched', label: 'Distinct ports touched', kind: 'range', min: 1, max: 512, step: 1, def: 3, unit: '', hint: 'Unique destination ports' },
  { key: 'url_entropy', label: 'URL entropy', kind: 'range', min: 0, max: 8, step: 0.05, def: 2.6, unit: 'bits', hint: 'Shannon entropy of the request URI' },
  { key: 'outbound_bytes_ratio', label: 'Outbound bytes ratio', kind: 'range', min: 0, max: 1, step: 0.01, def: 0.22, unit: '', hint: 'Egress share of total transfer' },
  { key: 'is_suspicious_process', label: 'Suspicious process', kind: 'toggle', def: false, hint: 'Abnormal parent-child process tree' },
  { key: 'privilege_level', label: 'Privileged session', kind: 'toggle', def: false, hint: 'admin / SYSTEM / root token' },
  { key: 'off_hours_access', label: 'Off-hours access', kind: 'toggle', def: false, hint: 'Outside the entity business-hours baseline' },
  { key: 'protocol', label: 'Protocol', kind: 'select', options: PROTOCOLS, def: 'TCP', hint: 'L4 / L7 protocol of the flow' },
];

export const FEATURE_DEFAULTS = FEATURE_SPECS.reduce((acc, f) => {
  acc[f.key] = f.def;
  return acc;
}, {});

/* ------------------------------------------------------------------ */
/* Small numeric helpers                                               */
/* ------------------------------------------------------------------ */
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const rand = (a, b) => a + Math.random() * (b - a);
const randInt = (a, b) => Math.round(rand(a, b));

function num(value, fallback) {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : fallback;
}

/** Read the first present numeric field from a loosely-typed API payload. */
export function firstNumber(obj, keys, fallback = null) {
  if (!obj) return fallback;
  for (const k of keys) {
    const n = num(obj[k], null);
    if (n !== null) return n;
  }
  return fallback;
}

/** Confidence values arrive as either 0..1 or 0..100 depending on endpoint. */
function toUnit(value, fallback = 0) {
  const n = num(value, null);
  if (n === null) return fallback;
  return n > 1 ? clamp(n / 100, 0, 1) : clamp(n, 0, 1);
}

export function hhmmss(ts) {
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
}

/* ------------------------------------------------------------------ */
/* Representative offline generator                                    */
/* ------------------------------------------------------------------ */
const INTERNAL_IPS = ['10.4.11.28', '10.4.11.63', '10.4.22.9', '172.16.8.41', '172.16.8.77', '10.8.3.150'];
const EXTERNAL_IPS = ['198.51.100.99', '198.51.100.42', '203.0.113.44', '203.0.113.7', '45.83.192.7', '185.220.101.34', '91.219.238.12', '104.28.199.66'];

const CUMULATIVE = (() => {
  let acc = 0;
  return ATTACK_CLASSES.map((c) => {
    acc += c.weight;
    return { name: c.name, upTo: acc };
  });
})();
const WEIGHT_TOTAL = CUMULATIVE[CUMULATIVE.length - 1].upTo;

function pickClass() {
  const r = Math.random() * WEIGHT_TOTAL;
  const hit = CUMULATIVE.find((c) => r <= c.upTo);
  return classMeta(hit ? hit.name : 'Benign');
}

let seq = 0;
const nextId = () => `sim-${Date.now().toString(36)}-${(seq += 1).toString(36)}`;

/** Build one representative detection for a class, mirroring the live shape. */
export function simulateDetection(ts = Date.now(), forced = null) {
  const meta = forced ? classMeta(forced) : pickClass();
  const benign = meta.name === 'Benign';
  const score = Math.round(rand(meta.scoreRange[0], meta.scoreRange[1]));
  const confidence = Number(rand(meta.confidenceRange[0], meta.confidenceRange[1]).toFixed(4));
  return {
    id: nextId(),
    ts,
    time: hhmmss(ts),
    ip: benign ? INTERNAL_IPS[randInt(0, INTERNAL_IPS.length - 1)] : EXTERNAL_IPS[randInt(0, EXTERNAL_IPS.length - 1)],
    attackType: meta.name,
    layer: meta.layer,
    mitre: meta.mitre,
    method: meta.method,
    confidence,
    score,
    verdict: benign ? 'benign' : 'malicious',
    anomalyScore: Number(clamp(benign ? rand(0, 0.2) : rand(0.35, 0.98), 0, 1).toFixed(3)),
    latencyMs: Number(rand(4.5, 18).toFixed(1)),
    simulated: true,
  };
}

/* ------------------------------------------------------------------ */
/* Live payload normalizer                                             */
/* ------------------------------------------------------------------ */
function normalizeDetection(raw, idx) {
  if (!raw || typeof raw !== 'object') return null;
  const name =
    raw.attackType || raw.attack_type || raw.predicted_class || raw.label || raw.class || raw.class_name || 'Benign';
  const meta = classMeta(name);
  const benign = meta.name === 'Benign';
  const confidence = toUnit(raw.confidence ?? raw.probability ?? raw.model_confidence, benign ? 0.95 : 0.85);
  const score = Math.round(
    clamp(firstNumber(raw, ['score', 'risk_score', 'threat_score', 'severity_score'], Math.round(confidence * 100)), 0, 100)
  );
  const ts = num(raw.ts, null) ?? (raw.timestamp ? Date.parse(raw.timestamp) : Date.now()) ?? Date.now();
  const safeTs = Number.isFinite(ts) ? ts : Date.now();
  return {
    id: String(raw.id || raw.detection_id || raw.event_id || `live-${safeTs}-${idx}`),
    ts: safeTs,
    time: raw.time || hhmmss(safeTs),
    ip: raw.ip || raw.source_ip || raw.src_ip || raw.entity || '0.0.0.0',
    attackType: meta.name,
    layer: (raw.layer || meta.layer || 'network').toLowerCase(),
    mitre: raw.mitre || raw.mitre_id || raw.technique || meta.mitre,
    method: raw.method || raw.detection_method || meta.method,
    confidence,
    score,
    verdict: raw.verdict || (benign ? 'benign' : 'malicious'),
    anomalyScore: toUnit(raw.anomaly_score ?? raw.anomalyScore, benign ? 0.05 : 0.5),
    latencyMs: Number(firstNumber(raw, ['latency_ms', 'latencyMs', 'inference_ms'], 9.5)),
    simulated: false,
  };
}

function normalizeBatch(payload) {
  const list = Array.isArray(payload) ? payload : payload?.detections || payload?.events || payload?.results || [];
  if (!Array.isArray(list)) return [];
  return list.map(normalizeDetection).filter(Boolean);
}

/* ------------------------------------------------------------------ */
/* Aggregation                                                         */
/* ------------------------------------------------------------------ */
const MAX_FEED = 40;
const MAX_SERIES = 36;

/** Per-class counts, share and mean confidence over the current feed window. */
export function aggregateByClass(detections) {
  const buckets = new Map();
  detections.forEach((d) => {
    const b = buckets.get(d.attackType) || { name: d.attackType, count: 0, confSum: 0, scoreSum: 0 };
    b.count += 1;
    b.confSum += d.confidence;
    b.scoreSum += d.score;
    buckets.set(d.attackType, b);
  });
  const total = detections.length || 1;
  return Array.from(buckets.values())
    .map((b) => ({
      name: b.name,
      count: b.count,
      share: (b.count / total) * 100,
      avgConfidence: b.confSum / b.count,
      avgScore: b.scoreSum / b.count,
      color: classMeta(b.name).color,
    }))
    .sort((a, b) => b.count - a.count);
}

function seedFeed(count, spacingMs) {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) => simulateDetection(now - i * spacingMs)).sort((a, b) => b.ts - a.ts);
}

function seedSeries(count, spacingMs, batchSize) {
  const now = Date.now();
  const perSec = batchSize / (spacingMs / 1000);
  return Array.from({ length: count }, (_, i) => {
    const ts = now - (count - 1 - i) * spacingMs;
    const eps = Number(clamp(perSec * rand(0.6, 1.4), 0.1, 9999).toFixed(2));
    return { ts, t: hhmmss(ts), eps, threats: randInt(0, Math.max(1, Math.round(batchSize * 0.45))) };
  });
}

/* ------------------------------------------------------------------ */
/* Hook                                                                */
/* ------------------------------------------------------------------ */
/**
 * useDetectionStream — owns the polling loop and all derived monitoring state.
 *
 * @param {object}   options
 * @param {boolean}  options.paused      halt polling without losing the feed
 * @param {number}   options.intervalMs  ingest cadence
 * @param {number}   options.batchSize   detections requested per tick
 * @param {Function} options.onBatch     called with each new batch (ref-stable)
 */
export function useDetectionStream({ paused = false, intervalMs = 1500, batchSize = 4, onBatch } = {}) {
  const [detections, setDetections] = useState(() => seedFeed(14, 1500));
  const [series, setSeries] = useState(() => seedSeries(18, 1500, 4));
  const [source, setSource] = useState('simulated');
  const [totals, setTotals] = useState(() => ({ events: 0, threats: 0, confSum: 0, latSum: 0, samples: 0 }));

  const onBatchRef = useRef(onBatch);
  const primedRef = useRef(false);

  useEffect(() => {
    onBatchRef.current = onBatch;
  }, [onBatch]);

  useEffect(() => {
    if (paused) return undefined;
    let cancelled = false;

    const tick = async () => {
      const payload = await api.getDetectionStream(batchSize);
      if (cancelled) return;

      const live = normalizeBatch(payload);
      const batch = live.length > 0 ? live : Array.from({ length: batchSize }, () => simulateDetection());
      const threats = batch.filter((d) => d.verdict !== 'benign').length;
      const eps = Number((batch.length / (intervalMs / 1000)).toFixed(2));
      const stamp = Date.now();

      setSource(live.length > 0 ? 'live' : 'simulated');
      setDetections((prev) => [...batch].sort((a, b) => b.ts - a.ts).concat(prev).slice(0, MAX_FEED));
      setSeries((prev) => [...prev, { ts: stamp, t: hhmmss(stamp), eps, threats }].slice(-MAX_SERIES));
      setTotals((prev) => ({
        events: prev.events + batch.length,
        threats: prev.threats + threats,
        confSum: prev.confSum + batch.reduce((s, d) => s + d.confidence, 0),
        latSum: prev.latSum + batch.reduce((s, d) => s + d.latencyMs, 0),
        samples: prev.samples + batch.length,
      }));

      onBatchRef.current?.(batch);
    };

    const id = setInterval(tick, intervalMs);
    if (!primedRef.current) {
      primedRef.current = true;
      tick();
    }

    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [paused, intervalMs, batchSize]);

  const clear = useCallback(() => {
    setDetections([]);
    setSeries([]);
    setTotals({ events: 0, threats: 0, confSum: 0, latSum: 0, samples: 0 });
  }, []);

  const stats = useMemo(() => {
    const feed = detections;
    const threatsInWindow = feed.filter((d) => d.verdict !== 'benign');
    const last = series[series.length - 1];
    return {
      eps: last ? last.eps : 0,
      epsSeries: series.map((p) => p.eps),
      sessionEvents: totals.events,
      sessionThreats: totals.threats,
      threatsInWindow: threatsInWindow.length,
      avgConfidence: totals.samples ? (totals.confSum / totals.samples) * 100 : 0,
      avgLatency: totals.samples ? totals.latSum / totals.samples : 0,
      criticalCount: feed.filter((d) => d.score >= 80).length,
    };
  }, [detections, series, totals]);

  const byClass = useMemo(() => aggregateByClass(detections), [detections]);

  return { detections, series, stats, byClass, source, clear };
}

/* ------------------------------------------------------------------ */
/* Offline heuristic inference                                         */
/* ------------------------------------------------------------------ */
const SEVERITY_BASE = { low: 12, medium: 48, high: 72, critical: 90 };

/**
 * localPredict — deterministic feature-rule scorer used when `/detect/predict`
 * is unreachable. Mirrors the ensemble output contract so the console renders
 * identically online and offline (results are flagged `simulated: true`).
 */
export function localPredict(f) {
  const proto = String(f.protocol || 'TCP').toUpperCase();
  const http = proto === 'HTTP';
  const payload = num(f.payload_pattern_score, 0);
  const rate = num(f.request_rate, 1);
  const size = num(f.packet_size, 500);
  const dur = num(f.session_duration, 20);
  const fails = num(f.login_failure_rate, 0);
  const ports = num(f.distinct_ports_touched, 1);
  const entropy = num(f.url_entropy, 2.5);
  const egress = num(f.outbound_bytes_ratio, 0.2);
  const suspicious = f.is_suspicious_process ? 1 : 0;
  const priv = f.privilege_level ? 1 : 0;
  const offHours = f.off_hours_access ? 1 : 0;

  const affinity = {
    Benign: 1.1 + (payload < 0.2 ? 0.9 : 0) + (fails < 0.2 ? 0.6 : 0) + (rate < 12 ? 0.7 : 0) + (ports < 8 ? 0.5 : 0) - suspicious * 0.8 - offHours * 0.3,
    'Brute Force': fails * 3.4 + (rate > 12 ? 1.3 : 0) + (dur < 12 ? 0.6 : 0) + (http ? 0.5 : 0) - payload * 0.6,
    'SQL Injection': payload * 3.1 + (size > 900 ? 1.2 : 0) + (http ? 0.9 : 0) + priv * 0.4 + (entropy > 3.4 ? 0.4 : 0),
    XSS: payload * 2.5 + (size > 600 && size <= 1400 ? 0.9 : 0) + (http ? 0.8 : 0) + (entropy > 3 ? 0.5 : 0) - priv * 0.3,
    DDoS: (rate > 120 ? rate / 220 : 0) + (size < 260 ? 1.4 : 0) + (dur < 3 ? 1.1 : 0) + (proto === 'ICMP' || proto === 'UDP' ? 0.7 : 0),
    'Probe / Reconnaissance': (ports > 12 ? ports / 60 : 0) + (dur < 5 ? 1.0 : 0) + (size < 400 ? 0.5 : 0) + (rate > 6 ? 0.4 : 0),
    'Malware / C2 Beaconing': suspicious * 2.2 + egress * 1.9 + (dur > 90 ? 0.9 : 0) + (rate > 0.2 && rate < 4 ? 0.8 : 0) + (entropy > 4 ? 0.6 : 0),
    Phishing: (entropy > 4 ? entropy / 4 : 0) + (http ? 0.8 : 0) + payload * 0.7 + (size > 400 ? 0.3 : 0),
    'Unauthorized Access': priv * 1.7 + offHours * 1.8 + (fails > 0.25 && fails < 0.8 ? 0.7 : 0) + suspicious * 0.5 + (dur > 60 ? 0.4 : 0),
  };

  const exp = {};
  let sum = 0;
  Object.entries(affinity).forEach(([k, v]) => {
    const e = Math.exp(clamp(v, -6, 6) * 1.15);
    exp[k] = e;
    sum += e;
  });

  const probabilities = Object.entries(exp)
    .map(([name, e]) => ({ name, probability: e / sum }))
    .sort((a, b) => b.probability - a.probability);

  const top = probabilities[0];
  const meta = classMeta(top.name);
  const benign = meta.name === 'Benign';
  const anomalyScore = clamp(
    payload * 0.3 + Math.min(rate / 400, 1) * 0.25 + egress * 0.15 + suspicious * 0.15 + Math.min(ports / 120, 1) * 0.1 + offHours * 0.05,
    0,
    1
  );
  const score = benign
    ? Math.round(clamp(SEVERITY_BASE.low * top.probability + anomalyScore * 22, 0, 38))
    : Math.round(clamp(SEVERITY_BASE[meta.severity] * (0.65 + top.probability * 0.35) + anomalyScore * 10, 0, 100));

  return {
    label: meta.name,
    confidence: top.probability,
    verdict: benign ? 'benign' : 'malicious',
    score,
    anomalyScore,
    isAnomaly: anomalyScore > 0.55,
    recommendedAction: recommendAction(score, benign),
    probabilities,
    method: meta.method,
    mitre: meta.mitre,
    layer: meta.layer,
    simulated: true,
  };
}

export function recommendAction(score, benign) {
  if (benign && score < 40) return 'No action — continue baseline monitoring';
  if (score >= 80) return 'Auto-block source IP and isolate the session';
  if (score >= 60) return 'Throttle source, open incident, notify on-call analyst';
  if (score >= 40) return 'Keep under watch and enrich with threat intelligence';
  return 'Log for baseline drift review';
}

/** Normalize a `/detect/predict` response into the same shape as localPredict. */
export function normalizePrediction(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = raw.label || raw.predicted_class || raw.attack_type || raw.class || raw.class_name;
  if (!name) return null;
  const meta = classMeta(name);
  const benign = meta.name === 'Benign';
  const confidence = toUnit(raw.confidence ?? raw.probability, 0.8);
  const score = Math.round(
    clamp(firstNumber(raw, ['score', 'risk_score', 'threat_score'], Math.round(confidence * 100)), 0, 100)
  );
  const anomalyScore = toUnit(raw.anomaly_score ?? raw.anomalyScore, 0);

  const rawProbs = raw.class_probabilities || raw.probabilities || raw.class_probs;
  let probabilities = [];
  if (Array.isArray(rawProbs)) {
    probabilities = rawProbs
      .map((p, i) =>
        typeof p === 'number'
          ? { name: ATTACK_CLASSES[i]?.name || `Class ${i}`, probability: toUnit(p, 0) }
          : { name: p.name || p.label || p.class || `Class ${i}`, probability: toUnit(p.probability ?? p.value ?? p.prob, 0) }
      )
      .sort((a, b) => b.probability - a.probability);
  } else if (rawProbs && typeof rawProbs === 'object') {
    probabilities = Object.entries(rawProbs)
      .map(([k, v]) => ({ name: k, probability: toUnit(v, 0) }))
      .sort((a, b) => b.probability - a.probability);
  }

  return {
    label: meta.name,
    confidence,
    verdict: raw.verdict || (benign ? 'benign' : 'malicious'),
    score,
    anomalyScore,
    isAnomaly: typeof raw.is_anomaly === 'boolean' ? raw.is_anomaly : anomalyScore > 0.55,
    recommendedAction: raw.recommended_action || raw.action || recommendAction(score, benign),
    probabilities,
    method: raw.method || meta.method,
    mitre: raw.mitre || meta.mitre,
    layer: raw.layer || meta.layer,
    simulated: false,
  };
}

/* ------------------------------------------------------------------ */
/* Metrics helpers (shared by the classification page)                 */
/* ------------------------------------------------------------------ */
const REPORT_SUMMARY_KEYS = ['accuracy', 'macro avg', 'weighted avg', 'micro avg', 'samples avg'];

/**
 * splitClassReport — pull per-class rows out of a scikit-learn
 * classification_report(output_dict=True), keeping the aggregate rows
 * (accuracy / macro avg / weighted avg) separate.
 */
export function splitClassReport(report) {
  if (!report || typeof report !== 'object') return { rows: [], summary: [] };
  const rows = [];
  const summary = [];
  Object.entries(report).forEach(([key, value]) => {
    const isSummary = REPORT_SUMMARY_KEYS.includes(key.toLowerCase());
    if (typeof value === 'number') {
      summary.push({ name: key, value });
      return;
    }
    if (!value || typeof value !== 'object') return;
    const entry = {
      name: key,
      precision: toUnit(value.precision, 0),
      recall: toUnit(value.recall, 0),
      f1: toUnit(value['f1-score'] ?? value.f1_score ?? value.f1, 0),
      support: num(value.support, 0),
    };
    if (isSummary) summary.push({ name: key, ...entry });
    else rows.push(entry);
  });
  return { rows: rows.sort((a, b) => b.support - a.support), summary };
}

/** Sorted [{ name, value, share }] from a `feature_importances` map. */
export function rankFeatureImportances(map) {
  if (!map || typeof map !== 'object') return [];
  const entries = Object.entries(map)
    .map(([name, value]) => ({ name, value: num(value, 0) }))
    .filter((e) => e.value >= 0)
    .sort((a, b) => b.value - a.value);
  const top = entries[0]?.value || 1;
  return entries.map((e) => ({ ...e, share: (e.value / top) * 100 }));
}

/** Deterministic stand-in importances for the 12 features when offline. */
export const FALLBACK_IMPORTANCES = {
  payload_pattern_score: 0.181,
  request_rate: 0.152,
  login_failure_rate: 0.134,
  packet_size: 0.106,
  outbound_bytes_ratio: 0.089,
  distinct_ports_touched: 0.081,
  url_entropy: 0.072,
  session_duration: 0.064,
  is_suspicious_process: 0.048,
  privilege_level: 0.037,
  off_hours_access: 0.021,
  protocol_type: 0.015,
};

/** Deterministic stand-in class report (9 classes) when `/metrics` is offline. */
export const FALLBACK_CLASS_REPORT = {
  Benign: { precision: 0.982, recall: 0.991, 'f1-score': 0.986, support: 1520 },
  'Brute Force': { precision: 0.951, recall: 0.936, 'f1-score': 0.943, support: 184 },
  'SQL Injection': { precision: 0.944, recall: 0.928, 'f1-score': 0.936, support: 176 },
  XSS: { precision: 0.917, recall: 0.898, 'f1-score': 0.907, support: 168 },
  DDoS: { precision: 0.973, recall: 0.982, 'f1-score': 0.977, support: 192 },
  'Probe / Reconnaissance': { precision: 0.886, recall: 0.861, 'f1-score': 0.873, support: 205 },
  'Malware / C2 Beaconing': { precision: 0.902, recall: 0.874, 'f1-score': 0.888, support: 141 },
  Phishing: { precision: 0.869, recall: 0.842, 'f1-score': 0.855, support: 128 },
  'Unauthorized Access': { precision: 0.913, recall: 0.889, 'f1-score': 0.901, support: 136 },
  accuracy: 0.951,
  'macro avg': { precision: 0.926, recall: 0.911, 'f1-score': 0.918, support: 2850 },
  'weighted avg': { precision: 0.952, recall: 0.951, 'f1-score': 0.951, support: 2850 },
};

export default useDetectionStream;
