import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import {
  Activity,
  Ban,
  Brain,
  Cpu,
  Database,
  DoorOpen,
  Gauge,
  KeyRound,
  Pause,
  Play,
  Radar,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Timer,
  Trash2,
  Waves,
  Bug,
  Code2,
  Fish,
} from 'lucide-react';
import { api } from '../lib/api';
import { cn, severityOf, severityStyle } from '../lib/cn';
import { Card, CardHeader, Donut, LiveDot, Meter, Pill, RiskBadge, StatCard, Toggle } from './ui/Primitives';
import { useNotifications } from '../lib/notifications';
import { useDefense } from '../lib/defense';
import {
  ATTACK_CLASSES,
  FEATURE_DEFAULTS,
  FEATURE_SPECS,
  LAYER_TONE,
  MODEL_INFO,
  classMeta,
  firstNumber,
  localPredict,
  normalizePrediction,
  useDetectionStream,
} from '../lib/useDetectionStream';

/* Ingest cadences offered to the analyst. */
const RATES = [
  { id: 'slow', label: 'Slow', ms: 3000, hint: '3s' },
  { id: 'normal', label: 'Normal', ms: 1500, hint: '1.5s' },
  { id: 'fast', label: 'Fast', ms: 700, hint: '700ms' },
];

const CLASS_ICONS = {
  benign: ShieldCheck,
  bruteForce: KeyRound,
  sqlInjection: Database,
  xss: Code2,
  ddos: Waves,
  probe: Radar,
  malware: Bug,
  phishing: Fish,
  unauthorized: DoorOpen,
};

const NOTIFY_COOLDOWN_MS = 7000;

function rowTint(score, benign) {
  if (benign) return 'bg-white';
  const sev = severityOf(score);
  if (sev === 'critical') return 'bg-rose-50';
  if (sev === 'high') return 'bg-amber-50';
  if (sev === 'medium') return 'bg-yellow-50/70';
  return 'bg-white';
}

function meterTone(score) {
  const sev = severityOf(score);
  if (sev === 'critical') return 'danger';
  if (sev === 'high') return 'warning';
  if (sev === 'medium') return 'warning';
  return 'success';
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0].payload;
  return (
    <div className="rounded-xl border border-slate-300 bg-white p-3 shadow-md text-xs space-y-1">
      <p className="font-bold text-blue-700 font-mono">{label}</p>
      <p className="text-slate-800">
        Ingest rate: <strong className="font-mono text-sm text-slate-900">{point.eps}/s</strong>
      </p>
      <p className="text-slate-600">
        Threats in window: <span className="font-mono font-bold text-rose-700">{point.threats}</span>
      </p>
    </div>
  );
}

export default function LiveMonitorPage({ onOpenEntity }) {
  const { notify } = useNotifications();
  // `blocked` drives the per-row action cell (it also carries auto vs manual mode),
  // so the shared blocklist stays the single source of truth across pages.
  const { autoBlock, threshold, maybeAutoBlock, blocked, blockIp } = useDefense();

  const [paused, setPaused] = useState(false);
  const [rateId, setRateId] = useState('normal');
  const [query, setQuery] = useState('');
  const [classFilter, setClassFilter] = useState('ALL');
  const [threatsOnly, setThreatsOnly] = useState(false);
  const [overview, setOverview] = useState(null);

  const rate = RATES.find((r) => r.id === rateId) || RATES[1];
  const lastNotifyRef = useRef(0);

  /* ---------- monitoring counters from the backend (soft-failing) ---------- */
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const res = await api.getStatsOverview();
      if (alive) setOverview(res);
    };
    load();
    const id = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  /* ---------- react to every new batch of detections ---------- */
  const handleBatch = useCallback(
    (batch) => {
      batch.forEach((d) => {
        if (d.verdict === 'benign') return;
        maybeAutoBlock(d);
        if (d.score >= 80 && Date.now() - lastNotifyRef.current > NOTIFY_COOLDOWN_MS) {
          lastNotifyRef.current = Date.now();
          notify({
            severity: 'critical',
            title: `CRITICAL — ${d.attackType}`,
            message: `${d.ip} · risk ${d.score} · confidence ${(d.confidence * 100).toFixed(1)}%${d.mitre ? ` · ${d.mitre}` : ''}`,
          });
        }
      });
    },
    [maybeAutoBlock, notify]
  );

  const { detections, series, stats, byClass, source, clear } = useDetectionStream({
    paused,
    intervalMs: rate.ms,
    batchSize: 4,
    onBatch: handleBatch,
  });

  /* ---------- KPI values: backend first, live stream as the fallback ---------- */
  const threatsDetected = firstNumber(overview, ['threats_detected', 'total_threats', 'threats', 'malicious_events'], null);
  const overviewConfidence = firstNumber(overview, ['avg_confidence', 'mean_confidence', 'model_confidence'], null);
  const overviewLatency = firstNumber(overview, ['avg_latency_ms', 'inference_latency_ms', 'latency_ms'], null);
  const autoBlockedCount = blocked.filter((b) => b.mode === 'auto').length;
  const avgConfidence = overviewConfidence !== null
    ? (overviewConfidence > 1 ? overviewConfidence : overviewConfidence * 100)
    : stats.avgConfidence;
  const avgLatency = overviewLatency !== null ? overviewLatency : stats.avgLatency;

  const blockedByIp = useMemo(() => {
    const map = new Map();
    blocked.forEach((b) => map.set(b.ip, b));
    return map;
  }, [blocked]);

  /* ---------- feed filtering ---------- */
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return detections.filter((d) => {
      if (threatsOnly && d.verdict === 'benign') return false;
      if (classFilter !== 'ALL' && d.attackType !== classFilter) return false;
      if (!q) return true;
      return d.ip.toLowerCase().includes(q) || d.attackType.toLowerCase().includes(q);
    });
  }, [detections, query, classFilter, threatsOnly]);

  const donutData = byClass.map((c) => ({ name: c.name, value: c.count, color: c.color }));

  const openEntity = (d) => {
    if (!onOpenEntity) return;
    onOpenEntity({
      id: `IP-${d.ip}`,
      label: d.ip,
      type: 'destination',
      risk_score: d.score,
      status: d.score >= 80 ? 'compromised' : d.verdict === 'benign' ? 'normal' : 'suspicious',
      layer: d.layer,
    });
  };

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------------------------------------------------------- */}
      {/* Header + stream controls                                         */}
      {/* ---------------------------------------------------------------- */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 shrink-0">
            <Activity className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-base font-bold text-slate-900">Real-Time Threat Detection</h1>
              <LiveDot tone={paused ? 'warning' : 'success'} label={paused ? 'PAUSED' : 'STREAMING'} />
              <Pill tone={source === 'live' ? 'success' : 'neutral'}>
                {source === 'live' ? 'BACKEND STREAM' : 'SIMULATED STREAM'}
              </Pill>
            </div>
            <p className="text-xs text-slate-600 mt-1">
              Every event is scored by the supervised classifier and the anomaly detector, then fused into a risk score.
            </p>
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <Pill tone="primary">
                <Brain className="w-3 h-3" /> {MODEL_INFO.supervised} + {MODEL_INFO.unsupervised}
              </Pill>
              <Pill tone="neutral">
                {MODEL_INFO.classCount} classes / {MODEL_INFO.featureCount} features
              </Pill>
              <Pill tone={autoBlock ? 'danger' : 'neutral'}>
                AUTO-BLOCK {autoBlock ? `ON @ ${threshold}` : 'OFF'}
              </Pill>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            aria-label={paused ? 'Resume detection stream' : 'Pause detection stream'}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition',
              paused
                ? 'border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
            )}
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? 'Resume' : 'Pause'}
          </button>

          <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5" role="group" aria-label="Ingest rate">
            {RATES.map((r) => (
              <button
                key={r.id}
                type="button"
                onClick={() => setRateId(r.id)}
                aria-pressed={rateId === r.id}
                className={cn(
                  'rounded-md px-2.5 py-1 text-[11px] font-mono font-semibold transition',
                  rateId === r.id ? 'bg-blue-600 text-white' : 'text-slate-600 hover:bg-slate-50'
                )}
              >
                {r.label} <span className="opacity-70">{r.hint}</span>
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={clear}
            aria-label="Clear detection feed"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear feed
          </button>
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* KPI row                                                          */}
      {/* ---------------------------------------------------------------- */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-5">
        <StatCard
          icon={Activity}
          label="Events / sec"
          value={stats.eps.toFixed(2)}
          tone="primary"
          spark={stats.epsSeries}
          footer={paused ? 'Stream paused' : `Sampled every ${rate.hint}`}
        />
        <StatCard
          icon={ShieldAlert}
          label="Threats detected"
          value={threatsDetected !== null ? threatsDetected : stats.sessionThreats}
          tone="danger"
          delta={{ dir: 'up', value: `${stats.threatsInWindow} in window` }}
          footer={threatsDetected !== null ? 'Backend counter' : 'This session'}
        />
        <StatCard
          icon={Ban}
          label="Auto-blocked IPs"
          value={autoBlockedCount}
          tone="warning"
          footer={`${blocked.length} total on blocklist`}
        />
        <StatCard
          icon={Gauge}
          label="Avg model confidence"
          value={avgConfidence.toFixed(1)}
          unit="%"
          tone="success"
          footer="RandomForest top-class probability"
        />
        <StatCard
          icon={Timer}
          label="Avg inference latency"
          value={avgLatency.toFixed(1)}
          unit="ms"
          tone="violet"
          footer="Ensemble scoring per event"
        />
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Throughput                                                       */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader
          icon={Waves}
          title="Ingest Throughput & Threat Density"
          subtitle="Events scored per second, with the count of malicious verdicts per sampling window."
          right={
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-600">
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-blue-600" /> events/s
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-rose-600" /> threats
              </span>
            </div>
          }
        />
        <div className="mt-4 h-[210px] w-full">
          {series.length === 0 ? (
            <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-slate-200 text-xs text-slate-500">
              Feed cleared — waiting for the next sampling window.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={series} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="epsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563eb" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.85} />
                <XAxis dataKey="t" stroke="#64748b" fontSize={10} tickLine={false} minTickGap={28} />
                <YAxis yAxisId="left" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis yAxisId="right" orientation="right" stroke="#94a3b8" fontSize={10} tickLine={false} width={28} />
                <Tooltip content={<ChartTooltip />} />
                <Bar yAxisId="right" dataKey="threats" fill="#C43D4B" barSize={7} radius={[2, 2, 0, 0]} opacity={0.75} />
                <Area
                  yAxisId="left"
                  type="monotone"
                  dataKey="eps"
                  stroke="#2563eb"
                  strokeWidth={2.25}
                  fill="url(#epsGradient)"
                  dot={false}
                  isAnimationActive={false}
                />
              </ComposedChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* Live detection feed                                              */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader
          icon={Radar}
          title="Live Detection Feed"
          subtitle={`Most recent ${detections.length} classified events — newest first.`}
          right={
            <span className="text-[11px] font-mono text-slate-500">
              {visible.length}/{detections.length} shown
            </span>
          }
        />

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search source IP or predicted class"
              aria-label="Search detections by source IP or predicted class"
              className="w-full rounded-lg border border-slate-200 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-800 placeholder:text-slate-400 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/25"
            />
          </div>
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            aria-label="Filter by predicted class"
            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/25"
          >
            <option value="ALL">All classes</option>
            {ATTACK_CLASSES.map((c) => (
              <option key={c.name} value={c.name}>
                {c.name}
              </option>
            ))}
          </select>
          <div className="min-w-[150px]">
            <Toggle checked={threatsOnly} onChange={setThreatsOnly} label="Threats only" tone="danger" />
          </div>
        </div>

        <div className="mt-3 max-h-[420px] overflow-y-auto rounded-lg border border-slate-200">
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-slate-50">
              <tr className="border-b border-slate-200">
                {['Time', 'Source IP', 'Layer', 'Predicted class', 'Confidence', 'Risk', 'MITRE', 'Action'].map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="whitespace-nowrap px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-10 text-center text-xs text-slate-500">
                    No detections match the current filters.
                  </td>
                </tr>
              )}
              {visible.map((d) => {
                const benign = d.verdict === 'benign';
                const entry = blockedByIp.get(d.ip);
                const sev = severityStyle(d.score);
                return (
                  <tr key={d.id} className={cn('feed-row-enter border-b border-slate-100 last:border-b-0', rowTint(d.score, benign))}>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-slate-500">{d.time}</td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <button
                        type="button"
                        onClick={() => openEntity(d)}
                        className="font-mono text-[11px] font-semibold text-slate-900 underline-offset-2 hover:text-blue-700 hover:underline"
                        aria-label={`Open entity details for ${d.ip}`}
                      >
                        {d.ip}
                      </button>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <Pill tone={LAYER_TONE[d.layer] || 'neutral'}>{d.layer}</Pill>
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn('text-xs font-semibold', benign ? 'text-slate-700' : sev.text)}>{d.attackType}</span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <Meter value={d.confidence * 100} tone={benign ? 'success' : meterTone(d.score)} height={6} className="w-16" />
                        <span className="font-mono text-[11px] text-slate-600">{(d.confidence * 100).toFixed(1)}%</span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <RiskBadge score={d.score} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-slate-500">{d.mitre || '—'}</td>
                    <td className="whitespace-nowrap px-3 py-2">
                      {entry ? (
                        <Pill tone="danger">{entry.mode === 'auto' ? 'AUTO-BLOCKED' : 'BLOCKED'}</Pill>
                      ) : benign ? (
                        <Pill tone="neutral">MONITORED</Pill>
                      ) : (
                        <button
                          type="button"
                          onClick={() =>
                            blockIp({
                              ip: d.ip,
                              attackType: d.attackType,
                              score: d.score,
                              reason: `Analyst block from live feed (${d.attackType})`,
                              mode: 'manual',
                            })
                          }
                          className="inline-flex items-center gap-1 rounded-md border border-rose-200 bg-white px-2 py-0.5 text-[10px] font-mono font-bold text-rose-700 transition hover:bg-rose-50"
                          aria-label={`Block source IP ${d.ip}`}
                        >
                          <Ban className="w-3 h-3" /> BLOCK
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* Classification mix                                               */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader
          icon={Sparkles}
          title="Threat Classification Mix"
          subtitle="Distribution of predicted classes across the current feed window."
        />
        <div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-4 flex flex-col items-center justify-center gap-3">
            {donutData.length === 0 ? (
              <p className="text-xs text-slate-500">No classified events in the window yet.</p>
            ) : (
              <>
                <Donut data={donutData} centerLabel="detections" centerValue={detections.length} />
                <ul className="w-full space-y-1">
                  {donutData.map((c) => (
                    <li key={c.name} className="flex items-center justify-between gap-2 text-[11px]">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: c.color }} />
                        <span className="truncate text-slate-600">{c.name}</span>
                      </span>
                      <span className="font-mono font-semibold text-slate-900">{c.value}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>

          <div className="lg:col-span-8">
            <div className="overflow-hidden rounded-lg border border-slate-200">
              <table className="w-full border-collapse text-left">
                <thead className="bg-slate-50">
                  <tr className="border-b border-slate-200">
                    {['Class', 'Count', 'Share', 'Avg confidence', 'Avg risk'].map((h) => (
                      <th key={h} scope="col" className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {byClass.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-8 text-center text-xs text-slate-500">
                        Waiting for detections.
                      </td>
                    </tr>
                  )}
                  {byClass.map((c) => {
                    const meta = classMeta(c.name);
                    const Icon = CLASS_ICONS[meta.iconKey] || ShieldCheck;
                    return (
                      <tr key={c.name} className="border-b border-slate-100 last:border-b-0">
                        <td className="px-3 py-2">
                          <span className="flex items-center gap-2">
                            <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: meta.color }} />
                            <span className="text-xs font-semibold text-slate-800">{c.name}</span>
                          </span>
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] font-bold text-slate-900">{c.count}</td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <Meter value={c.share} tone={c.name === 'Benign' ? 'success' : 'danger'} height={6} className="w-24" />
                            <span className="font-mono text-[11px] text-slate-600">{c.share.toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-600">{(c.avgConfidence * 100).toFixed(1)}%</td>
                        <td className="px-3 py-2">
                          <RiskBadge score={c.avgScore} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </Card>

      {/* ---------------------------------------------------------------- */}
      {/* Live inference console                                           */}
      {/* ---------------------------------------------------------------- */}
      <InferenceConsole />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live Inference Console                                              */
/* ------------------------------------------------------------------ */
function InferenceConsole() {
  const [features, setFeatures] = useState(() => ({ ...FEATURE_DEFAULTS }));
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);

  const setFeature = (key, value) => setFeatures((prev) => ({ ...prev, [key]: value }));

  const runPrediction = async () => {
    setRunning(true);
    const detail = {
      packet_size: Number(features.packet_size),
      protocol: features.protocol,
      request_rate: Number(features.request_rate),
      session_duration: Number(features.session_duration),
      payload_pattern_score: Number(features.payload_pattern_score),
      login_failure_rate: Number(features.login_failure_rate),
      distinct_ports_touched: Number(features.distinct_ports_touched),
      url_entropy: Number(features.url_entropy),
      outbound_bytes_ratio: Number(features.outbound_bytes_ratio),
      is_suspicious_process: features.is_suspicious_process ? 1 : 0,
      privilege_level: features.privilege_level ? 1 : 0,
      off_hours_access: features.off_hours_access ? 1 : 0,
    };
    const res = await api.predict({ detail });
    setResult(normalizePrediction(res) || localPredict(features));
    setRunning(false);
  };

  const reset = () => {
    setFeatures({ ...FEATURE_DEFAULTS });
    setResult(null);
  };

  const ranges = FEATURE_SPECS.filter((f) => f.kind === 'range');
  const toggles = FEATURE_SPECS.filter((f) => f.kind === 'toggle');
  const selects = FEATURE_SPECS.filter((f) => f.kind === 'select');

  return (
    <Card>
      <CardHeader
        icon={Terminal}
        title="Live Inference Console"
        subtitle="Score a synthetic telemetry event through the ensemble and inspect every class probability."
        right={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={reset}
              aria-label="Reset feature inputs"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Reset
            </button>
            <button
              type="button"
              onClick={runPrediction}
              disabled={running}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-blue-700 disabled:opacity-60"
            >
              <Cpu className="w-3.5 h-3.5" /> {running ? 'Scoring…' : 'Run Prediction'}
            </button>
          </div>
        }
      />

      <div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* ---- feature inputs ---- */}
        <div className="lg:col-span-7 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-3">
            {ranges.map((f) => (
              <div key={f.key}>
                <div className="flex items-baseline justify-between gap-2">
                  <label htmlFor={`feat-${f.key}`} className="text-[11px] font-semibold text-slate-700">
                    {f.label}
                  </label>
                  <span className="font-mono text-[11px] font-bold text-blue-700">
                    {Number(features[f.key]).toFixed(f.step < 1 ? 2 : 0)}
                    {f.unit && <span className="text-slate-400"> {f.unit}</span>}
                  </span>
                </div>
                <input
                  id={`feat-${f.key}`}
                  type="range"
                  min={f.min}
                  max={f.max}
                  step={f.step}
                  value={features[f.key]}
                  onChange={(e) => setFeature(f.key, Number(e.target.value))}
                  className="mt-1 w-full accent-blue-600"
                />
                <p className="text-[10px] text-slate-500">{f.hint}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-2 border-t border-slate-200 pt-4">
            {toggles.map((f) => (
              <Toggle
                key={f.key}
                checked={Boolean(features[f.key])}
                onChange={(v) => setFeature(f.key, v)}
                label={f.label}
                description={f.hint}
                tone={f.key === 'is_suspicious_process' ? 'danger' : 'primary'}
              />
            ))}
            {selects.map((f) => (
              <div key={f.key} className="flex items-center justify-between gap-3">
                <span className="min-w-0">
                  <label htmlFor={`feat-${f.key}`} className="block text-xs font-semibold text-slate-800">
                    {f.label}
                  </label>
                  <span className="block text-[11px] leading-snug text-slate-500">{f.hint}</span>
                </span>
                <select
                  id={`feat-${f.key}`}
                  value={features[f.key]}
                  onChange={(e) => setFeature(f.key, e.target.value)}
                  className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-mono font-semibold text-slate-700 focus:border-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/25"
                >
                  {f.options.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </select>
              </div>
            ))}
          </div>
        </div>

        {/* ---- prediction result ---- */}
        <div className="lg:col-span-5">
          {running ? (
            <div className="space-y-2.5">
              <div className="skeleton h-16 rounded-lg" />
              <div className="skeleton h-10 rounded-lg" />
              <div className="skeleton h-10 rounded-lg" />
              <div className="skeleton h-32 rounded-lg" />
            </div>
          ) : result ? (
            <PredictionResult result={result} />
          ) : (
            <div className="flex h-full min-h-[240px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-slate-200 bg-slate-50 p-6 text-center">
              <Cpu className="h-8 w-8 text-slate-300" />
              <p className="text-xs font-semibold text-slate-700">No prediction yet</p>
              <p className="text-[11px] text-slate-500">
                Adjust the {MODEL_INFO.featureCount} features and run the ensemble to see the predicted class, confidence
                and full probability vector.
              </p>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

function PredictionResult({ result }) {
  const sev = severityStyle(result.score);
  const benign = result.verdict === 'benign';
  const meta = classMeta(result.label);
  const Icon = CLASS_ICONS[meta.iconKey] || ShieldCheck;

  return (
    <div className="space-y-3 animate-slideInUp">
      <div className={cn('rounded-lg border p-4', sev.bg, sev.border)}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <Icon className="mt-0.5 h-5 w-5 shrink-0" style={{ color: meta.color }} />
            <div className="min-w-0">
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Predicted class</p>
              <p className="text-sm font-bold text-slate-900">{result.label}</p>
              <p className="mt-0.5 font-mono text-[11px] text-slate-600">
                {result.mitre || 'no MITRE mapping'} · {result.layer} · {result.method}
              </p>
            </div>
          </div>
          <RiskBadge score={result.score} />
        </div>

        <div className="mt-3 grid grid-cols-2 gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Confidence</p>
            <p className="font-mono text-lg font-extrabold leading-none text-slate-900">
              {(result.confidence * 100).toFixed(1)}%
            </p>
            <Meter value={result.confidence * 100} tone={benign ? 'success' : 'danger'} height={6} className="mt-1.5" />
          </div>
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Anomaly score</p>
            <p className="font-mono text-lg font-extrabold leading-none text-slate-900">
              {result.anomalyScore.toFixed(3)}
            </p>
            <Meter value={result.anomalyScore * 100} tone="violet" height={6} className="mt-1.5" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div className="rounded-lg border border-slate-200 bg-white p-2.5">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Verdict</p>
          <p className={cn('font-mono text-xs font-bold uppercase', benign ? 'text-emerald-700' : 'text-rose-700')}>
            {result.verdict}
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-2.5">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Risk score</p>
          <p className="font-mono text-xs font-bold text-slate-900">{result.score}/100</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-2.5">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Severity</p>
          <p className={cn('font-mono text-xs font-bold', sev.text)}>{sev.label}</p>
        </div>
      </div>

      <div className="rounded-lg border border-blue-200 bg-blue-50 p-3">
        <p className="text-[10px] font-bold uppercase tracking-wider text-blue-700">Recommended action</p>
        <p className="mt-0.5 text-xs text-slate-800">{result.recommendedAction}</p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-3">
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Class probabilities</p>
          <Pill tone={result.simulated ? 'warning' : 'success'}>
            {result.simulated ? 'LOCAL HEURISTIC' : 'MODEL OUTPUT'}
          </Pill>
        </div>
        <ul className="mt-2 space-y-1.5">
          {result.probabilities.map((p) => {
            const pm = classMeta(p.name);
            const top = p.name === result.label;
            return (
              <li key={p.name} className="flex items-center gap-2">
                <span className={cn('w-40 shrink-0 truncate text-[11px]', top ? 'font-bold text-slate-900' : 'text-slate-600')}>
                  {p.name}
                </span>
                <span className="meter-track h-1.5 flex-1">
                  <span
                    className="meter-fill block"
                    style={{ width: `${Math.max(1, p.probability * 100)}%`, backgroundColor: pm.color, opacity: top ? 1 : 0.55 }}
                  />
                </span>
                <span className={cn('w-12 shrink-0 text-right font-mono text-[10px]', top ? 'font-bold text-slate-900' : 'text-slate-500')}>
                  {(p.probability * 100).toFixed(1)}%
                </span>
              </li>
            );
          })}
        </ul>
        {result.simulated && (
          <p className="mt-2 text-[10px] text-slate-500">
            Detection service unreachable — probabilities computed by the local feature-rule fallback.
          </p>
        )}
      </div>
    </div>
  );
}
