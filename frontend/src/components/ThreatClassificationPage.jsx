import React, { useEffect, useMemo, useState } from 'react';
import {
  Boxes,
  Brain,
  Bug,
  Code2,
  Database,
  DoorOpen,
  Fish,
  GitBranch,
  KeyRound,
  Layers,
  Radar,
  ScanLine,
  ShieldCheck,
  SlidersHorizontal,
  Table2,
  Waves,
  Workflow,
  Zap,
} from 'lucide-react';
import { api } from '../lib/api';
import { cn, SEVERITY_STYLES } from '../lib/cn';
import { Card, CardHeader, Meter, Pill } from './ui/Primitives';
import {
  ATTACK_CLASSES,
  DETECTION_METHOD,
  FALLBACK_CLASS_REPORT,
  FALLBACK_IMPORTANCES,
  LAYER_TONE,
  MODEL_INFO,
  classMeta,
  rankFeatureImportances,
  splitClassReport,
} from '../lib/useDetectionStream';

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

const METHOD_TONE = {
  [DETECTION_METHOD.RF]: 'primary',
  [DETECTION_METHOD.ISO]: 'violet',
  [DETECTION_METHOD.HYBRID]: 'warning',
};

const PIPELINE = [
  {
    icon: Brain,
    title: 'Supervised RandomForest',
    body: 'Classifies known attack patterns into the 9-class taxonomy and emits per-class probabilities.',
    tone: 'text-blue-600 bg-blue-50 border-blue-200',
  },
  {
    icon: ScanLine,
    title: 'Unsupervised IsolationForest',
    body: 'Trained on benign traffic only, so novel and zero-day behaviour surfaces as an anomaly score.',
    tone: 'text-violet-600 bg-violet-50 border-violet-200',
  },
  {
    icon: SlidersHorizontal,
    title: 'Correlation rules',
    body: 'Deterministic guardrails add MITRE context and escalate multi-layer weak signals.',
    tone: 'text-amber-600 bg-amber-50 border-amber-200',
  },
  {
    icon: Zap,
    title: 'Fused risk score',
    body: 'Model confidence, anomaly intensity and rule hits combine into one 0-100 score that drives response.',
    tone: 'text-rose-600 bg-rose-50 border-rose-200',
  },
];

/** Normalize `/detect/classes` payloads onto the canonical catalog. */
function mergeCatalog(payload) {
  const list = Array.isArray(payload) ? payload : payload?.classes || [];
  if (!Array.isArray(list) || list.length === 0) return ATTACK_CLASSES;
  const merged = list
    .map((entry) => {
      const name = typeof entry === 'string' ? entry : entry?.name || entry?.label || entry?.class;
      if (!name) return null;
      const local = classMeta(name);
      const source = typeof entry === 'string' ? {} : entry;
      return {
        ...local,
        name: local.name,
        mitre: source.mitre || source.mitre_id || source.technique || local.mitre,
        layer: (source.layer || local.layer || 'network').toLowerCase(),
        severity: (source.severity || local.severity || 'medium').toLowerCase(),
        method: source.method || source.detection_method || local.method,
        description: source.description || local.description,
      };
    })
    .filter(Boolean);
  return merged.length > 0 ? merged : ATTACK_CLASSES;
}

/** Pull a { className: count } map out of a loosely-shaped stats payload. */
function extractCounts(overview) {
  const raw =
    overview?.class_distribution ||
    overview?.class_counts ||
    overview?.classes ||
    overview?.detections_by_class ||
    null;
  const counts = {};
  if (Array.isArray(raw)) {
    raw.forEach((entry) => {
      const name = entry?.name || entry?.label || entry?.class;
      const value = Number(entry?.count ?? entry?.value ?? entry?.total);
      if (name && Number.isFinite(value)) counts[name] = value;
    });
  } else if (raw && typeof raw === 'object') {
    Object.entries(raw).forEach(([name, value]) => {
      const n = Number(value);
      if (Number.isFinite(n)) counts[name] = n;
    });
  }
  return counts;
}

export default function ThreatClassificationPage() {
  const [catalog, setCatalog] = useState(ATTACK_CLASSES);
  const [counts, setCounts] = useState({});
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [liveCatalog, setLiveCatalog] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const [classes, overview, modelMetrics] = await Promise.all([
        api.getThreatClasses(),
        api.getStatsOverview(),
        api.getMetrics(),
      ]);
      if (!alive) return;
      const list = Array.isArray(classes) ? classes : classes?.classes || [];
      setLiveCatalog(Array.isArray(list) && list.length > 0);
      setCatalog(mergeCatalog(classes));
      setCounts(extractCounts(overview));
      setMetrics(modelMetrics);
      setLoading(false);
    };
    load();
    return () => {
      alive = false;
    };
  }, []);

  const totalCount = Object.values(counts).reduce((s, v) => s + v, 0);
  const usingLiveMetrics = Boolean(metrics?.class_report);
  const usingLiveImportances = Boolean(metrics?.feature_importances);

  const { rows, summary } = useMemo(
    () => splitClassReport(metrics?.class_report || FALLBACK_CLASS_REPORT),
    [metrics]
  );
  const importances = useMemo(
    () => rankFeatureImportances(metrics?.feature_importances || FALLBACK_IMPORTANCES),
    [metrics]
  );
  const accuracy = summary.find((s) => s.name.toLowerCase() === 'accuracy');
  const macro = summary.find((s) => s.name.toLowerCase() === 'macro avg');
  const weighted = summary.find((s) => s.name.toLowerCase() === 'weighted avg');

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------------------------------------------------------- */}
      {/* Header                                                           */}
      {/* ---------------------------------------------------------------- */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 shrink-0">
            <Boxes className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-bold text-slate-900">Threat Classification & Model Quality</h1>
            <p className="text-xs text-slate-600 mt-0.5">
              The attack taxonomy Sentinel detects, how each class is identified, and how well the ensemble performs on
              every class.
            </p>
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <Pill tone="primary">
                <Brain className="w-3 h-3" /> {MODEL_INFO.supervised} + {MODEL_INFO.unsupervised}
              </Pill>
              <Pill tone="neutral">
                {catalog.length} classes / {MODEL_INFO.featureCount} features
              </Pill>
              <Pill tone={liveCatalog ? 'success' : 'warning'}>
                {liveCatalog ? 'CATALOG FROM BACKEND' : 'LOCAL CATALOG'}
              </Pill>
            </div>
          </div>
        </div>
        <div className="text-xs font-mono text-slate-500">
          Observed events: <strong className="text-slate-900">{totalCount || '—'}</strong>
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Class catalog                                                    */}
      {/* ---------------------------------------------------------------- */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-5">
        {loading
          ? Array.from({ length: 6 }).map((_, i) => <div key={i} className="skeleton h-52 rounded-xl" />)
          : catalog.map((c) => {
              const Icon = CLASS_ICONS[c.iconKey] || ShieldCheck;
              const sev = SEVERITY_STYLES[c.severity] || SEVERITY_STYLES.medium;
              const count = counts[c.name] ?? 0;
              const share = totalCount > 0 ? (count / totalCount) * 100 : 0;
              return (
                <Card key={c.name} hover className="flex flex-col gap-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5 min-w-0">
                      <span className="mt-0.5 shrink-0 rounded-lg border border-slate-200 bg-slate-50 p-2">
                        <Icon className="w-4 h-4" style={{ color: c.color }} />
                      </span>
                      <div className="min-w-0">
                        <h3 className="text-sm font-bold text-slate-900 leading-tight">{c.name}</h3>
                        <p className="mt-0.5 font-mono text-[11px] text-slate-500">{c.mitre || 'no MITRE mapping'}</p>
                      </div>
                    </div>
                    <span
                      className={cn(
                        'shrink-0 rounded border px-2 py-0.5 font-mono text-[10px] font-bold',
                        sev.bg,
                        sev.text,
                        sev.border
                      )}
                    >
                      {sev.label}
                    </span>
                  </div>

                  <p className="text-xs leading-relaxed text-slate-600">{c.description}</p>

                  <div className="flex flex-wrap items-center gap-2">
                    <Pill tone={LAYER_TONE[c.layer] || 'neutral'}>
                      <Layers className="w-3 h-3" /> {c.layer}
                    </Pill>
                    <Pill tone={METHOD_TONE[c.method] || 'neutral'}>{c.method}</Pill>
                  </div>

                  <div className="mt-auto border-t border-slate-200 pt-3">
                    <div className="flex items-baseline justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                        Observed detections
                      </span>
                      <span className="font-mono text-sm font-extrabold text-slate-900">{count}</span>
                    </div>
                    <div className="mt-1.5 flex items-center gap-2">
                      <Meter
                        value={share}
                        tone={c.name === 'Benign' ? 'success' : 'danger'}
                        height={6}
                        className="flex-1"
                      />
                      <span className="w-10 text-right font-mono text-[11px] text-slate-600">{share.toFixed(0)}%</span>
                    </div>
                  </div>
                </Card>
              );
            })}
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Per-class model quality + feature importance                     */}
      {/* ---------------------------------------------------------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7">
          <Card>
            <CardHeader
              icon={Table2}
              title="Per-Class Detection Quality"
              subtitle="Precision, recall and F1 from the held-out validation split."
              right={
                <Pill tone={usingLiveMetrics ? 'success' : 'warning'}>
                  {usingLiveMetrics ? 'LIVE METRICS' : 'REFERENCE METRICS'}
                </Pill>
              }
            />

            <div className="mt-4 grid grid-cols-3 gap-3">
              {[
                { label: 'Accuracy', value: accuracy?.value ?? accuracy?.precision, tone: 'text-blue-700' },
                { label: 'Macro F1', value: macro?.f1, tone: 'text-violet-700' },
                { label: 'Weighted F1', value: weighted?.f1, tone: 'text-emerald-700' },
              ].map((s) => (
                <div key={s.label} className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-center">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{s.label}</p>
                  <p className={cn('font-mono text-xl font-extrabold leading-none mt-1', s.tone)}>
                    {typeof s.value === 'number' ? `${(s.value * 100).toFixed(1)}%` : '—'}
                  </p>
                </div>
              ))}
            </div>

            <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full border-collapse text-left">
                <thead className="bg-slate-50">
                  <tr className="border-b border-slate-200">
                    {['Class', 'Precision', 'Recall', 'F1', 'Support'].map((h) => (
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
                  {rows.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-8 text-center text-xs text-slate-500">
                        No per-class report available.
                      </td>
                    </tr>
                  )}
                  {rows.map((r) => {
                    const meta = classMeta(r.name);
                    return (
                      <tr key={r.name} className="border-b border-slate-100 last:border-b-0">
                        <td className="whitespace-nowrap px-3 py-2">
                          <span className="flex items-center gap-2">
                            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} />
                            <span className="text-xs font-semibold text-slate-800">{r.name}</span>
                          </span>
                        </td>
                        <MetricCell value={r.precision} tone="primary" />
                        <MetricCell value={r.recall} tone="violet" />
                        <MetricCell value={r.f1} tone={r.f1 >= 0.9 ? 'success' : r.f1 >= 0.8 ? 'warning' : 'danger'} />
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-slate-500">{r.support}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="mt-2 text-[11px] text-slate-500">
              Aggregate rows (accuracy, macro and weighted averages) are summarised above the table rather than listed as
              classes.
            </p>
          </Card>
        </div>

        <div className="lg:col-span-5">
          <Card>
            <CardHeader
              icon={GitBranch}
              title="Feature Importance"
              subtitle={`Gini importance across the ${MODEL_INFO.featureCount} model features.`}
              right={
                <Pill tone={usingLiveImportances ? 'success' : 'warning'}>
                  {usingLiveImportances ? 'LIVE' : 'REFERENCE'}
                </Pill>
              }
            />
            <ul className="mt-4 space-y-2.5">
              {importances.map((f, i) => (
                <li key={f.name}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="flex min-w-0 items-center gap-1.5">
                      <span className="font-mono text-[10px] text-slate-400">{String(i + 1).padStart(2, '0')}</span>
                      <span className="truncate font-mono text-[11px] text-slate-700">{f.name}</span>
                    </span>
                    <span className="shrink-0 font-mono text-[11px] font-bold text-blue-700">
                      {(f.value * 100).toFixed(1)}%
                    </span>
                  </div>
                  <Meter value={f.share} tone={i < 3 ? 'primary' : 'neutral'} height={6} className="mt-1" />
                </li>
              ))}
              {importances.length === 0 && (
                <li className="text-xs text-slate-500">No feature importances reported by the model service.</li>
              )}
            </ul>
          </Card>
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Detection pipeline strip                                         */}
      {/* ---------------------------------------------------------------- */}
      <Card>
        <CardHeader
          icon={Workflow}
          title="How Detection Works"
          subtitle="Four stages turn raw telemetry into one explainable risk score."
        />
        <ol className="mt-4 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {PIPELINE.map((step, i) => {
            const Icon = step.icon;
            return (
              <li key={step.title} className="rounded-lg border border-slate-200 bg-white p-3.5">
                <div className="flex items-center gap-2">
                  <span className={cn('rounded-lg border p-1.5', step.tone)}>
                    <Icon className="w-4 h-4" />
                  </span>
                  <span className="font-mono text-[10px] font-bold text-slate-400">STEP {i + 1}</span>
                </div>
                <h4 className="mt-2 text-xs font-bold text-slate-900">{step.title}</h4>
                <p className="mt-1 text-[11px] leading-snug text-slate-600">{step.body}</p>
              </li>
            );
          })}
        </ol>
      </Card>
    </div>
  );
}

function MetricCell({ value, tone }) {
  return (
    <td className="px-3 py-2">
      <div className="flex items-center gap-2">
        <Meter value={value * 100} tone={tone} height={6} className="w-16" />
        <span className="font-mono text-[11px] text-slate-600">{(value * 100).toFixed(1)}%</span>
      </div>
    </td>
  );
}
