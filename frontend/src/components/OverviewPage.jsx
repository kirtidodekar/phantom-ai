import React, { useEffect, useMemo, useState } from 'react';
import TrajectoryChart from './TrajectoryChart';
import {
  ShieldAlert, Activity, AlertTriangle, Layers, ShieldCheck, Search,
  User, Monitor, Terminal, Globe, Radio, Server, Eye, FlaskConical,
} from 'lucide-react';
import { Card, CardHeader, StatCard, RiskBadge, LiveDot, Pill } from './ui/Primitives';
import { api } from '../lib/api';
import { cn } from '../lib/cn';

/**
 * Overview page.
 *
 * Every figure on this page is derived from real backend state: the selected
 * incident's own evidence, its risk breakdown, and live network counters.
 * Nothing is hardcoded. When no telemetry has been observed the page says so
 * instead of displaying invented numbers.
 *
 * Incidents produced by the simulated replay engine carry `is_simulated=true`
 * and are labelled SIMULATED so demo data can never be mistaken for real
 * observations.
 */

const LAYER_STYLES = {
  identity: { text: 'text-violet-700', bg: 'bg-violet-50', border: 'border-violet-200', icon: User },
  endpoint: { text: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-200', icon: Monitor },
  process: { text: 'text-amber-700', bg: 'bg-amber-50', border: 'border-amber-200', icon: Terminal },
  network: { text: 'text-rose-700', bg: 'bg-rose-50', border: 'border-rose-200', icon: Globe },
};

const NODE_ICONS = { user: User, host: Monitor, process: Terminal, destination: Globe, api: Server };

function layerStyle(layer) {
  return LAYER_STYLES[String(layer || '').toLowerCase()] || LAYER_STYLES.network;
}

function shortTime(value) {
  if (!value) return '--:--:--';
  const s = String(value);
  const i = s.indexOf('T');
  return i >= 0 ? s.substring(i + 1, i + 9) : s;
}

export default function OverviewPage({
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  activeIncident,
  currentStage,
  onOpenEntity,
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [netStatus, setNetStatus] = useState(null);

  // Live network counters feed the real-time strip.
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      const s = await api.getNetworkStatus();
      if (!cancelled) setNetStatus(s);
    };
    poll();
    const timer = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const filteredIncidents = useMemo(() => incidents.filter((inc) => {
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch = !q
      || (inc.title || '').toLowerCase().includes(q)
      || (inc.incident_id || '').toLowerCase().includes(q)
      || (inc.primary_entity || '').toLowerCase().includes(q);
    const score = inc.threat_score || 0;
    const matchesSev =
      severityFilter === 'ALL' ? true
      : severityFilter === 'HIGH' ? score >= 80
      : severityFilter === 'MEDIUM' ? (score >= 60 && score < 80)
      : score < 60;
    return matchesSearch && matchesSev;
  }), [incidents, searchQuery, severityFilter]);

  // ---- Real metrics derived from the selected incident ----
  const metrics = useMemo(() => {
    if (!activeIncident) return null;
    const evidences = activeIncident.evidences || [];
    const confidences = evidences
      .map((e) => e.ml_confidence)
      .filter((v) => typeof v === 'number' && v > 0);
    const avgConfidence = confidences.length
      ? confidences.reduce((a, b) => a + b, 0) / confidences.length
      : null;
    const ruleHits = evidences.filter((e) => e.rule_name).length;

    return {
      entities: (activeIncident.affected_entities || []).length,
      signals: evidences.length,
      layers: (activeIncident.layers_involved || []).length,
      ruleHits,
      avgConfidence,
      techniques: (activeIncident.mitre_mappings || []).length,
    };
  }, [activeIncident]);

  const monitoring = Boolean(netStatus?.monitoring);
  const isSimulated = activeIncident?.is_simulated === true;
  const threatScore = activeIncident?.threat_score ?? 0;
  const threatLevel = activeIncident?.risk_breakdown?.risk_level || 'LOW';

  // Real event sequence: newest evidence first, straight from the incident.
  const sequence = useMemo(() => {
    const evidences = activeIncident?.evidences || [];
    return evidences.slice(-6).reverse().map((e, idx) => ({
      key: `${e.event?.event_id || idx}`,
      time: shortTime(e.event?.timestamp),
      layer: e.event?.layer || 'network',
      action: e.event?.action || 'observed',
      attack: e.event?.attack_type || 'Benign',
      entity: e.event?.entity_id || '',
      rule: e.rule_name,
      contribution: e.contribution_score,
      confidence: e.ml_confidence,
    }));
  }, [activeIncident]);

  // Real reasons: rule names + scoring breakdown contributions.
  const reasons = useMemo(() => {
    if (!activeIncident) return [];
    const out = [];
    const rb = activeIncident.risk_breakdown;
    const seenRules = new Set();

    (activeIncident.evidences || []).forEach((e) => {
      if (e.rule_name && !seenRules.has(e.rule_name)) {
        seenRules.add(e.rule_name);
        out.push({
          tone: 'danger',
          icon: AlertTriangle,
          text: e.rule_name,
          detail: `+${(e.contribution_score || 0).toFixed(1)} contribution`,
        });
      }
    });

    if (rb?.cross_layer_diversity_bonus > 0) {
      out.push({
        tone: 'warning',
        icon: Layers,
        text: `Evidence converged across ${(activeIncident.layers_involved || []).length} telemetry layers`,
        detail: `+${rb.cross_layer_diversity_bonus} cross-layer bonus`,
      });
    }
    if (rb?.temporal_sequence_score > 0) {
      out.push({
        tone: 'primary',
        icon: Activity,
        text: `Sustained activity across ${(activeIncident.evidences || []).length} correlated signals`,
        detail: `+${rb.temporal_sequence_score} sequence strength`,
      });
    }
    if (rb?.asset_criticality_boost > 0) {
      out.push({
        tone: 'warning',
        icon: ShieldAlert,
        text: 'Target marked as a high-value asset',
        detail: `+${rb.asset_criticality_boost} criticality`,
      });
    }
    return out.slice(0, 5);
  }, [activeIncident]);

  // Real entities from the incident's own attack graph.
  const entities = useMemo(() => {
    const nodes = activeIncident?.graph_nodes || [];
    return nodes.slice(0, 6).map((n) => ({
      id: n.id,
      label: n.label,
      type: n.type,
      layer: n.layer,
      status: n.status,
    }));
  }, [activeIncident]);

  const toneClasses = {
    danger: 'bg-rose-50 border-rose-200 text-rose-900',
    warning: 'bg-amber-50 border-amber-200 text-amber-900',
    primary: 'bg-blue-50 border-blue-200 text-blue-900',
  };

  // ---------------- Empty state: no real telemetry yet ----------------
  if (!activeIncident) {
    return (
      <div className="space-y-5 animate-fadeIn">
        <LiveStrip netStatus={netStatus} monitoring={monitoring} />
        <Card className="flex flex-col items-center justify-center py-16 text-center space-y-3">
          <ShieldCheck className="w-12 h-12 text-slate-300" />
          <h2 className="text-sm font-bold text-slate-900">No incidents observed</h2>
          <p className="text-xs text-slate-600 max-w-md leading-relaxed">
            {monitoring
              ? 'Live network monitoring is active. This view will populate as soon as correlated evidence crosses a detection threshold. Benign traffic intentionally raises no incident.'
              : 'Nothing is being monitored yet. Open the Live Network tab to start authorized packet capture, or run the simulated scenario from the navbar to explore the workflow with clearly-labelled demo data.'}
          </p>
          <div className="flex items-center gap-2 pt-1">
            <Pill tone={monitoring ? 'success' : 'neutral'}>
              {monitoring ? 'LIVE CAPTURE ACTIVE' : 'NO LIVE CAPTURE'}
            </Pill>
            <Pill tone="neutral">REAL DATA ONLY</Pill>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-5 animate-fadeIn">
      <LiveStrip netStatus={netStatus} monitoring={monitoring} />

      {/* ---------------- Active investigation summary ---------------- */}
      <div className={cn(
        'soc-surface p-5 border flex flex-wrap items-start justify-between gap-4',
        isSimulated ? 'border-amber-300' : 'border-[#D9E0E8]',
      )}>
        <div className="space-y-1.5 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm font-bold text-slate-900">
              {activeIncident.incident_id}
            </span>
            <RiskBadge score={threatScore} showScore={false} />
            <span className="font-mono text-[10px] font-bold text-slate-600">
              {threatLevel} {Math.round(threatScore)}/100
            </span>

            {/* Provenance label - never let demo data look real. */}
            {isSimulated ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-300">
                <FlaskConical className="w-3 h-3" />
                SIMULATED REPLAY
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <Radio className="w-3 h-3" />
                OBSERVED TELEMETRY
              </span>
            )}
          </div>

          <p className="text-xs text-slate-600 max-w-2xl">{activeIncident.title}</p>

          <div className="flex items-center gap-3 flex-wrap text-[11px] font-mono text-slate-500">
            <span>ENTITY: <span className="text-slate-800 font-semibold">{activeIncident.primary_entity}</span></span>
            <span>STATUS: <span className="text-slate-800 font-semibold">{activeIncident.status}</span></span>
            {currentStage && isSimulated && (
              <span>PHASE: <span className="text-slate-800 font-semibold">{currentStage}</span></span>
            )}
          </div>
        </div>

        {/* Search / filter over real incidents */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
            <label className="sr-only" htmlFor="inc-search">Search incidents</label>
            <input
              id="inc-search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search incidents"
              className="w-40 pl-8 pr-2 py-1.5 rounded-md bg-slate-50 border border-slate-300 text-xs text-slate-800 focus:outline-none focus:border-blue-600"
            />
          </div>
          <label className="sr-only" htmlFor="sev-filter">Severity filter</label>
          <select
            id="sev-filter"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2 py-1.5 rounded-md bg-slate-50 border border-slate-300 text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600"
          >
            <option value="ALL">All severities</option>
            <option value="HIGH">Critical / High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* ---------------- Real KPI row ---------------- */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard icon={Server} label="Entities Affected" tone="primary"
          value={metrics.entities} footer="from incident correlation" />
        <StatCard icon={Activity} label="Correlated Signals" tone="violet"
          value={metrics.signals} footer={`${metrics.ruleHits} rule hits`} />
        <StatCard icon={Layers} label="Layers Fused" tone="neutral"
          value={`${metrics.layers} / 4`}
          footer={(activeIncident.layers_involved || []).join(', ') || 'none'} />
        <StatCard icon={ShieldAlert} label="ATT&CK Techniques" tone="danger"
          value={metrics.techniques} footer="mapped from evidence" />
        <StatCard icon={Eye} label="Model Confidence" tone="success"
          value={metrics.avgConfidence !== null ? `${Math.round(metrics.avgConfidence * 100)}%` : 'n/a'}
          footer={metrics.avgConfidence !== null ? 'mean ML confidence' : 'rule-only detection'} />
        <StatCard icon={ShieldCheck} label="Open Incidents" tone="warning"
          value={incidents.length}
          footer={`${filteredIncidents.length} match filter`} />
      </div>

      {/* ---------------- Main grid ---------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-8 space-y-5">
          <TrajectoryChart incident={activeIncident} />

          {/* Real correlated sequence */}
          <Card className="space-y-3">
            <CardHeader
              icon={Activity}
              title="Correlated Event Sequence"
              subtitle="Actual evidence recorded against this incident, newest first"
              right={<Pill tone={isSimulated ? 'warning' : 'success'}>
                {isSimulated ? 'SIMULATED' : 'OBSERVED'}
              </Pill>}
            />
            {sequence.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">
                No evidence recorded on this incident yet.
              </p>
            ) : (
              <div className="space-y-2">
                {sequence.map((ev) => {
                  const st = layerStyle(ev.layer);
                  const Icon = st.icon;
                  return (
                    <div key={ev.key}
                      className={cn('p-3 rounded-lg border flex items-start justify-between gap-3', st.bg, st.border)}>
                      <div className="flex items-start gap-2.5 min-w-0">
                        <Icon className={cn('w-4 h-4 shrink-0 mt-0.5', st.text)} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-[10px] font-bold text-slate-500">{ev.time}</span>
                            <span className={cn('font-mono text-[10px] font-bold uppercase', st.text)}>
                              {ev.layer}
                            </span>
                            <span className="text-xs font-semibold text-slate-900">{ev.attack}</span>
                          </div>
                          <p className="text-[11px] text-slate-600 mt-0.5 font-mono truncate">
                            {ev.action}{ev.entity ? ` — ${ev.entity}` : ''}
                          </p>
                          {ev.rule && (
                            <p className="text-[10px] text-slate-500 mt-0.5">Rule: {ev.rule}</p>
                          )}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="font-mono text-xs font-bold text-slate-900">
                          +{(ev.contribution || 0).toFixed(1)}
                        </span>
                        {ev.confidence > 0 && (
                          <span className="block font-mono text-[10px] text-slate-500">
                            {Math.round(ev.confidence * 100)}% conf
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        <div className="lg:col-span-4 space-y-5">
          {/* Real scoring rationale */}
          <Card className="space-y-3">
            <CardHeader icon={ShieldAlert} title="Why Sentinel Flagged It" accent="text-rose-600"
              subtitle="Derived from the scoring audit trail" />
            {reasons.length === 0 ? (
              <p className="text-xs text-slate-500 py-3">
                No rule hits or scoring bonuses recorded yet.
              </p>
            ) : (
              <ul className="space-y-2">
                {reasons.map((r, i) => {
                  const Icon = r.icon;
                  return (
                    <li key={i} className={cn('p-2.5 rounded-lg border flex items-start gap-2 text-xs', toneClasses[r.tone])}>
                      <Icon className="w-4 h-4 shrink-0 mt-0.5" />
                      <span className="min-w-0">
                        <span className="block">{r.text}</span>
                        <span className="block text-[10px] font-mono opacity-75 mt-0.5">{r.detail}</span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
            {activeIncident.risk_breakdown?.formula_explanation && (
              <p className="text-[10px] font-mono text-slate-500 leading-relaxed border-t border-slate-200 pt-2">
                {activeIncident.risk_breakdown.formula_explanation}
              </p>
            )}
          </Card>

          {/* Real entities from the attack graph */}
          <Card className="space-y-3">
            <CardHeader icon={Server} title="Affected Entities"
              subtitle="Nodes from this incident's attack graph"
              right={<span className="text-[11px] text-slate-500 font-mono">click to inspect</span>} />
            {entities.length === 0 ? (
              <p className="text-xs text-slate-500 py-3">No entities linked yet.</p>
            ) : (
              <div className="space-y-2">
                {entities.map((n) => {
                  const Icon = NODE_ICONS[n.type] || Server;
                  const st = layerStyle(n.layer);
                  const compromised = n.status === 'compromised';
                  return (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => onOpenEntity && onOpenEntity({
                        id: n.id, label: n.label, type: n.type,
                        risk_score: threatScore, status: n.status, layer: n.layer,
                      })}
                      className="w-full text-left p-3 rounded-lg bg-white border border-slate-200 hover:border-slate-300 flex items-center justify-between gap-3 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
                    >
                      <span className="flex items-center gap-2.5 min-w-0">
                        <Icon className={cn('w-4 h-4 shrink-0', st.text)} />
                        <span className="min-w-0">
                          <span className="block font-mono text-xs font-bold text-slate-900 truncate">
                            {n.label}
                          </span>
                          <span className="block font-mono text-[10px] text-slate-500 capitalize">
                            {n.type} · {n.layer}
                          </span>
                        </span>
                      </span>
                      <Pill tone={compromised ? 'danger' : 'warning'}>
                        {String(n.status || '').toUpperCase()}
                      </Pill>
                    </button>
                  );
                })}
              </div>
            )}
          </Card>

          {/* Real incident list */}
          {filteredIncidents.length > 1 && (
            <Card className="space-y-3">
              <CardHeader icon={Layers} title="Open Investigations"
                subtitle={`${filteredIncidents.length} incidents`} />
              <div className="space-y-1.5 max-h-[240px] overflow-y-auto">
                {filteredIncidents.map((inc) => (
                  <button
                    key={inc.incident_id}
                    type="button"
                    onClick={() => onSelectIncident && onSelectIncident(inc.incident_id)}
                    className={cn(
                      'w-full text-left p-2.5 rounded-lg border flex items-center justify-between gap-2 transition text-xs',
                      inc.incident_id === selectedIncidentId
                        ? 'bg-blue-50 border-blue-300'
                        : 'bg-white border-slate-200 hover:border-slate-300',
                    )}
                  >
                    <span className="min-w-0">
                      <span className="block font-mono font-bold text-slate-900 truncate">
                        {inc.incident_id}
                      </span>
                      <span className="block font-mono text-[10px] text-slate-500 truncate">
                        {inc.primary_entity}
                      </span>
                    </span>
                    <span className="flex items-center gap-1.5 shrink-0">
                      {inc.is_simulated && <Pill tone="warning">SIM</Pill>}
                      <RiskBadge score={inc.threat_score || 0} />
                    </span>
                  </button>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Live capture strip - real counters straight from the monitor, or an explicit
 * "not monitoring" state. No placeholder numbers.
 */
function LiveStrip({ netStatus, monitoring }) {
  const cap = netStatus?.capability || {};
  const blocked = cap.capture_possible === false;

  return (
    <div className={cn(
      'soc-surface px-5 py-3 border flex flex-wrap items-center gap-x-6 gap-y-2',
      monitoring ? 'border-emerald-200' : 'border-[#D9E0E8]',
    )}>
      <span className="flex items-center gap-2 text-xs font-bold text-slate-900">
        <Radio className="w-4 h-4 text-blue-600" />
        Live Network
        {monitoring
          ? <LiveDot tone="success" label="CAPTURING" />
          : <Pill tone="neutral">{blocked ? 'UNAVAILABLE' : 'STOPPED'}</Pill>}
      </span>

      {monitoring ? (
        <>
          <Metric label="pkt/s" value={netStatus?.packets_per_second ?? 0} />
          <Metric label="packets" value={netStatus?.packets_captured ?? 0} />
          <Metric label="source IPs" value={netStatus?.unique_source_ips ?? 0} />
          <Metric label="flows" value={netStatus?.active_connections ?? 0} />
          <Metric label="net threats" value={netStatus?.threat_count ?? 0} />
          <span className="text-[11px] font-mono text-slate-500 truncate max-w-[220px]">
            {String(netStatus?.interface || '').replace('\\Device\\NPF_', '')}
          </span>
        </>
      ) : (
        <span className="text-[11px] text-slate-500">
          {blocked
            ? `Capture unavailable: ${cap.reason || 'unknown'}`
            : 'Start capture from the Live Network tab to observe real traffic.'}
        </span>
      )}
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <span className="flex flex-col leading-tight">
      <span className="font-mono text-sm font-bold text-slate-900">{value}</span>
      <span className="text-[10px] uppercase tracking-wide text-slate-500">{label}</span>
    </span>
  );
}
