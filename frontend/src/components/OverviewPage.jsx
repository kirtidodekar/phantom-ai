import React, { useEffect, useMemo, useState, useCallback } from 'react';
import TrajectoryChart from './TrajectoryChart';
import {
  ShieldAlert, Activity, AlertTriangle, Layers, ShieldCheck, Search,
  User, Monitor, Terminal, Globe, Server, Eye, Lock, Database, Cpu,
  Sparkles, Filter, ChevronRight, ArrowUpRight
} from 'lucide-react';
import { Card, CardHeader, StatCard, RiskBadge, Pill } from './ui/Primitives';
import { api } from '../lib/api';
import { cn } from '../lib/cn';

const LAYER_STYLES = {
  identity: { text: 'text-violet-700', bg: 'bg-violet-50/80', border: 'border-violet-200', badge: 'bg-violet-100 text-violet-800', icon: User },
  endpoint: { text: 'text-blue-700', bg: 'bg-blue-50/80', border: 'border-blue-200', badge: 'bg-blue-100 text-blue-800', icon: Monitor },
  process: { text: 'text-amber-700', bg: 'bg-amber-50/80', border: 'border-amber-200', badge: 'bg-amber-100 text-amber-800', icon: Terminal },
  network: { text: 'text-cyan-700', bg: 'bg-cyan-50/80', border: 'border-cyan-200', badge: 'bg-cyan-100 text-cyan-800', icon: Globe },
  application: { text: 'text-emerald-700', bg: 'bg-emerald-50/80', border: 'border-emerald-200', badge: 'bg-emerald-100 text-emerald-800', icon: Server },
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
  const [sysStatus, setSysStatus] = useState(null);
  const [coverage, setCoverage] = useState(null);

  const fetchStatus = useCallback(async () => {
    const [st, cov] = await Promise.all([
      api.getSystemStatus(),
      api.getCoverage(),
    ]);
    if (st) setSysStatus(st);
    if (cov) setCoverage(cov);
  }, []);

  useEffect(() => {
    fetchStatus();
    const timer = setInterval(fetchStatus, 3000);
    return () => clearInterval(timer);
  }, [fetchStatus]);

  const filteredIncidents = useMemo(() => incidents.filter((inc) => {
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch = !q
      || (inc.explanation || '').toLowerCase().includes(q)
      || (inc.id || inc.incident_id || '').toLowerCase().includes(q)
      || (inc.entity_id || inc.primary_entity || '').toLowerCase().includes(q);
    const score = inc.threat_score || 0;
    const matchesSev =
      severityFilter === 'ALL' ? true
      : severityFilter === 'HIGH' ? score >= 80
      : severityFilter === 'MEDIUM' ? (score >= 60 && score < 80)
      : score < 60;
    return matchesSearch && matchesSev;
  }), [incidents, searchQuery, severityFilter]);

  const threatScore = activeIncident?.threat_score ?? 85;
  const threatLevel = activeIncident?.risk_band || (threatScore >= 80 ? 'CRITICAL' : threatScore >= 60 ? 'HIGH' : 'MEDIUM');
  const entityId = activeIncident?.entity_id || activeIncident?.primary_entity || 'user:attacker_mallory';
  const incidentId = activeIncident?.id || activeIncident?.incident_id || 'INC-MAIN';

  // Real event sequence from timeline or signals_involved
  const sequence = useMemo(() => {
    const timeline = activeIncident?.timeline || [];
    if (timeline.length > 0) {
      return timeline.slice(-6).reverse().map((t, idx) => ({
        key: t.event_id || idx,
        time: shortTime(t.timestamp),
        layer: t.source_type || 'endpoint',
        action: t.event_type || 'activity',
        attack: t.summary || `Signal received from ${t.source_type}`,
        entity: entityId,
      }));
    }
    const signals = activeIncident?.signals_involved || [];
    return signals.slice(-6).reverse().map((s, idx) => ({
      key: s.event_id || idx,
      time: shortTime(s.timestamp),
      layer: s.source_type || 'endpoint',
      action: s.details?.event_type || s.details?.sub_event || 'activity',
      attack: s.details?.summary || `Signal received from ${s.source_type}`,
      entity: s.details?.user || s.details?.host_id || entityId,
    }));
  }, [activeIncident, entityId]);

  // Scoring rationale from risk_breakdown
  const reasons = useMemo(() => {
    if (!activeIncident) return [];
    const out = [];
    const rb = activeIncident.risk_breakdown || {};

    if (rb.rule_score > 0) {
      out.push({
        tone: 'danger',
        icon: AlertTriangle,
        text: 'Deterministic Heuristic Rule Match',
        detail: `+${rb.rule_score} pts (Known attack pattern matched)`,
      });
    }
    if (rb.ml_score > 0) {
      out.push({
        tone: 'primary',
        icon: Cpu,
        text: 'Unsupervised ML Anomaly Outlier',
        detail: `+${rb.ml_score} pts (IsolationForest distribution deviation)`,
      });
    }
    if (rb.agreement_bonus > 0) {
      out.push({
        tone: 'warning',
        icon: Layers,
        text: 'Cross-Layer Correlation Agreement Bonus',
        detail: `+${rb.agreement_bonus} bonus pts (Multi-signal convergence)`,
      });
    }

    if (rb.details && Array.isArray(rb.details)) {
      rb.details.forEach((d) => {
        if (!out.some(o => o.text === d)) {
          out.push({
            tone: 'primary',
            icon: ShieldAlert,
            text: d,
            detail: 'Correlated & Verified',
          });
        }
      });
    }

    return out.slice(0, 5);
  }, [activeIncident]);

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
    danger: 'bg-rose-50 border-rose-200/80 text-rose-900',
    warning: 'bg-amber-50 border-amber-200/80 text-amber-900',
    primary: 'bg-blue-50 border-blue-200/80 text-blue-900',
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner: Active Incident Spotlight Card */}
      <div className="soc-surface p-6 border border-slate-200/90 relative overflow-hidden bg-gradient-to-r from-white via-slate-50/50 to-blue-50/30">
        <div className="flex flex-wrap items-start justify-between gap-6 relative z-10">
          <div className="space-y-3 min-w-0 max-w-4xl">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="font-mono text-base font-extrabold text-slate-900 px-2.5 py-1 rounded-lg bg-slate-100 border border-slate-300 shadow-2xs">
                {incidentId}
              </span>
              <RiskBadge score={threatScore} showScore={false} />
              <span className="font-mono text-xs font-bold text-slate-600 bg-white px-2 py-1 rounded-md border border-slate-200">
                {threatLevel} ({Math.round(threatScore)}/100)
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                CORRELATED INCIDENT
              </span>
              {activeIncident?.mitre_tag && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200">
                  MITRE {activeIncident.mitre_tag.id}: {activeIncident.mitre_tag.name}
                </span>
              )}
            </div>

            <p className="text-xs sm:text-sm text-slate-700 leading-relaxed font-medium">
              {activeIncident?.explanation || 'Cross-layer threat correlation detecting concurrent anomalies across identity authentication, host process execution, and network destination telemetry.'}
            </p>

            <div className="flex items-center gap-4 flex-wrap text-xs font-mono text-slate-500 pt-1">
              <span className="flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-blue-600" />
                <span>PRIMARY ENTITY:</span>
                <strong className="text-slate-900 bg-slate-100 px-1.5 py-0.5 rounded">{entityId}</strong>
              </span>
              <span className="flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-600" />
                <span>STATUS:</span>
                <strong className="text-blue-700 font-bold">{activeIncident?.status || 'NEW'}</strong>
              </span>
              <span className="flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-purple-600" />
                <span>EVIDENCE SIGNALS:</span>
                <strong className="text-slate-900">{activeIncident?.signals_involved?.length || activeIncident?.timeline?.length || 3}</strong>
              </span>
            </div>
          </div>

          {/* Search & Filter Drawer Trigger */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 shrink-0">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="inc-search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search incidents..."
                className="w-full sm:w-48 pl-9 pr-3 py-2 rounded-xl bg-white border border-slate-300 text-xs text-slate-800 focus:outline-none focus:border-blue-600 shadow-2xs font-medium"
              />
            </div>
            <select
              id="sev-filter"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 rounded-xl bg-white border border-slate-300 text-xs font-mono font-bold text-slate-800 focus:outline-none focus:border-blue-600 cursor-pointer shadow-2xs"
            >
              <option value="ALL">All Severities</option>
              <option value="HIGH">Critical (80+)</option>
              <option value="MEDIUM">High / Med (60-79)</option>
              <option value="LOW">Low (&lt;60)</option>
            </select>
          </div>
        </div>
      </div>

      {/* KPI Stat Cards Grid with Distinct Color Chips */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          icon={Server}
          label="Primary Entity"
          tone="primary"
          value={entityId.length > 13 ? entityId.substring(0, 13) + '…' : entityId}
          footer="Target of investigation"
        />
        <StatCard
          icon={Activity}
          label="Threat Score"
          tone="danger"
          value={`${Math.round(threatScore)}/100`}
          footer={`Risk band: ${threatLevel}`}
        />
        <StatCard
          icon={Layers}
          label="Signal Layers"
          tone="cyan"
          value="3 Feeds"
          footer="Network / Host / App"
        />
        <StatCard
          icon={ShieldAlert}
          label="MITRE Tactic"
          tone="warning"
          value={activeIncident?.mitre_tag?.id || 'T1110'}
          footer={activeIncident?.mitre_tag?.name || 'Brute Force'}
        />
        <StatCard
          icon={Eye}
          label="Rule Heuristic"
          tone="success"
          value={`+${activeIncident?.risk_breakdown?.rule_score || 40} pts`}
          footer="Pattern match verification"
        />
        <StatCard
          icon={ShieldCheck}
          label="ML Anomaly"
          tone="violet"
          value={`+${activeIncident?.risk_breakdown?.ml_score || 30} pts`}
          footer="IsolationForest outlier"
        />
      </div>

      {/* Main Grid: Trajectory & Timeline vs Scoring Breakdown & Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (65%): Trajectory Evolution Area Chart & Correlated Sequence Stream */}
        <div className="lg:col-span-8 space-y-6">
          <TrajectoryChart incident={activeIncident} />

          {/* Real Correlated Sequence Stream */}
          <Card className="space-y-4">
            <CardHeader
              icon={Activity}
              title="Correlated Signal & Live Telemetry Sequence"
              subtitle="Real-time multi-signal evidence chronologically correlated to this incident"
              right={
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                  {sequence.length} EVENTS RECORDED
                </span>
              }
            />

            {sequence.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400 font-mono">
                Awaiting correlated multi-signal packets...
              </div>
            ) : (
              <div className="space-y-2.5">
                {sequence.map((ev) => {
                  const st = layerStyle(ev.layer);
                  const Icon = st.icon;
                  return (
                    <div
                      key={ev.key}
                      className={cn(
                        'p-3.5 rounded-xl border flex items-start justify-between gap-3 transition hover-lift',
                        st.bg,
                        st.border
                      )}
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <div className={cn('p-2 rounded-lg bg-white border shrink-0 mt-0.5 shadow-2xs', st.border)}>
                          <Icon className={cn('w-4 h-4', st.text)} />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-[10px] font-bold text-slate-500 bg-white px-1.5 py-0.5 rounded border border-slate-200">
                              {ev.time}
                            </span>
                            <span className={cn('px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase', st.badge)}>
                              {ev.layer}
                            </span>
                            <span className="text-xs font-bold text-slate-900">{ev.action}</span>
                          </div>
                          <p className="text-xs text-slate-700 mt-1 font-mono leading-tight">
                            {ev.attack}
                          </p>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="font-mono text-xs text-blue-700 font-bold bg-white px-2 py-1 rounded-md border border-blue-200 shadow-2xs">
                          {ev.entity}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        {/* Right Column (35%): Scoring Rationale + Entity Cards + Incident Queue */}
        <div className="lg:col-span-4 space-y-6">
          {/* Explainable Scoring Rationale Breakdown */}
          <Card className="space-y-3.5">
            <CardHeader
              icon={ShieldAlert}
              title="Explainable Risk Breakdown"
              accent="text-rose-600"
              subtitle="Mathematical score derivation formula"
            />
            {reasons.length === 0 ? (
              <p className="text-xs text-slate-500 py-3">No scoring bonuses recorded yet.</p>
            ) : (
              <div className="space-y-2">
                {reasons.map((r, i) => {
                  const Icon = r.icon;
                  return (
                    <div
                      key={i}
                      className={cn('p-3 rounded-xl border flex items-start gap-2.5 text-xs', toneClasses[r.tone])}
                    >
                      <Icon className="w-4 h-4 shrink-0 mt-0.5" />
                      <div className="min-w-0 flex-1">
                        <span className="block font-bold">{r.text}</span>
                        <span className="block text-[11px] font-mono opacity-80 mt-0.5">{r.detail}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          {/* Correlated Entities */}
          <Card className="space-y-3.5">
            <CardHeader
              icon={Server}
              title="Correlated Threat Entities"
              subtitle="Topology nodes associated with threat"
              right={<span className="text-[10px] text-slate-500 font-mono font-semibold">Click to inspect</span>}
            />
            {entities.length === 0 ? (
              <p className="text-xs text-slate-500 py-3">No entity graph nodes linked yet.</p>
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
                      className="w-full text-left p-3 rounded-xl bg-white border border-slate-200/90 hover:border-slate-300 flex items-center justify-between gap-3 transition hover-lift cursor-pointer shadow-2xs group"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={cn('p-2 rounded-lg bg-slate-50 border shrink-0', st.border)}>
                          <Icon className={cn('w-4 h-4', st.text)} />
                        </div>
                        <div className="min-w-0">
                          <span className="block font-mono text-xs font-extrabold text-slate-900 truncate group-hover:text-blue-600 transition">
                            {n.label}
                          </span>
                          <span className="block font-mono text-[10px] text-slate-500 capitalize">
                            {n.type} · {n.layer}
                          </span>
                        </div>
                      </div>
                      <Pill tone={compromised ? 'danger' : 'warning'}>
                        {String(n.status || 'ACTIVE').toUpperCase()}
                      </Pill>
                    </button>
                  );
                })}
              </div>
            )}
          </Card>

          {/* Correlated Incident Queue */}
          {filteredIncidents.length > 0 && (
            <Card className="space-y-3.5">
              <CardHeader
                icon={Layers}
                title="Active Incident Queue"
                subtitle={`${filteredIncidents.length} correlated investigations in memory`}
              />
              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {filteredIncidents.map((inc) => {
                  const currentId = inc.id || inc.incident_id;
                  const isSelected = currentId === (selectedIncidentId || incidentId);
                  return (
                    <button
                      key={currentId}
                      type="button"
                      onClick={() => onSelectIncident && onSelectIncident(currentId)}
                      className={cn(
                        'w-full text-left p-3 rounded-xl border flex items-center justify-between gap-2.5 transition cursor-pointer shadow-2xs',
                        isSelected
                          ? 'bg-blue-50 border-blue-400 font-semibold'
                          : 'bg-white border-slate-200 hover:border-slate-300'
                      )}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-900 truncate">
                            {currentId}
                          </span>
                          <span className="text-[10px] font-mono text-blue-700 font-bold bg-blue-100/60 px-1.5 py-0.2 rounded">
                            {inc.status || 'NEW'}
                          </span>
                        </div>
                        <span className="block font-mono text-[11px] text-slate-500 truncate mt-0.5">
                          {inc.entity_id || inc.primary_entity}
                        </span>
                      </div>
                      <RiskBadge score={inc.threat_score || 0} />
                    </button>
                  );
                })}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}