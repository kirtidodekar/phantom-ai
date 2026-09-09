import React from 'react';
import AttackGraph from './AttackGraph';
import { Network, User, Monitor, Terminal, Globe, ArrowRight, ShieldAlert, Sparkles } from 'lucide-react';
import { Card, CardHeader, Pill } from './ui/Primitives';

export default function TopologyPage({ activeIncident, onOpenEntity }) {
  const threatScore = activeIncident?.threat_score || 85;
  const entityId = activeIncident?.entity_id || activeIncident?.primary_entity || 'user:attacker_mallory';
  const rb = activeIncident?.risk_breakdown || {};

  const nodes = activeIncident?.graph_nodes || [
    { id: entityId, label: entityId, type: entityId.includes('user:') ? 'user' : 'host', risk_score: threatScore, status: 'compromised', layer: 'identity' },
    { id: 'SRV-AUTH01', label: 'SRV-AUTH01', type: 'host', risk_score: 87, status: 'compromised', layer: 'endpoint' },
    { id: 'PROC-SSHD', label: 'sshd / bash', type: 'process', risk_score: 89, status: 'suspicious', layer: 'endpoint' },
    { id: 'IP-203.0.113.55', label: '203.0.113.55', type: 'destination', risk_score: 95, status: 'compromised', layer: 'network' }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-6 border border-slate-200/90 flex flex-wrap items-center justify-between gap-6 bg-gradient-to-r from-white via-slate-50 to-violet-50/20">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-violet-600 text-white shadow-md shadow-violet-500/20">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-extrabold text-slate-900 tracking-tight">
              Attack Path & Entity Topology Graph
            </h1>
            <p className="text-xs text-slate-600 font-medium mt-0.5">
              Multi-signal topological progression mapping compromised accounts to host infrastructure, spawned processes, and external command & control targets.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Incident: <strong className="text-blue-700">{activeIncident?.id || activeIncident?.incident_id}</strong>
          </span>
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Target: <strong className="text-slate-900">{entityId}</strong>
          </span>
        </div>
      </div>

      {/* Visual Kill Chain Stepper */}
      <div className="soc-surface p-6 border border-slate-200/90 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-extrabold text-slate-900">
            Propagated Kill-Chain Attack Flow
          </h3>
          <span className="text-[10px] font-mono font-bold text-violet-700 bg-violet-50 px-2.5 py-0.5 rounded-lg border border-violet-200">
            CROSS-LAYER PROPAGATION
          </span>
        </div>

        <div className="flex flex-wrap items-center justify-around gap-4 pt-2">
          {nodes.map((node, i) => (
            <React.Fragment key={node.id || i}>
              <div
                onClick={() => onOpenEntity && onOpenEntity({ id: node.id, label: node.label, type: node.type, risk_score: threatScore, status: node.status, layer: node.layer })}
                className="p-4 rounded-xl bg-white border border-slate-200/90 hover:border-violet-300 cursor-pointer text-center space-y-1.5 min-w-[135px] shadow-2xs transition hover-lift group"
              >
                <div className="p-2 rounded-lg bg-slate-50 mx-auto w-fit border border-slate-200 group-hover:scale-110 transition">
                  {node.type === 'user' ? (
                    <User className="w-5 h-5 text-violet-600" />
                  ) : node.type === 'destination' ? (
                    <Globe className="w-5 h-5 text-cyan-600" />
                  ) : node.type === 'process' ? (
                    <Terminal className="w-5 h-5 text-amber-600" />
                  ) : (
                    <Monitor className="w-5 h-5 text-blue-600" />
                  )}
                </div>
                <p className="text-xs font-bold text-slate-900 font-mono truncate max-w-[130px] group-hover:text-blue-600 transition">
                  {node.label}
                </p>
                <span className="text-[10px] text-slate-500 block uppercase font-mono font-bold">
                  {node.layer || node.type}
                </span>
                <span className={`${node.status === 'compromised' ? 'badge-critical' : 'badge-warning'} px-2 py-0.5 text-[9px] font-mono font-extrabold rounded-md uppercase`}>
                  {node.status?.toUpperCase() || 'OBSERVED'}
                </span>
              </div>
              {i < nodes.length - 1 && (
                <div className="flex flex-col items-center">
                  <ArrowRight className="w-5 h-5 text-slate-400 shrink-0 animate-pulse" />
                  <span className="text-[9px] font-mono text-slate-400 font-semibold mt-0.5">pivots</span>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Main Grid: Interactive Attack Graph + Correlation Rationale */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7">
          <AttackGraph incident={activeIncident} />
        </div>

        {/* Human Readable Correlation & Explainability Breakdown */}
        <div className="lg:col-span-5 soc-surface p-6 border border-slate-200/90 space-y-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <h3 className="text-sm font-extrabold text-slate-900">Topology Risk Rationale</h3>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700 font-semibold">+ Heuristic Rule Pattern Match</span>
              <span className="text-amber-700 font-extrabold">+{rb.rule_score || 40} pts</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700 font-semibold">+ ML Outlier Detection (IsoForest)</span>
              <span className="text-violet-700 font-extrabold">+{rb.ml_score || 30} pts</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700 font-semibold">+ Cross-Layer Signal Agreement</span>
              <span className="text-cyan-700 font-extrabold">+{rb.agreement_bonus || 20} pts</span>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 flex justify-between items-center text-xs font-bold text-rose-900 shadow-2xs">
              <span>Combined Incident Threat Score</span>
              <span className="text-sm">{threatScore} / 100 ({activeIncident?.risk_band || 'CRITICAL'})</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 leading-relaxed font-sans space-y-1">
            <strong className="font-mono text-slate-900 block text-xs">Explainability Engine Verdict:</strong>
            <p>{activeIncident?.explanation || 'Correlated security telemetry indicates cross-layer threat progression across observed network, host agent, and authentication signals.'}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
