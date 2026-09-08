import React from 'react';
import { Cpu, Calculator, ShieldAlert, FileText, CheckCircle2, AlertCircle } from 'lucide-react';

export default function IncidentDetails({ incident }) {
  if (!incident || !incident.risk_breakdown) {
    return (
      <div className="glass-card rounded-2xl p-6 text-center text-slate-400">
        <Calculator className="w-10 h-10 mx-auto text-slate-600 mb-2" />
        <p>No active incident breakdown available.</p>
      </div>
    );
  }

  const rb = incident.risk_breakdown;
  const evidences = incident.evidences || [];

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl space-y-5">
      {/* Title */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Calculator className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100">Explainable Risk Scoring Breakdown</h2>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-lg border border-cyan-500/30">
          Transparent Math Formula
        </span>
      </div>

      {/* Mathematical Breakdown Formula Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 font-semibold block uppercase">Evidence Score</span>
          <span className="text-lg font-bold text-cyan-400">+{rb.evidence_score}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 font-semibold block uppercase">Cross-Layer Bonus</span>
          <span className="text-lg font-bold text-purple-400">+{rb.cross_layer_diversity_bonus}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 font-semibold block uppercase">Sequence Strength</span>
          <span className="text-lg font-bold text-amber-400">+{rb.temporal_sequence_score}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 font-semibold block uppercase">Asset Criticality</span>
          <span className="text-lg font-bold text-indigo-400">+{rb.asset_criticality_boost}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center col-span-2 sm:col-span-1">
          <span className="text-[10px] text-slate-400 font-semibold block uppercase">Benign Adjustment</span>
          <span className="text-lg font-bold text-emerald-400">-{rb.benign_context_adjustment}</span>
        </div>
      </div>

      {/* Formula Explanation Banner */}
      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs font-mono text-slate-300 leading-relaxed">
        <span className="text-cyan-400 font-bold block mb-1">Score Calculation Equation:</span>
        {rb.formula_explanation}
      </div>

      {/* Evidence Table */}
      <div>
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center justify-between">
          <span>Contributing Signals & Evidence ({evidences.length})</span>
          <span className="text-[10px] text-slate-500 lowercase font-normal">Ranked by contribution</span>
        </h3>

        <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
          {evidences.map((ev, idx) => (
            <div
              key={ev.event.event_id || idx}
              className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition flex items-center justify-between gap-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ev.event.layer === 'identity' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' :
                    ev.event.layer === 'endpoint' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                    'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  }`}>
                    {ev.event.layer}
                  </span>
                  <span className="font-bold text-slate-200">{ev.event.attack_type || ev.event.action}</span>
                  {ev.rule_name && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] bg-rose-500/10 text-rose-300 border border-rose-500/30">
                      Rule Hit
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 truncate max-w-[340px]">
                  Action: {ev.event.action} | Confidence: {(ev.event.confidence_score * 100).toFixed(0)}%
                </p>
              </div>

              <div className="text-right">
                <span className="text-sm font-bold text-cyan-400 block">+{ev.contribution_score} pts</span>
                <span className="text-[10px] font-mono text-slate-500">{ev.event.timestamp.substring(11, 19)}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
