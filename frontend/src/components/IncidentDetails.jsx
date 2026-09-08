import React from 'react';
import { Cpu, Calculator, FileText, AlertCircle } from 'lucide-react';

export default function IncidentDetails({ incident }) {
  if (!incident || !incident.risk_breakdown) {
    return (
      <div className="soc-surface rounded-2xl p-6 border border-[#D9E0E8] text-center text-slate-600">
        <Calculator className="w-10 h-10 mx-auto text-slate-400 mb-2" />
        <p className="text-xs">No active incident breakdown available.</p>
      </div>
    );
  }

  const rb = incident.risk_breakdown;
  const evidences = incident.evidences || [];

  return (
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] space-y-5">
      {/* Title */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Calculator className="w-5 h-5 text-blue-600" />
          <h2 className="text-sm font-bold text-slate-900">Explainable Risk Scoring Breakdown</h2>
        </div>
        <span className="text-xs font-mono font-bold badge-primary px-2.5 py-1 rounded-lg flex items-center space-x-1.5">
          <Cpu className="w-3.5 h-3.5" />
          <span>Transparent Math Formula</span>
        </span>
      </div>

      {/* Mathematical Breakdown Formula Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
          <span className="text-[10px] text-slate-500 font-semibold block uppercase">Evidence Score</span>
          <span className="text-lg font-bold font-mono text-blue-600">+{rb.evidence_score}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
          <span className="text-[10px] text-slate-500 font-semibold block uppercase">Cross-Layer Bonus</span>
          <span className="text-lg font-bold font-mono text-violet-600">+{rb.cross_layer_diversity_bonus}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
          <span className="text-[10px] text-slate-500 font-semibold block uppercase">Sequence Strength</span>
          <span className="text-lg font-bold font-mono text-amber-700">+{rb.temporal_sequence_score}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
          <span className="text-[10px] text-slate-500 font-semibold block uppercase">Asset Criticality</span>
          <span className="text-lg font-bold font-mono text-rose-700">+{rb.asset_criticality_boost}</span>
        </div>

        <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center col-span-2 sm:col-span-1">
          <span className="text-[10px] text-slate-500 font-semibold block uppercase">Benign Adjustment</span>
          <span className="text-lg font-bold font-mono text-emerald-700">-{rb.benign_context_adjustment}</span>
        </div>
      </div>

      {/* Formula Explanation Banner */}
      <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700 leading-relaxed">
        <span className="text-blue-600 font-bold mb-1 flex items-center space-x-1.5">
          <FileText className="w-3.5 h-3.5" />
          <span>Score Calculation Equation:</span>
        </span>
        {rb.formula_explanation}
      </div>

      {/* Evidence Table */}
      <div>
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-2 flex items-center justify-between">
          <span>Contributing Signals & Evidence ({evidences.length})</span>
          <span className="text-[10px] text-slate-500 lowercase font-normal">Ranked by contribution</span>
        </h3>

        <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
          {evidences.map((ev, idx) => (
            <div
              key={ev.event.event_id || idx}
              className="p-3 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition flex items-center justify-between gap-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                    ev.event.layer === 'identity' ? 'bg-violet-50 text-violet-700 border-violet-200' :
                    ev.event.layer === 'endpoint' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                    'bg-blue-50 text-blue-700 border-blue-200'
                  }`}>
                    {ev.event.layer}
                  </span>
                  <span className="font-bold text-slate-900">{ev.event.attack_type || ev.event.action}</span>
                  {ev.rule_name && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-50 text-rose-700 border border-rose-200 flex items-center space-x-1">
                      <AlertCircle className="w-2.5 h-2.5" />
                      <span>Rule Hit</span>
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-600 truncate max-w-[340px]">
                  Action: {ev.event.action} | Confidence: {(ev.event.confidence_score * 100).toFixed(0)}%
                </p>
              </div>

              <div className="text-right">
                <span className="text-sm font-bold font-mono text-blue-600 block">+{ev.contribution_score} pts</span>
                <span className="text-[10px] font-mono text-slate-500">{ev.event.timestamp.substring(11, 19)}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
