import React, { useEffect, useState } from 'react';
import { GitCompare, ArrowRight, ShieldCheck, AlertOctagon } from 'lucide-react';

export default function BaselineDiff({ incidentId }) {
  const [diffData, setDiffData] = useState(null);

  useEffect(() => {
    if (!incidentId) return;
    fetch(`/api/baseline/diff/${incidentId}`)
      .then(res => res.json())
      .then(data => setDiffData(data))
      .catch(err => console.error("Error fetching baseline diff:", err));
  }, [incidentId]);

  if (!diffData) return null;

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl space-y-4">
      <div className="flex items-center space-x-2">
        <GitCompare className="w-5 h-5 text-amber-400" />
        <h2 className="text-base font-semibold text-slate-100">Counterfactual "What Changed?" Diff</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Baseline State */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
            <ShieldCheck className="w-4 h-4" />
            <span>Learned Normal Behavioral Baseline</span>
          </div>
          <ul className="text-xs text-slate-300 space-y-1.5 font-mono">
            <li>Failed Logins: <span className="text-slate-400">{diffData.baseline_state.failed_login_rate}</span></li>
            <li>Ingress Request Rate: <span className="text-slate-400">{diffData.baseline_state.request_rate}</span></li>
            <li>Process Execution: <span className="text-slate-400">{diffData.baseline_state.process_execution}</span></li>
            <li>Network Target: <span className="text-slate-400">{diffData.baseline_state.network_destination}</span></li>
          </ul>
        </div>

        {/* Current Anomalous State */}
        <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-2">
          <div className="flex items-center space-x-2 text-rose-400 font-bold text-xs">
            <AlertOctagon className="w-4 h-4" />
            <span>Current Evolving Threat State</span>
          </div>
          <ul className="text-xs text-slate-200 space-y-1.5 font-mono">
            <li>Failed Logins: <span className="text-rose-300 font-bold">{diffData.current_anomalous_state.failed_login_rate}</span></li>
            <li>Ingress Request Rate: <span className="text-amber-300 font-bold">{diffData.current_anomalous_state.request_rate}</span></li>
            <li>Process Execution: <span className="text-rose-300 font-bold">{diffData.current_anomalous_state.process_execution}</span></li>
            <li>Network Target: <span className="text-rose-300 font-bold">{diffData.current_anomalous_state.network_destination}</span></li>
          </ul>
        </div>
      </div>

      {/* Key Anomaly Deltas */}
      <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-1">
        <span className="font-bold text-amber-400 block">Critical Behavioral Deviations:</span>
        <ul className="list-disc list-inside text-slate-300 space-y-0.5">
          {diffData.deltas.map((delta, i) => (
            <li key={i}>{delta}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
