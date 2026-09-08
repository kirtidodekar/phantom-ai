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

  if (!diffData) {
    return (
      <div className="soc-surface rounded-2xl p-6 border border-[#D9E0E8] text-center text-slate-500 font-mono text-xs">
        <GitCompare className="w-8 h-8 mx-auto text-slate-400 mb-2 animate-pulse" />
        <p>Loading counterfactual baseline diff...</p>
      </div>
    );
  }

  return (
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] space-y-4">
      <div className="flex items-center space-x-2">
        <GitCompare className="w-5 h-5 text-amber-600" />
        <h2 className="text-sm font-bold text-slate-900">Counterfactual "What Changed?" Diff</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Baseline State */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
          <div className="flex items-center space-x-2 text-emerald-700 font-bold text-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span>Learned Normal Behavioral Baseline</span>
          </div>
          <ul className="text-xs text-slate-700 space-y-1.5 font-mono">
            <li>Failed Logins: <span className="text-slate-500">{diffData.baseline_state?.failed_login_rate || "0.0%"}</span></li>
            <li>Ingress Request Rate: <span className="text-slate-500">{diffData.baseline_state?.request_rate || "2.1 req/s"}</span></li>
            <li>Process Execution: <span className="text-slate-500">{diffData.baseline_state?.process_execution || "Standard"}</span></li>
            <li>Network Target: <span className="text-slate-500">{diffData.baseline_state?.network_destination || "Internal LAN"}</span></li>
          </ul>
        </div>

        {/* Current Anomalous State */}
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 space-y-2">
          <div className="flex items-center space-x-2 text-rose-700 font-bold text-xs">
            <AlertOctagon className="w-4 h-4 text-rose-600" />
            <span>Current Evolving Threat State</span>
          </div>
          <ul className="text-xs text-slate-700 space-y-1.5 font-mono">
            <li>Failed Logins: <span className="text-rose-700 font-bold">{diffData.current_anomalous_state?.failed_login_rate || "Brute Force"}</span></li>
            <li>Ingress Request Rate: <span className="text-amber-700 font-bold">{diffData.current_anomalous_state?.request_rate || "Spike"}</span></li>
            <li>Process Execution: <span className="text-rose-700 font-bold">{diffData.current_anomalous_state?.process_execution || "Suspicious PowerShell"}</span></li>
            <li>Network Target: <span className="text-rose-700 font-bold">{diffData.current_anomalous_state?.network_destination || "External C2 IP"}</span></li>
          </ul>
        </div>
      </div>

      {/* Key Anomaly Deltas */}
      <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-xs space-y-1">
        <span className="font-bold text-amber-700 flex items-center space-x-1.5">
          <ArrowRight className="w-3.5 h-3.5" />
          <span>Critical Behavioral Deviations:</span>
        </span>
        <ul className="list-disc list-inside text-slate-700 space-y-0.5">
          {diffData.deltas?.map((delta, i) => (
            <li key={i}>{delta}</li>
          )) || <li>No behavioral deltas recorded.</li>}
        </ul>
      </div>
    </div>
  );
}
