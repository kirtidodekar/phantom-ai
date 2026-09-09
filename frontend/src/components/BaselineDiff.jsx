import React, { useState } from 'react';
import { GitCompare, ArrowRight, ShieldCheck, AlertOctagon, Sparkles } from 'lucide-react';
import { cn } from '../lib/cn';

export default function BaselineDiff({ incidentId }) {
  const [diffData] = useState({
    baseline_state: {
      failed_login_rate: '0.05 fails/min (Expected normal distribution)',
      request_rate: '12 req/min (Normal operational load)',
      process_execution: 'Standard system services (init / systemd)',
      network_destination: 'Internal LAN & Verified CDNs'
    },
    current_anomalous_state: {
      failed_login_rate: '6 fails / 60s (Outlier deviation +3.42σ)',
      request_rate: '148 req/min sudden spike (+1133%)',
      process_execution: 'sshd → bash privilege escalation spawn',
      network_destination: 'Untrusted external ASN (203.0.113.55)'
    },
    deltas: [
      'Failed authentication velocity exceeded threshold by 3.42 standard deviations (Z-score > 3.0)',
      'Host process execution violates learned parent-child binary execution graph',
      'Cross-layer fusion confirms application layer 401 unauthorized probe matching entity session'
    ]
  });

  return (
    <div className="soc-surface rounded-2xl p-6 border border-slate-200/90 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-200 pb-3">
        <div className="flex items-center gap-2">
          <GitCompare className="w-5 h-5 text-amber-600" />
          <h2 className="text-sm font-extrabold text-slate-900">Counterfactual Baseline vs Anomaly Diff</h2>
        </div>
        <span className="text-[10px] font-mono font-bold text-amber-700 bg-amber-50 px-2.5 py-0.5 rounded-lg border border-amber-200">
          Z-SCORE OUTLIER TEST
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Baseline State */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <div className="flex items-center gap-2 text-emerald-700 font-extrabold text-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span>Historical Normal Behavioral Baseline</span>
          </div>
          <ul className="text-xs text-slate-700 space-y-2 font-mono">
            <li className="flex justify-between p-1.5 rounded bg-white border border-slate-200">
              <span className="text-slate-500">Failed Logins:</span>
              <span className="font-bold text-slate-800">{diffData.baseline_state?.failed_login_rate}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-slate-200">
              <span className="text-slate-500">Request Rate:</span>
              <span className="font-bold text-slate-800">{diffData.baseline_state?.request_rate}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-slate-200">
              <span className="text-slate-500">Process Exec:</span>
              <span className="font-bold text-slate-800">{diffData.baseline_state?.process_execution}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-slate-200">
              <span className="text-slate-500">Network Target:</span>
              <span className="font-bold text-slate-800">{diffData.baseline_state?.network_destination}</span>
            </li>
          </ul>
        </div>

        {/* Current Anomalous State */}
        <div className="p-4 rounded-xl bg-rose-50/60 border border-rose-200 space-y-2.5">
          <div className="flex items-center gap-2 text-rose-700 font-extrabold text-xs">
            <AlertOctagon className="w-4 h-4 text-rose-600" />
            <span>Current Evolving Threat State (Outlier)</span>
          </div>
          <ul className="text-xs text-slate-700 space-y-2 font-mono">
            <li className="flex justify-between p-1.5 rounded bg-white border border-rose-200 text-rose-900 font-bold">
              <span>Failed Logins:</span>
              <span>{diffData.current_anomalous_state?.failed_login_rate}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-rose-200 text-amber-900 font-bold">
              <span>Request Rate:</span>
              <span>{diffData.current_anomalous_state?.request_rate}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-rose-200 text-rose-900 font-bold">
              <span>Process Exec:</span>
              <span>{diffData.current_anomalous_state?.process_execution}</span>
            </li>
            <li className="flex justify-between p-1.5 rounded bg-white border border-rose-200 text-rose-900 font-bold">
              <span>Network Target:</span>
              <span>{diffData.current_anomalous_state?.network_destination}</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Key Anomaly Deltas */}
      <div className="p-4 rounded-xl bg-amber-50/80 border border-amber-200 text-xs space-y-2 font-mono">
        <span className="font-bold text-amber-900 flex items-center gap-1.5">
          <ArrowRight className="w-3.5 h-3.5 text-amber-700" />
          <span>Statistically Significant Behavioral Deviations:</span>
        </span>
        <ul className="list-disc list-inside text-slate-700 space-y-1 text-xs">
          {diffData.deltas.map((delta, i) => (
            <li key={i} className="leading-relaxed">{delta}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
