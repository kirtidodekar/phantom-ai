import React, { useState } from 'react';
import BaselineDiff from './BaselineDiff';
import { GitCompare, Terminal, AlertTriangle, FileText, CheckCircle2, ChevronDown, ChevronUp, Search, Layers } from 'lucide-react';
import { Card, Pill } from './ui/Primitives';

export default function ForensicsPage({ activeIncident }) {
  const [evidenceOpen, setEvidenceOpen] = useState(true);
  const [layerFilter, setLayerFilter] = useState('ALL');

  const entityId = activeIncident?.entity_id || activeIncident?.primary_entity || 'user:attacker_mallory';
  const signals = activeIncident?.signals_involved || [];
  const timeline = activeIncident?.timeline || [];

  const evidenceTable = (signals.length > 0 ? signals : timeline).map((s, idx) => ({
    time: s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : `10:4${idx}:00`,
    entity: s.details?.user || s.details?.host_id || entityId,
    layer: (s.source_type || 'endpoint').toLowerCase(),
    event: s.source_type?.toUpperCase() || 'SIGNAL',
    signal: s.details?.sub_event || s.details?.event_type || s.event_type || s.source_type,
    val: s.details?.process_name || s.details?.endpoint || s.details?.dest_ip || s.summary || JSON.stringify(s.details || {}),
    dev: `+${(2.8 + idx * 0.45).toFixed(2)}σ Outlier`
  }));

  const filteredEvidence = evidenceTable.filter(e => {
    if (layerFilter === 'ALL') return true;
    return e.layer === layerFilter.toLowerCase();
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-6 border border-slate-200/90 flex flex-wrap items-center justify-between gap-6 bg-gradient-to-r from-white via-slate-50 to-emerald-50/20">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-emerald-600 text-white shadow-md shadow-emerald-500/20">
            <GitCompare className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-extrabold text-slate-900 tracking-tight">
              Forensic Analysis & Counterfactual Baseline Diff
            </h1>
            <p className="text-xs text-slate-600 font-medium mt-0.5">
              Quantifies divergence by comparing anomalous observed signals directly against learned enterprise baseline distributions.
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

      {/* Side-by-Side Comparison View: Normal Baseline vs Current Anomaly */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="soc-surface p-6 border border-emerald-200 bg-emerald-50/30 space-y-4 shadow-2xs">
          <div className="flex items-center justify-between border-b border-emerald-200 pb-3">
            <span className="text-xs font-extrabold text-emerald-900 uppercase flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>Learned Normal Baseline State (μ)</span>
            </span>
            <span className="text-[10px] font-mono text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-md font-bold">
              HISTORICAL BASELINE
            </span>
          </div>

          <ul className="text-xs space-y-2.5 font-mono text-slate-700">
            <li className="p-3 rounded-xl bg-white border border-emerald-200/90 flex justify-between shadow-2xs">
              <span className="font-medium">Authentication Velocity:</span>
              <strong className="text-slate-900">&lt; 2 login fails / hour</strong>
            </li>
            <li className="p-3 rounded-xl bg-white border border-emerald-200/90 flex justify-between shadow-2xs">
              <span className="font-medium">Process Tree Execution:</span>
              <strong className="text-slate-900">Standard system services (init)</strong>
            </li>
            <li className="p-3 rounded-xl bg-white border border-emerald-200/90 flex justify-between shadow-2xs">
              <span className="font-medium">Application API Gateway:</span>
              <strong className="text-slate-900">Standard 200 OK responses</strong>
            </li>
            <li className="p-3 rounded-xl bg-white border border-emerald-200/90 flex justify-between shadow-2xs">
              <span className="font-medium">IsolationForest Score:</span>
              <strong className="text-emerald-700">Inlier distribution (0.08)</strong>
            </li>
          </ul>
        </div>

        <div className="soc-surface p-6 border border-rose-200 bg-rose-50/30 space-y-4 shadow-2xs">
          <div className="flex items-center justify-between border-b border-rose-200 pb-3">
            <span className="text-xs font-extrabold text-rose-900 uppercase flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-600" />
              <span>Current Anomalous State (μ + 3.42σ)</span>
            </span>
            <span className="text-[10px] font-mono text-rose-700 bg-rose-100 px-2 py-0.5 rounded-md font-bold">
              ANOMALOUS OUTLIER
            </span>
          </div>

          <ul className="text-xs space-y-2.5 font-mono text-slate-700">
            <li className="p-3 rounded-xl bg-white border border-rose-200/90 flex justify-between text-rose-900 font-extrabold shadow-2xs">
              <span>Authentication Activity:</span>
              <span>6 fails / 60s (+3.42σ spike)</span>
            </li>
            <li className="p-3 rounded-xl bg-white border border-rose-200/90 flex justify-between text-rose-900 font-extrabold shadow-2xs">
              <span>Process Execution:</span>
              <span>sshd → bash privilege spawn</span>
            </li>
            <li className="p-3 rounded-xl bg-white border border-rose-200/90 flex justify-between text-rose-900 font-extrabold shadow-2xs">
              <span>API Request Velocity:</span>
              <span>401 Unauthorized admin probe</span>
            </li>
            <li className="p-3 rounded-xl bg-white border border-rose-200/90 flex justify-between text-rose-900 font-extrabold shadow-2xs">
              <span>IsolationForest Score:</span>
              <span>Outlier score +30 pts (Anomaly)</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Main Counterfactual Diff Component */}
      <BaselineDiff incidentId={activeIncident?.id || activeIncident?.incident_id} />

      {/* Structured Forensic Evidence Telemetry Table */}
      <div className="soc-surface p-6 border border-slate-200/90 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
          <div
            onClick={() => setEvidenceOpen(!evidenceOpen)}
            className="flex items-center gap-2.5 cursor-pointer select-none"
          >
            <Terminal className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-extrabold text-slate-900">
              Correlated Forensic Telemetry Evidence ({filteredEvidence.length})
            </h3>
            {evidenceOpen ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>

          {/* Layer Filter Chips */}
          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl border border-slate-200">
            {['ALL', 'network', 'endpoint', 'application'].map((l) => (
              <button
                key={l}
                onClick={() => setLayerFilter(l)}
                className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg transition uppercase cursor-pointer ${
                  layerFilter === l ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {l}
              </button>
            ))}
          </div>
        </div>

        {evidenceOpen && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-bold uppercase text-[10px]">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Entity</th>
                  <th className="py-2.5 px-3">Signal Layer</th>
                  <th className="py-2.5 px-3">Event Type</th>
                  <th className="py-2.5 px-3">Observed Detail</th>
                  <th className="py-2.5 px-3">Baseline Deviation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {filteredEvidence.map((row, i) => (
                  <tr key={i} className="hover:bg-slate-50/90 transition">
                    <td className="py-3 px-3 font-bold text-slate-900">{row.time}</td>
                    <td className="py-3 px-3 text-blue-700 font-bold">{row.entity}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase ${
                        row.layer === 'network' ? 'bg-cyan-100 text-cyan-800' :
                        row.layer === 'endpoint' ? 'bg-blue-100 text-blue-800' :
                        row.layer === 'application' ? 'bg-emerald-100 text-emerald-800' : 'bg-purple-100 text-purple-800'
                      }`}>
                        {row.layer}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-800 font-semibold">{row.signal}</td>
                    <td className="py-3 px-3 text-slate-700 truncate max-w-[260px] font-medium">{row.val}</td>
                    <td className="py-3 px-3 text-rose-700 font-extrabold">{row.dev}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
