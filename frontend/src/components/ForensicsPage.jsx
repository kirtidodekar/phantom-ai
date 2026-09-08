import React, { useState } from 'react';
import BaselineDiff from './BaselineDiff';
import { GitCompare, Terminal, AlertTriangle, FileText, CheckCircle2, ChevronDown, ChevronUp } from 'lucide-react';

export default function ForensicsPage({ activeIncident }) {
  const [evidenceOpen, setEvidenceOpen] = useState(true);

  const evidenceTable = [
    { time: '10:41:05', entity: 'USER-ADMIN01', event: 'Authentication', signal: 'Geo Velocity', val: 'Untrusted ASN (198.51.100.88)', dev: '+14 Failed Tokens' },
    { time: '10:43:22', entity: 'HOST-042', event: 'Process Spawn', signal: 'Parent Execution', val: 'w3wp.exe → cmd.exe', dev: 'Encrypted PowerShell' },
    { time: '10:46:10', entity: 'HOST-042', event: 'Persistence', signal: 'Schtasks Creation', val: 'schtasks /create /tn Updates', dev: 'Reboot Trigger' },
    { time: '10:48:40', entity: '198.51.100.99', event: 'Network Exfil', signal: 'Outbound Traffic', val: '14.8 MB POST Payload', dev: 'Rare IP Target' }
  ];

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
            <GitCompare className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900">Forensic Analysis: What Changed?</h1>
            <p className="text-xs text-slate-600">
              Comparative counterfactual analysis contrasting live anomalous signals directly against historical normal baselines.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-500">Target Host: <strong className="text-slate-900">{activeIncident?.primary_entity || "HOST-042"}</strong></span>
        </div>
      </div>

      {/* Split Comparison View: Normal vs Current Anomalous State */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="soc-surface p-5 border border-slate-200 bg-emerald-50/40 space-y-3">
          <div className="flex items-center justify-between border-b border-emerald-200 pb-2">
            <span className="text-xs font-bold text-emerald-800 uppercase flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>Learned Normal Baseline State</span>
            </span>
            <span className="text-[10px] font-mono text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded">HISTORICAL</span>
          </div>

          <ul className="text-xs space-y-2 font-mono text-slate-700">
            <li className="p-2 rounded bg-white border border-emerald-200 flex justify-between">
              <span>Authentication Origin:</span>
              <strong className="text-slate-900">Known Internal LAN (10.0.0.0/8)</strong>
            </li>
            <li className="p-2 rounded bg-white border border-emerald-200 flex justify-between">
              <span>Process Execution:</span>
              <strong className="text-slate-900">Standard Explorer / Chrome</strong>
            </li>
            <li className="p-2 rounded bg-white border border-emerald-200 flex justify-between">
              <span>Network Destination:</span>
              <strong className="text-slate-900">Internal Domain Controller</strong>
            </li>
            <li className="p-2 rounded bg-white border border-emerald-200 flex justify-between">
              <span>System Resource CPU:</span>
              <strong className="text-slate-900">4.2% Normal Load</strong>
            </li>
          </ul>
        </div>

        <div className="soc-surface p-5 border border-rose-200 bg-rose-50/40 space-y-3">
          <div className="flex items-center justify-between border-b border-rose-200 pb-2">
            <span className="text-xs font-bold text-rose-800 uppercase flex items-center space-x-1.5">
              <AlertTriangle className="w-4 h-4 text-rose-600" />
              <span>Current Evolving Threat State</span>
            </span>
            <span className="text-[10px] font-mono text-rose-700 bg-rose-100 px-2 py-0.5 rounded">ANOMALOUS</span>
          </div>

          <ul className="text-xs space-y-2 font-mono text-slate-700">
            <li className="p-2 rounded bg-white border border-rose-200 flex justify-between text-rose-900 font-bold">
              <span>Authentication Origin:</span>
              <span>Untrusted External ASN (198.51.100.88)</span>
            </li>
            <li className="p-2 rounded bg-white border border-rose-200 flex justify-between text-rose-900 font-bold">
              <span>Process Execution:</span>
              <span>cmd.exe → powershell.exe -enc</span>
            </li>
            <li className="p-2 rounded bg-white border border-rose-200 flex justify-between text-rose-900 font-bold">
              <span>Network Destination:</span>
              <span>External C2 Target (198.51.100.99)</span>
            </li>
            <li className="p-2 rounded bg-white border border-rose-200 flex justify-between text-rose-900 font-bold">
              <span>System Resource CPU:</span>
              <span>+34% Process Spike Load</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Main Counterfactual Diff Component */}
      <BaselineDiff incidentId={activeIncident?.incident_id} />

      {/* Collapsible Structured Raw Evidence Telemetry Table */}
      <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3">
        <div
          onClick={() => setEvidenceOpen(!evidenceOpen)}
          className="flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-bold text-slate-900">Structured Forensic Evidence Telemetry</h3>
          </div>
          {evidenceOpen ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
        </div>

        {evidenceOpen && (
          <div className="overflow-x-auto pt-2">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-slate-500 font-bold uppercase text-[10px]">
                  <th className="py-2 px-3">Timestamp</th>
                  <th className="py-2 px-3">Entity</th>
                  <th className="py-2 px-3">Event Type</th>
                  <th className="py-2 px-3">Signal</th>
                  <th className="py-2 px-3">Observed Value</th>
                  <th className="py-2 px-3">Baseline Deviation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {evidenceTable.map((row, i) => (
                  <tr key={i} className="hover:bg-slate-50/80 transition">
                    <td className="py-2.5 px-3 font-bold text-slate-900">{row.time}</td>
                    <td className="py-2.5 px-3 text-blue-700 font-bold">{row.entity}</td>
                    <td className="py-2.5 px-3 text-slate-800">{row.event}</td>
                    <td className="py-2.5 px-3 text-slate-600">{row.signal}</td>
                    <td className="py-2.5 px-3 text-slate-800 truncate max-w-[200px]">{row.val}</td>
                    <td className="py-2.5 px-3 text-rose-700 font-bold">{row.dev}</td>
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
