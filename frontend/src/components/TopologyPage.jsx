import React from 'react';
import AttackGraph from './AttackGraph';
import IncidentDetails from './IncidentDetails';
import { Network, Calculator, ShieldAlert, Cpu, User, Monitor, Terminal, Globe, ArrowRight, AlertTriangle } from 'lucide-react';

export default function TopologyPage({ activeIncident, onOpenEntity }) {
  const threatScore = activeIncident?.threat_score || 87;

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900">Attack Path & Entity Propagation</h1>
            <p className="text-xs text-slate-600">
              Interactive propagation flow mapping compromised accounts to host endpoints, child process trees, and external C2 targets.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-500">Click any node to view entity drawer</span>
        </div>
      </div>

      {/* Structured Attack Path Node Flow Bar */}
      <div className="soc-surface p-5 border border-[#D9E0E8] space-y-4">
        <h3 className="text-sm font-bold text-slate-900">Propagated Intrusion Path Flow</h3>

        <div className="flex flex-wrap items-center justify-around gap-3 pt-2">
          {/* Node 1: User */}
          <div
            onClick={() => onOpenEntity && onOpenEntity({ id: 'USER-ADMIN01', label: 'admin_service', type: 'user', risk_score: 74, status: 'suspicious', layer: 'identity' })}
            className="p-3.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer text-center space-y-1 min-w-[120px] shadow-xs transition"
          >
            <User className="w-5 h-5 mx-auto text-purple-600" />
            <p className="text-xs font-bold text-slate-900 font-mono">USER-ADMIN01</p>
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Identity</span>
            <span className="badge-warning px-1.5 py-0.5 text-[9px] font-mono font-bold">RISK 74</span>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-400 shrink-0" />

          {/* Node 2: Host */}
          <div
            onClick={() => onOpenEntity && onOpenEntity({ id: 'HOST-042', label: 'WKS-042.internal.corp', type: 'host', risk_score: 87, status: 'compromised', layer: 'endpoint' })}
            className="p-3.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer text-center space-y-1 min-w-[120px] shadow-xs transition"
          >
            <Monitor className="w-5 h-5 mx-auto text-blue-600" />
            <p className="text-xs font-bold text-slate-900 font-mono">HOST-042</p>
            <span className="text-[10px] text-slate-500 block uppercase font-mono">Endpoint</span>
            <span className="badge-critical px-1.5 py-0.5 text-[9px] font-mono font-bold">RISK 87</span>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-400 shrink-0" />

          {/* Node 3: Process */}
          <div
            onClick={() => onOpenEntity && onOpenEntity({ id: 'PROC-4912', label: 'powershell.exe -enc', type: 'process', risk_score: 89, status: 'compromised', layer: 'endpoint' })}
            className="p-3.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer text-center space-y-1 min-w-[120px] shadow-xs transition"
          >
            <Terminal className="w-5 h-5 mx-auto text-amber-600" />
            <p className="text-xs font-bold text-slate-900 font-mono">PID: 4912</p>
            <span className="text-[10px] text-slate-500 block uppercase font-mono">powershell.exe</span>
            <span className="badge-critical px-1.5 py-0.5 text-[9px] font-mono font-bold">RISK 89</span>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-400 shrink-0" />

          {/* Node 4: Network C2 */}
          <div
            onClick={() => onOpenEntity && onOpenEntity({ id: 'IP-198.51.100.99', label: 'C2 Exfiltration Target', type: 'destination', risk_score: 96, status: 'compromised', layer: 'network' })}
            className="p-3.5 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer text-center space-y-1 min-w-[120px] shadow-xs transition"
          >
            <Globe className="w-5 h-5 mx-auto text-rose-600" />
            <p className="text-xs font-bold text-slate-900 font-mono">198.51.100.99</p>
            <span className="text-[10px] text-slate-500 block uppercase font-mono">C2 Destination</span>
            <span className="badge-critical px-1.5 py-0.5 text-[9px] font-mono font-bold">RISK 96</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Attack Graph + Human Readable Risk Reasoning */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <AttackGraph incident={activeIncident} />
        
        {/* Human Readable Attack Path Explanation */}
        <div className="soc-surface p-5 border border-[#D9E0E8] space-y-4">
          <h3 className="text-sm font-bold text-slate-900">Why This Attack Path Is Risky</h3>
          
          <div className="space-y-2 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700">+ New authentication origin (Off-hours untrusted IP)</span>
              <span className="text-amber-700 font-bold">+25 pts</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700">+ Privileged service account targeted (admin_service)</span>
              <span className="text-purple-700 font-bold">+18 pts</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700">+ Encrypted PowerShell spawned from web server</span>
              <span className="text-rose-700 font-bold">+30 pts</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex justify-between items-center">
              <span className="text-slate-700">+ Rare external C2 destination (198.51.100.99)</span>
              <span className="text-rose-700 font-bold">+24 pts</span>
            </div>

            <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 flex justify-between items-center text-xs font-bold text-rose-900">
              <span>Combined Attack Path Threat Score</span>
              <span>87 / 100 (HIGH)</span>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 font-mono">
            <strong>Explainability Formula:</strong> Threat Score = Σ(Signal Weight × Confidence × Asset Criticality) - Context Adjustment
          </div>
        </div>
      </div>
    </div>
  );
}
