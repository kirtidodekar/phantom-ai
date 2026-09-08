import React from 'react';
import { X, ShieldAlert, Monitor, User, Terminal, Globe, ArrowRight, Activity, AlertTriangle } from 'lucide-react';

export default function EntityDrawer({ isOpen, onClose, entityData, onNavigateTab }) {
  if (!isOpen || !entityData) return null;

  const {
    id = "HOST-042",
    label = "WKS-042.internal.corp",
    type = "host",
    risk_score = 87,
    status = "compromised",
    layer = "endpoint"
  } = entityData;

  const getNodeIcon = (t) => {
    switch (t) {
      case 'user': return <User className="w-5 h-5 text-purple-600" />;
      case 'host': return <Monitor className="w-5 h-5 text-blue-600" />;
      case 'process': return <Terminal className="w-5 h-5 text-amber-600" />;
      case 'destination': return <Globe className="w-5 h-5 text-rose-600" />;
      default: return <Activity className="w-5 h-5 text-slate-600" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs animate-fadeIn">
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-white border-l border-slate-200 shadow-2xl flex flex-col justify-between">
          {/* Drawer Header */}
          <div className="p-5 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs">
                {getNodeIcon(type)}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-base font-bold text-slate-900 font-mono">{id}</h3>
                  <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded ${
                    status === 'compromised' ? 'badge-critical' : 'badge-warning'
                  }`}>
                    {status}
                  </span>
                </div>
                <p className="text-xs text-slate-500 truncate max-w-[220px]">{label}</p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
            {/* Risk Overview Card */}
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
              <div>
                <span className="text-[11px] font-semibold text-slate-500 uppercase block">Entity Risk Score</span>
                <span className="text-2xl font-extrabold font-mono text-slate-900">{risk_score}/100</span>
              </div>
              <div className="text-right font-mono">
                <span className="text-[11px] text-slate-500 block uppercase">Layer</span>
                <span className="font-semibold text-slate-800 uppercase">{layer}</span>
              </div>
            </div>

            {/* Why Flagged Section */}
            <div className="space-y-2">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-[11px]">Why Sentinel Flagged It</h4>
              <ul className="space-y-1.5">
                <li className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>Encoded PowerShell process spawned from webserver parent process.</span>
                </li>
                <li className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 flex items-start space-x-2">
                  <Activity className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <span>Outbound connection request to unverified external IP (198.51.100.99).</span>
                </li>
                <li className="p-2.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-800 flex items-start space-x-2">
                  <ShieldAlert className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                  <span>Off-hours service login from untrusted geographic origin.</span>
                </li>
              </ul>
            </div>

            {/* Related Events Timeline */}
            <div className="space-y-2">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-[11px]">Recent Telemetry Hits</h4>
              <div className="space-y-2 font-mono">
                <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-slate-800 block">10:48 — C2 Data Exfiltration</span>
                    <span className="text-slate-500 text-[10px]">Destination: 198.51.100.99</span>
                  </div>
                  <span className="badge-critical px-1.5 py-0.5 text-[10px]">96% CONF</span>
                </div>

                <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-slate-800 block">10:43 — PowerShell Spawned</span>
                    <span className="text-slate-500 text-[10px]">Parent: w3wp.exe</span>
                  </div>
                  <span className="badge-warning px-1.5 py-0.5 text-[10px]">84% CONF</span>
                </div>

                <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-slate-800 block">10:41 — Off-Hours Login</span>
                    <span className="text-slate-500 text-[10px]">User: admin_service</span>
                  </div>
                  <span className="badge-primary px-1.5 py-0.5 text-[10px]">72% CONF</span>
                </div>
              </div>
            </div>
          </div>

          {/* Drawer Footer Actions */}
          <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center space-x-2">
            <button
              onClick={() => {
                if (onNavigateTab) onNavigateTab('forensics');
                onClose();
              }}
              className="flex-1 py-2 px-3 rounded-lg bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 font-semibold text-xs text-center transition"
            >
              Open in Forensics
            </button>
            <button
              onClick={() => {
                if (onNavigateTab) onNavigateTab('actions');
                onClose();
              }}
              className="flex-1 py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs text-center transition shadow-xs"
            >
              Contain Entity
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
