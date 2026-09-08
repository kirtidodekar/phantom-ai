import React, { useState } from 'react';
import AnalystActions from './AnalystActions';
import { Sliders, ShieldCheck, Lock, ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';

export default function ActionCenterPage({ activeIncident, onRefreshIncident }) {
  const [actionConfirmed, setActionConfirmed] = useState(false);
  const [executingAction, setExecutingAction] = useState(null);

  const handleSimulateContainment = (actionName, target) => {
    setExecutingAction({ name: actionName, target: target });
    setTimeout(() => {
      setActionConfirmed(true);
      if (onRefreshIncident) onRefreshIncident();
    }, 600);
  };

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900">Response & Controlled Decision Center</h1>
            <p className="text-xs text-slate-600">
              Execute sandboxed automated containment playbooks, adjust asset criticality weights, and verify threat score reduction.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-500">Target Entity: <strong className="text-slate-900">{activeIncident?.primary_entity || "HOST-042"}</strong></span>
        </div>
      </div>

      {/* Operational Response Actions & Post-Action Verification Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (60%): Containment Playbook Actions */}
        <div className="lg:col-span-7 space-y-5">
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Recommended Containment Actions</h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-4 rounded-lg bg-white border border-slate-200 space-y-2">
                <div className="flex items-center space-x-2 font-bold text-rose-700">
                  <Lock className="w-4 h-4" />
                  <span>ISOLATE HOST</span>
                </div>
                <p className="text-[11px] text-slate-600">Restricts host network interface on HOST-042 to internal SOC VLAN only.</p>
                <button
                  onClick={() => handleSimulateContainment('Isolate Host', 'HOST-042')}
                  className="w-full py-2 px-3 rounded-md bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs transition"
                >
                  Isolate Host (HOST-042)
                </button>
              </div>

              <div className="p-4 rounded-lg bg-white border border-slate-200 space-y-2">
                <div className="flex items-center space-x-2 font-bold text-amber-700">
                  <ShieldAlert className="w-4 h-4" />
                  <span>BLOCK C2 DESTINATION</span>
                </div>
                <p className="text-[11px] text-slate-600">Applies egress firewall rule blocking outbound traffic to 198.51.100.99.</p>
                <button
                  onClick={() => handleSimulateContainment('Block IP', '198.51.100.99')}
                  className="w-full py-2 px-3 rounded-md bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs transition"
                >
                  Block IP (198.51.100.99)
                </button>
              </div>
            </div>
          </div>

          <AnalystActions incident={activeIncident} onRefreshIncident={onRefreshIncident} />
        </div>

        {/* Right Column (40%): Response Verification Narrative */}
        <div className="lg:col-span-5 space-y-5">
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Post-Action Response Verification</h3>

            {actionConfirmed ? (
              <div className="p-4 rounded-lg bg-emerald-50 border border-emerald-200 space-y-3 animate-fadeIn">
                <div className="flex items-center space-x-2 text-emerald-800 font-bold text-xs">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                  <span>ACTION EXECUTED & VERIFIED</span>
                </div>

                <p className="text-xs text-slate-700">
                  {executingAction?.name || "Host Isolation"} completed successfully for {executingAction?.target || "HOST-042"}.
                </p>

                <div className="p-3 rounded bg-white border border-emerald-200 space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-slate-600">Threat Score Before:</span>
                    <strong className="text-rose-700">87 / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-600">Threat Score After:</span>
                    <strong className="text-emerald-700">31 / 100 (-56 pts)</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-600">C2 Communication:</span>
                    <strong className="text-emerald-700">BLOCKED</strong>
                  </div>
                  <div className="flex justify-between border-t border-slate-200 pt-1 font-bold">
                    <span className="text-slate-800">Current Status:</span>
                    <span className="badge-success px-2 py-0.5 rounded text-[10px]">CONTAINED</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-lg bg-slate-50 border border-slate-200 text-center space-y-2 text-xs text-slate-500 font-mono">
                <ShieldCheck className="w-8 h-8 mx-auto text-slate-400" />
                <p className="font-bold text-slate-700">Awaiting Response Action</p>
                <p className="text-[11px] text-slate-500">Execute one of the containment playbooks on the left to verify threat score reduction.</p>
              </div>
            )}

            {/* Narrative Summary Flow */}
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono space-y-1">
              <span className="font-bold text-slate-800 block">Complete Investigation Story Loop:</span>
              <p className="text-slate-600 text-[11px]">
                Detect → Correlate → Understand → Act → Verify
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
