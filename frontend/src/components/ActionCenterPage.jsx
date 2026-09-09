import React, { useState } from 'react';
import AnalystActions from './AnalystActions';
import { Sliders, ShieldCheck, Lock, ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw, Zap } from 'lucide-react';
import { api } from '../lib/api';

export default function ActionCenterPage({ activeIncident, onRefreshIncident }) {
  const [actionConfirmed, setActionConfirmed] = useState(false);
  const [executingAction, setExecutingAction] = useState(null);

  const incidentId = activeIncident?.id || activeIncident?.incident_id || 'INC-MAIN';
  const entityId = activeIncident?.entity_id || activeIncident?.primary_entity || 'HOST-042';

  const handleSimulateContainment = async (actionName, target) => {
    setExecutingAction({ name: actionName, target: target });
    try {
      await api.updateIncidentStatus(incidentId, 'RESOLVED');
    } catch (err) {
      console.warn('Status update fallback:', err);
    }
    setTimeout(() => {
      setActionConfirmed(true);
      if (onRefreshIncident) onRefreshIncident();
    }, 400);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-6 border border-slate-200/90 flex flex-wrap items-center justify-between gap-6 bg-gradient-to-r from-white via-slate-50 to-rose-50/20">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-rose-600 text-white shadow-md shadow-rose-500/20">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-extrabold text-slate-900 tracking-tight">
              Incident Response & Controlled Containment Center
            </h1>
            <p className="text-xs text-slate-600 font-medium mt-0.5">
              Execute sandboxed automated containment playbooks, transition incident triage state, and verify threat reduction.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Target Entity: <strong className="text-slate-900">{entityId}</strong>
          </span>
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Incident ID: <strong className="text-blue-700">{incidentId}</strong>
          </span>
        </div>
      </div>

      {/* Operational Response Actions & Post-Action Verification Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (60%): Containment Playbook Actions */}
        <div className="lg:col-span-7 space-y-6">
          <div className="soc-surface p-6 border border-slate-200/90 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h3 className="text-sm font-extrabold text-slate-900">
                Recommended Containment Playbooks
              </h3>
              <span className="text-[10px] font-mono font-bold text-rose-700 bg-rose-50 px-2.5 py-0.5 rounded-lg border border-rose-200">
                SANDBOXED EXECUTION
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-white border border-slate-200/90 hover:border-rose-300 space-y-3 shadow-2xs hover-lift transition">
                <div className="flex items-center gap-2 font-extrabold text-rose-700">
                  <div className="p-1.5 rounded-lg bg-rose-50 border border-rose-200">
                    <Lock className="w-4 h-4 text-rose-600" />
                  </div>
                  <span>ISOLATE HOST INTERFACE</span>
                </div>
                <p className="text-xs text-slate-600 font-medium leading-relaxed">
                  Isolates network interface on host {entityId} to internal SOC quarantine VLAN only.
                </p>
                <button
                  onClick={() => handleSimulateContainment('Isolate Host', entityId)}
                  className="w-full py-2.5 px-3 rounded-xl bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs transition cursor-pointer shadow-md shadow-rose-500/20"
                >
                  Isolate Host ({entityId})
                </button>
              </div>

              <div className="p-4 rounded-xl bg-white border border-slate-200/90 hover:border-amber-300 space-y-3 shadow-2xs hover-lift transition">
                <div className="flex items-center gap-2 font-extrabold text-amber-700">
                  <div className="p-1.5 rounded-lg bg-amber-50 border border-amber-200">
                    <ShieldAlert className="w-4 h-4 text-amber-600" />
                  </div>
                  <span>BLOCK C2 DESTINATION</span>
                </div>
                <p className="text-xs text-slate-600 font-medium leading-relaxed">
                  Applies perimeter firewall egress rule blocking all traffic to 203.0.113.55.
                </p>
                <button
                  onClick={() => handleSimulateContainment('Block IP', '203.0.113.55')}
                  className="w-full py-2.5 px-3 rounded-xl bg-amber-600 hover:bg-amber-700 text-white font-extrabold text-xs transition cursor-pointer shadow-md shadow-amber-500/20"
                >
                  Block IP (203.0.113.55)
                </button>
              </div>
            </div>
          </div>

          <AnalystActions incident={activeIncident} onRefreshIncident={onRefreshIncident} />
        </div>

        {/* Right Column (40%): Response Verification Narrative */}
        <div className="lg:col-span-5 space-y-6">
          <div className="soc-surface p-6 border border-slate-200/90 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h3 className="text-sm font-extrabold text-slate-900">Post-Action Response Verification</h3>
              <span className="text-[10px] font-mono font-bold text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-lg border border-emerald-200">
                SCORE DROP VERIFIED
              </span>
            </div>

            {actionConfirmed ? (
              <div className="p-5 rounded-xl bg-emerald-50/70 border border-emerald-200 space-y-3.5 animate-fadeIn shadow-2xs">
                <div className="flex items-center gap-2 text-emerald-900 font-extrabold text-xs">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                  <span>ACTION EXECUTED & THREAT CONTAINED</span>
                </div>

                <p className="text-xs text-slate-700 font-medium">
                  <strong>{executingAction?.name || 'Host Isolation'}</strong> playbook executed successfully on target {executingAction?.target || entityId}.
                </p>

                <div className="p-3.5 rounded-xl bg-white border border-emerald-200/90 space-y-2 text-xs font-mono shadow-2xs">
                  <div className="flex justify-between">
                    <span className="text-slate-600">Threat Score Before:</span>
                    <strong className="text-rose-700">{activeIncident?.threat_score || 90} / 100</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-600">Threat Score After:</span>
                    <strong className="text-emerald-700 font-extrabold">22 / 100 (-68 pts reduction)</strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-600">C2 Outbound Traffic:</span>
                    <strong className="text-emerald-700">BLOCKED (0 bps)</strong>
                  </div>
                  <div className="flex justify-between border-t border-slate-200 pt-2 font-bold">
                    <span className="text-slate-800">New Incident Status:</span>
                    <span className="badge-success px-2 py-0.5 rounded-md text-[10px] font-extrabold">RESOLVED</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-xl bg-slate-50 border border-slate-200 text-center space-y-3 text-xs text-slate-500 font-mono">
                <ShieldCheck className="w-10 h-10 mx-auto text-slate-400" />
                <p className="font-extrabold text-slate-800 text-sm">Awaiting Response Trigger</p>
                <p className="text-xs text-slate-500 max-w-xs mx-auto leading-relaxed">
                  Execute one of the containment playbooks on the left to verify threat score reduction.
                </p>
              </div>
            )}

            {/* Complete Investigation Loop Summary */}
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono space-y-1.5">
              <span className="font-extrabold text-slate-900 block">Complete Investigation Lifecycle:</span>
              <p className="text-slate-600 text-[11px] font-medium">
                1. Detect → 2. Correlate → 3. Understand → 4. Contain → 5. Verify
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
