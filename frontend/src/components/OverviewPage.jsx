import React, { useState } from 'react';
import TrajectoryChart from './TrajectoryChart';
import { ShieldAlert, Activity, Server, AlertTriangle, Layers, ShieldCheck, Search, ArrowRight, User, Monitor, Terminal, Globe, CheckCircle2 } from 'lucide-react';

export default function OverviewPage({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  activeIncident,
  currentStage,
  onOpenEntity
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch = inc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          inc.incident_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          inc.primary_entity.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSev = severityFilter === 'ALL' ? true :
                       severityFilter === 'HIGH' ? inc.threat_score >= 80 :
                       severityFilter === 'MEDIUM' ? (inc.threat_score >= 60 && inc.threat_score < 80) :
                       inc.threat_score < 60;
    return matchesSearch && matchesSev;
  });

  const threatScore = activeIncident?.threat_score || 87;
  const threatLevel = activeIncident?.risk_breakdown?.risk_level || "CRITICAL";

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Section: Active Investigation Summary Bar */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="space-y-1">
          <div className="flex items-center space-x-3">
            <span className="font-mono text-sm font-bold text-slate-900">{activeIncident?.incident_id || "INC-2048"}</span>
            <span className={`px-2.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded ${
              threatScore >= 80 ? 'badge-critical' : threatScore >= 60 ? 'badge-warning' : 'badge-success'
            }`}>
              {threatLevel} ({threatScore}/100)
            </span>
            <span className="text-xs text-slate-500 font-medium hidden sm:inline">| Attack Phase: <strong className="text-slate-800">{currentStage || "Command & Control"}</strong></span>
          </div>
          <p className="text-xs text-slate-600">
            {activeIncident?.title || "Multi-stage cross-layer intrusion with unauthorized PowerShell execution & SQLi exfiltration."}
          </p>
        </div>

        {/* Compact Key Stats Metrics */}
        <div className="flex items-center space-x-6 text-xs font-mono">
          <div>
            <span className="text-[10px] text-slate-500 block uppercase">Entities Affected</span>
            <span className="font-bold text-slate-900 font-mono text-sm">12 Entities</span>
          </div>
          <div className="border-l border-slate-200 pl-6">
            <span className="text-[10px] text-slate-500 block uppercase">Correlated Signals</span>
            <span className="font-bold text-slate-900 font-mono text-sm">47 Signals</span>
          </div>
          <div className="border-l border-slate-200 pl-6">
            <span className="text-[10px] text-slate-500 block uppercase">Attack Stages</span>
            <span className="font-bold text-blue-600 font-mono text-sm">4 / 5 Stages</span>
          </div>
          <div className="border-l border-slate-200 pl-6">
            <span className="text-[10px] text-slate-500 block uppercase">Model Confidence</span>
            <span className="font-bold text-emerald-700 font-mono text-sm">91%</span>
          </div>
        </div>
      </div>

      {/* Main 2-Column Dashboard Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (65%): Trajectory Chart + Incident Sequence Timeline */}
        <div className="lg:col-span-8 space-y-5">
          <TrajectoryChart incident={activeIncident} />

          {/* Correlated Incident Timeline */}
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900">Correlated Attack Sequence Timeline</h3>
              <span className="text-xs font-mono text-slate-500">Real-time Telemetry Stream</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-[10px] text-purple-700 font-bold block">10:41 — AUTH</span>
                <span className="font-bold text-slate-800 block">Off-Hours Login</span>
                <span className="text-[10px] text-slate-500 block">User: admin_service</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-[10px] text-blue-700 font-bold block">10:43 — ENDPOINT</span>
                <span className="font-bold text-slate-800 block">PowerShell Spawn</span>
                <span className="text-[10px] text-slate-500 block">Host: WKS-042</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-[10px] text-amber-700 font-bold block">10:46 — EXECUTION</span>
                <span className="text-[10px] font-bold text-slate-800 block truncate">cmd.exe -enc</span>
                <span className="text-[10px] text-slate-500 block">PID: 4912</span>
              </div>

              <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 space-y-1">
                <span className="text-[10px] text-rose-700 font-bold block">10:48 — C2 NETWORK</span>
                <span className="font-bold text-rose-900 block">SQLi Exfiltration</span>
                <span className="text-[10px] text-rose-700 block">198.51.100.99</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (35%): Affected Entities + Why Sentinel Flagged It */}
        <div className="lg:col-span-4 space-y-5">
          {/* Why Sentinel Flagged It */}
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3">
            <h3 className="text-sm font-bold text-slate-900">Why Sentinel Flagged It</h3>
            <ul className="space-y-2 text-xs">
              <li className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-900 flex items-start space-x-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                <span>3 weak signals combined across Identity & Network layers.</span>
              </li>
              <li className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 flex items-start space-x-2">
                <Activity className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                <span>Historical behavioral deviation detected on host WKS-042.</span>
              </li>
              <li className="p-2.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 flex items-start space-x-2">
                <ShieldAlert className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <span>Unusual external destination target (198.51.100.99).</span>
              </li>
            </ul>
          </div>

          {/* Affected Entities List with Drawer Click Handlers */}
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900">Affected Key Entities</h3>
              <span className="text-[11px] text-slate-500 font-mono">Click for Side Drawer</span>
            </div>

            <div className="space-y-2 text-xs">
              <div
                onClick={() => onOpenEntity && onOpenEntity({ id: 'HOST-042', label: 'WKS-042.internal.corp', type: 'host', risk_score: 87, status: 'compromised', layer: 'endpoint' })}
                className="p-3 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer flex items-center justify-between transition shadow-xs"
              >
                <div className="flex items-center space-x-2.5">
                  <Monitor className="w-4 h-4 text-blue-600" />
                  <div>
                    <span className="font-bold text-slate-900 font-mono block">HOST-042</span>
                    <span className="text-[10px] text-slate-500 font-mono">WKS-042 (Windows OS)</span>
                  </div>
                </div>
                <span className="badge-critical px-2 py-0.5 text-[10px] font-mono">RISK 87</span>
              </div>

              <div
                onClick={() => onOpenEntity && onOpenEntity({ id: 'USER-ADMIN01', label: 'admin_service', type: 'user', risk_score: 74, status: 'suspicious', layer: 'identity' })}
                className="p-3 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer flex items-center justify-between transition shadow-xs"
              >
                <div className="flex items-center space-x-2.5">
                  <User className="w-4 h-4 text-purple-600" />
                  <div>
                    <span className="font-bold text-slate-900 font-mono block">USER-ADMIN01</span>
                    <span className="text-[10px] text-slate-500 font-mono">admin_service (Service Acc)</span>
                  </div>
                </div>
                <span className="badge-warning px-2 py-0.5 text-[10px] font-mono">RISK 74</span>
              </div>

              <div
                onClick={() => onOpenEntity && onOpenEntity({ id: 'IP-198.51.100.99', label: 'C2 Destination', type: 'destination', risk_score: 96, status: 'compromised', layer: 'network' })}
                className="p-3 rounded-lg bg-white border border-slate-200 hover:border-slate-300 cursor-pointer flex items-center justify-between transition shadow-xs"
              >
                <div className="flex items-center space-x-2.5">
                  <Globe className="w-4 h-4 text-rose-600" />
                  <div>
                    <span className="font-bold text-slate-900 font-mono block">198.51.100.99</span>
                    <span className="text-[10px] text-slate-500 font-mono">External C2 Server</span>
                  </div>
                </div>
                <span className="badge-critical px-2 py-0.5 text-[10px] font-mono">RISK 96</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
