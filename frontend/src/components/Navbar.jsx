import React from 'react';
import {
  ShieldAlert, Play, SkipForward, RotateCcw,
  LayoutDashboard, Network, Target, GitCompare, Sliders, Cpu, ChevronDown, Home, UserCheck, Search
} from 'lucide-react';

export default function Navbar({
  activeTab,
  onTabChange,
  incidents,
  selectedIncidentId,
  onSelectIncident,
  onStartReplay,
  onStepReplay,
  onResetReplay,
  onOpenMetrics,
  isReplaying,
  currentStage,
  currentUser,
  onGoHome,
  onOpenAuth,
  threatScore = 87,
  threatLevel = "CRITICAL"
}) {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'topology', label: 'Attack Path', icon: Network, badge: activeIncidentLayersCount(incidents, selectedIncidentId) },
    { id: 'intel', label: 'Threat Story', icon: Target },
    { id: 'forensics', label: 'Forensics', icon: GitCompare },
    { id: 'actions', label: 'Response', icon: Sliders },
    { id: 'diagnostics', label: 'Model Health', icon: Cpu },
  ];

  function activeIncidentLayersCount(incList, currentId) {
    const found = incList.find(i => i.incident_id === currentId);
    return found?.layers_involved?.length || null;
  }

  const investigationSteps = [
    { label: "DETECT", desc: "Signal Ingestion", active: true },
    { label: "CORRELATE", desc: "Cross-Layer Fusion", active: threatScore >= 40 },
    { label: "UNDERSTAND", desc: "Attack Path & Story", active: threatScore >= 60 },
    { label: "RESPOND", desc: "Containment Action", active: threatScore >= 80 },
    { label: "VERIFY", desc: "Threat Reduction", active: threatScore < 50 && currentStage.includes("Baseline") }
  ];

  return (
    <header className="border-b border-[#D9E0E8] bg-white sticky top-0 z-40 space-y-2 px-6 py-2.5 shadow-xs">
      {/* Top Application Shell Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Persistent Incident Context */}
        <div className="flex items-center space-x-4">
          <button
            onClick={onGoHome}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-600 hover:text-slate-900 transition"
            title="Return to Landing Page"
          >
            <Home className="w-4 h-4" />
          </button>

          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-blue-600 text-white">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <span className="text-base font-bold text-slate-900 tracking-tight">Sentinel AI</span>
          </div>

          <div className="h-4 w-px bg-slate-300 hidden sm:block" />

          {/* Persistent Incident Context Selector */}
          <div className="flex items-center space-x-2">
            <span className="text-xs font-semibold text-slate-500 hidden md:inline">Investigation:</span>
            <div className="relative">
              <select
                value={selectedIncidentId || ''}
                onChange={(e) => onSelectIncident(e.target.value)}
                className="appearance-none pl-2.5 pr-7 py-1 rounded-md bg-slate-50 border border-slate-300 text-xs font-mono text-slate-900 font-bold focus:outline-none focus:border-blue-600 cursor-pointer shadow-xs"
              >
                {incidents.map(inc => (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    {inc.incident_id} — {inc.primary_entity} ({inc.threat_score} Score)
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2 top-2 pointer-events-none" />
            </div>

            <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
              threatScore >= 80 ? 'badge-critical' : threatScore >= 60 ? 'badge-warning' : 'badge-success'
            }`}>
              {threatLevel} ({threatScore})
            </span>
          </div>
        </div>

        {/* User Status & Replay Actions */}
        <div className="flex items-center space-x-3">
          <div
            onClick={() => onOpenAuth('login')}
            className="flex items-center space-x-2 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-300 text-xs cursor-pointer hover:bg-slate-100 transition"
          >
            <UserCheck className="w-3.5 h-3.5 text-blue-600" />
            <span className="font-semibold text-slate-800">{currentUser?.name || 'Alex Rivera'}</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-blue-100 text-blue-800 border border-blue-200">
              {currentUser?.role ? currentUser.role.split(' ')[0] : 'Analyst'}
            </span>
          </div>

          <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg border border-slate-300">
            <button
              onClick={onStartReplay}
              disabled={isReplaying}
              className="flex items-center space-x-1.5 px-3 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition disabled:opacity-50"
              title="Auto-play full 5-stage investigation scenario"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isReplaying ? "Replaying..." : "Play Scenario"}</span>
            </button>

            <button
              onClick={onStepReplay}
              disabled={isReplaying}
              className="flex items-center space-x-1 px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold border border-slate-300 transition disabled:opacity-50"
              title="Step to next attack stage"
            >
              <SkipForward className="w-3.5 h-3.5 text-blue-600" />
              <span className="hidden sm:inline">Next Step</span>
            </button>

            <button
              onClick={onResetReplay}
              disabled={isReplaying}
              className="flex items-center space-x-1 px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 text-slate-500 hover:text-slate-800 text-xs font-medium border border-slate-300 transition disabled:opacity-50"
              title="Reset investigation"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Reset</span>
            </button>
          </div>
        </div>
      </div>

      {/* Investigation Journey Stepper (DETECT -> CORRELATE -> UNDERSTAND -> RESPOND -> VERIFY) */}
      <div className="pt-1.5 pb-1 border-t border-slate-200 flex flex-col md:flex-row items-center justify-between gap-2 text-xs">
        <div className="flex items-center space-x-1.5 text-slate-500 text-[11px] font-medium">
          <span>Active Phase:</span>
          <span className="font-bold text-slate-900">{currentStage || "Baseline Normal"}</span>
        </div>

        <div className="flex items-center space-x-1 max-w-2xl w-full overflow-x-auto">
          {investigationSteps.map((stg, i) => (
            <React.Fragment key={stg.label}>
              <div
                className={`py-1 px-2.5 rounded text-[10px] font-mono font-bold text-center border transition-all ${
                  stg.active
                    ? 'bg-blue-50 text-blue-800 border-blue-300'
                    : 'bg-slate-50 text-slate-400 border-slate-200 font-normal'
                }`}
              >
                {i + 1}. {stg.label}
              </div>
              {i < investigationSteps.length - 1 && (
                <span className="text-slate-300 text-[10px]">→</span>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex items-center space-x-1 border-t border-slate-200 pt-1.5 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all whitespace-nowrap ${
                isActive
                  ? 'bg-slate-900 text-white font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                  isActive ? 'bg-blue-500/30 text-blue-200' : 'bg-slate-200 text-slate-700'
                }`}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
