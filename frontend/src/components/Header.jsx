import React from 'react';
import {
  ShieldAlert, ChevronDown, Activity, Sparkles,
  Lock, Globe, Search, Bell, HelpCircle
} from 'lucide-react';
import NotificationCenter from './NotificationCenter';
import { cn } from '../lib/cn';

export default function Header({
  activeTab,
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  currentStage,
  threatScore = 85,
  threatLevel = 'CRITICAL',
  backendOnline = true,
  systemStatus
}) {
  const tabTitles = {
    overview: 'Executive Dashboard & Incident Queue',
    coverage: 'Multi-Signal Telemetry Ingestion Engine',
    topology: 'Attack Path & Entity Topology Graph',
    intel: 'Threat Story & MITRE ATT&CK Matrix',
    forensics: 'Forensic Analysis & Baseline Diff',
    actions: 'Incident Response & Containment Center',
    details: 'Raw Incident & Telemetry Drill-Down Inspector'
  };

  const investigationSteps = [
    { label: 'INGEST', desc: 'Multi-Signal', active: true, color: 'border-cyan-400 text-cyan-700 bg-cyan-50' },
    { label: 'CORRELATE', desc: 'ML + Rule', active: threatScore >= 40, color: 'border-blue-400 text-blue-700 bg-blue-50' },
    { label: 'UNDERSTAND', desc: 'Path & Story', active: threatScore >= 60, color: 'border-amber-400 text-amber-700 bg-amber-50' },
    { label: 'RESPOND', desc: 'Containment', active: threatScore >= 80, color: 'border-rose-400 text-rose-700 bg-rose-50' },
    { label: 'VERIFY', desc: 'Resolved', active: threatScore < 50 || (currentStage && currentStage.includes('Resolved')), color: 'border-emerald-400 text-emerald-700 bg-emerald-50' }
  ];

  return (
    <header className="sticky top-0 z-20 bg-white/95 backdrop-blur-md border-b border-slate-200/90 px-6 py-3 shadow-xs">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Left: Active Module Title & Persistent Incident Selector */}
        <div className="flex items-center gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold uppercase text-slate-400">MODULE</span>
              <span className="text-slate-300">/</span>
              <h1 className="text-sm font-extrabold text-slate-900 tracking-tight">
                {tabTitles[activeTab] || 'SOC Workspace'}
              </h1>
            </div>
          </div>

          <div className="h-5 w-px bg-slate-200 hidden md:block" />

          {/* Incident Quick Switcher */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-slate-500 hidden lg:inline">Active Incident:</span>
            <div className="relative">
              <select
                value={selectedIncidentId || ''}
                onChange={(e) => onSelectIncident(e.target.value)}
                className="appearance-none pl-3 pr-8 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono text-slate-900 font-bold focus:outline-none focus:border-blue-600 cursor-pointer shadow-xs"
              >
                {incidents.length === 0 && <option value="">No active incidents observed</option>}
                {incidents.map((inc) => {
                  const id = inc.id || inc.incident_id;
                  const entity = inc.entity_id || inc.primary_entity;
                  return (
                    <option key={id} value={id}>
                      {id} — {entity} ({Math.round(inc.threat_score || 0)} pts)
                    </option>
                  );
                })}
              </select>
              <ChevronDown className="w-3.5 h-3.5 text-slate-500 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>

            {/* Severity Pill */}
            <span
              className={cn(
                'px-2.5 py-1 text-[10px] font-mono font-extrabold rounded-lg border shadow-2xs',
                threatScore >= 80
                  ? 'bg-rose-50 text-rose-700 border-rose-200 animate-pulse'
                  : threatScore >= 60
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              )}
            >
              {threatLevel} ({Math.round(threatScore)}/100)
            </span>
          </div>
        </div>

        {/* Center/Right: Stepper + Status Pills + Notification Bell */}
        <div className="flex items-center gap-4 flex-wrap">
          {/* Investigation Phase Stepper */}
          <div className="hidden xl:flex items-center gap-1.5 p-1 rounded-xl bg-slate-100/80 border border-slate-200">
            {investigationSteps.map((stg, i) => (
              <React.Fragment key={stg.label}>
                <span
                  className={cn(
                    'px-2 py-0.5 rounded-lg text-[10px] font-mono font-bold text-center border transition-all',
                    stg.active
                      ? stg.color
                      : 'bg-transparent text-slate-400 border-transparent font-normal'
                  )}
                  title={stg.desc}
                >
                  {i + 1}. {stg.label}
                </span>
                {i < investigationSteps.length - 1 && (
                  <span className="text-slate-300 text-[10px]">›</span>
                )}
              </React.Fragment>
            ))}
          </div>

          {/* System Sovereignty Pill */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-200 text-[11px] font-mono font-bold text-emerald-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" />
            <span>SOVEREIGN: {systemStatus?.sovereignty || '100% LOCAL'}</span>
          </div>

          {/* Notification Center */}
          <NotificationCenter />
        </div>
      </div>
    </header>
  );
}