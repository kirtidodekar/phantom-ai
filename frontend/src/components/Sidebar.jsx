import React, { useState } from 'react';
import {
  LayoutDashboard, Layers3, Network, Target, GitCompare,
  Sliders, Eye, ShieldAlert, Play, Pause, ChevronLeft, ChevronRight,
  UserCheck, Shield, Activity, Radio, Cpu, Sparkles
} from 'lucide-react';
import { cn } from '../lib/cn';

export default function Sidebar({
  activeTab,
  onTabChange,
  incidentsCount = 0,
  isSimulating,
  onStartSim,
  onStopSim,
  currentUser,
  onOpenAuth,
  onGoHome,
  backendOnline,
  systemStatus
}) {
  const [collapsed, setCollapsed] = useState(false);

  const navSections = [
    {
      title: 'CORE OPS & MONITORING',
      items: [
        {
          id: 'overview',
          label: 'Executive Overview',
          sub: 'KPIs & Threat Queue',
          icon: LayoutDashboard,
          accent: 'text-blue-600',
          badge: incidentsCount > 0 ? String(incidentsCount) : null,
          badgeTone: 'bg-rose-50 text-rose-700 border-rose-200'
        },
        {
          id: 'coverage',
          label: 'Telemetry Ingestion',
          sub: '3-Signal Stream Matrix',
          icon: Layers3,
          accent: 'text-cyan-600',
          badge: '3 Live',
          badgeTone: 'bg-cyan-50 text-cyan-700 border-cyan-200'
        }
      ]
    },
    {
      title: 'DEEP INVESTIGATION',
      items: [
        {
          id: 'topology',
          label: 'Attack Path Topology',
          sub: 'Entity Graph & Kill Chain',
          icon: Network,
          accent: 'text-violet-600'
        },
        {
          id: 'intel',
          label: 'Threat Story & MITRE',
          sub: 'Narrative & ATT&CK Matrix',
          icon: Target,
          accent: 'text-amber-600'
        },
        {
          id: 'forensics',
          label: 'Forensic Diff',
          sub: 'Baseline vs Outlier Divergence',
          icon: GitCompare,
          accent: 'text-emerald-600'
        }
      ]
    },
    {
      title: 'RESPONSE & INSPECTION',
      items: [
        {
          id: 'actions',
          label: 'Response & Containment',
          sub: 'Sandboxed Playbooks',
          icon: Sliders,
          accent: 'text-rose-600'
        },
        {
          id: 'details',
          label: 'Drill-Down Inspector',
          sub: 'Raw REST API Inspector',
          icon: Eye,
          accent: 'text-indigo-600'
        }
      ]
    }
  ];

  return (
    <aside
      className={cn(
        'relative bg-white border-r border-slate-200/90 flex flex-col justify-between transition-all duration-300 z-30 shrink-0 select-none shadow-sm min-h-screen',
        collapsed ? 'w-20' : 'w-72'
      )}
    >
      {/* Top Brand & Header */}
      <div>
        <div className="p-4 border-b border-slate-200/90 flex items-center justify-between">
          <button
            onClick={onGoHome}
            className="flex items-center gap-3 text-left focus:outline-none group cursor-pointer"
            title="Go to Sentinel AI Landing Page"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 via-indigo-600 to-blue-700 flex items-center justify-center text-white shadow-md shadow-blue-500/25 group-hover:scale-105 transition">
              <ShieldAlert className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="font-extrabold text-slate-900 text-base tracking-tight">Sentinel AI</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                    v2.0
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500 truncate">SOC Investigation Suite</p>
              </div>
            )}
          </button>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 border border-transparent hover:border-slate-200 transition cursor-pointer"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Menu */}
        <nav className="p-3 space-y-5 overflow-y-auto max-h-[calc(100vh-270px)]">
          {navSections.map((sec, idx) => (
            <div key={idx} className="space-y-1">
              {!collapsed && (
                <div className="px-3 py-1 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                  {sec.title}
                </div>
              )}
              <div className="space-y-1">
                {sec.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onTabChange(item.id)}
                      className={cn(
                        'w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all group cursor-pointer relative',
                        isActive
                          ? 'bg-blue-50/90 text-blue-900 font-semibold border border-blue-200/80 shadow-xs'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
                      )}
                      title={collapsed ? `${item.label} — ${item.sub}` : undefined}
                    >
                      {isActive && (
                        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1.5 h-6 bg-blue-600 rounded-r-full" />
                      )}
                      <div
                        className={cn(
                          'p-2 rounded-lg transition-colors shrink-0',
                          isActive
                            ? 'bg-blue-600 text-white shadow-xs'
                            : 'bg-slate-100 text-slate-500 group-hover:bg-white group-hover:text-slate-800 group-hover:shadow-xs'
                        )}
                      >
                        <Icon className="w-4 h-4" />
                      </div>

                      {!collapsed && (
                        <div className="min-w-0 flex-1 flex items-center justify-between">
                          <div className="min-w-0">
                            <span className="block text-xs font-bold leading-tight truncate text-slate-900">
                              {item.label}
                            </span>
                            <span className="block text-[10px] text-slate-500 font-medium truncate mt-0.5">
                              {item.sub}
                            </span>
                          </div>
                          {item.badge && (
                            <span
                              className={cn(
                                'ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0',
                                item.badgeTone
                              )}
                            >
                              {item.badge}
                            </span>
                          )}
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </div>

      {/* Bottom Footer Section: Simulator Toggle + User Card */}
      <div className="p-3 border-t border-slate-200/90 bg-slate-50/80 space-y-2.5">
        {/* Simulator Widget */}
        {!collapsed ? (
          <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Radio className={cn('w-3.5 h-3.5', isSimulating ? 'text-amber-500 animate-pulse' : 'text-slate-400')} />
                <span className="text-[11px] font-bold text-slate-800">Attack Simulator</span>
              </div>
              <span
                className={cn(
                  'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase',
                  isSimulating
                    ? 'bg-amber-100 text-amber-800 border border-amber-200'
                    : 'bg-slate-100 text-slate-500 border border-slate-200'
                )}
              >
                {isSimulating ? 'RUNNING' : 'PAUSED'}
              </span>
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Emits multi-signal brute-force & C2 network attack telemetry.
            </p>
            {isSimulating ? (
              <button
                onClick={onStopSim}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold transition shadow-xs cursor-pointer"
              >
                <Pause className="w-3.5 h-3.5 fill-current" />
                <span>Pause Simulation</span>
              </button>
            ) : (
              <button
                onClick={onStartSim}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition shadow-xs cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Launch Simulation</span>
              </button>
            )}
          </div>
        ) : (
          <button
            onClick={isSimulating ? onStopSim : onStartSim}
            className={cn(
              'w-full p-2.5 rounded-xl flex items-center justify-center transition cursor-pointer text-white shadow-xs',
              isSimulating ? 'bg-amber-600 hover:bg-amber-700' : 'bg-blue-600 hover:bg-blue-700'
            )}
            title={isSimulating ? 'Pause Attack Simulator' : 'Start Attack Simulator'}
          >
            {isSimulating ? <Pause className="w-4 h-4 fill-current" /> : <Play className="w-4 h-4 fill-current" />}
          </button>
        )}

        {/* User Profile Card */}
        <div
          onClick={() => onOpenAuth('login')}
          className={cn(
            'flex items-center gap-2.5 p-2 rounded-xl bg-white border border-slate-200 hover:border-slate-300 transition cursor-pointer shadow-xs group',
            collapsed && 'justify-center p-2'
          )}
          title="Switch Analyst / User Profile"
        >
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-slate-800 to-slate-700 text-white flex items-center justify-center text-xs font-bold shrink-0 shadow-xs">
            {currentUser?.name?.charAt(0) || 'A'}
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 truncate group-hover:text-blue-600 transition">
                  {currentUser?.name || 'Alex Rivera'}
                </span>
                <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                  {currentUser?.role?.split(' ')[0] || 'Analyst'}
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 truncate">{currentUser?.email || 'alex@sentinel.ai'}</p>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}