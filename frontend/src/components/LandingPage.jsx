import React, { useState } from 'react';
import {
  ShieldAlert, Activity, Network, Target, GitCompare, Sliders, Cpu, ArrowRight,
  CheckCircle2, Lock, Eye, Zap, Layers, Server, ShieldCheck,
  LogIn, UserPlus, PlayCircle, Radio, ArrowDown
} from 'lucide-react';

export default function LandingPage({ onLaunchDashboard, onOpenAuth }) {
  const [activeRole, setActiveRole] = useState('Analyst');

  const roles = [
    {
      id: 'Analyst',
      title: 'SOC Tier-2 Analyst',
      icon: Eye,
      color: 'text-blue-600',
      bg: 'bg-blue-50',
      border: 'border-blue-200',
      desc: 'Correlate multi-layer signals, investigate early-warning trajectory curves, and review explainable risk scoring formulas.'
    },
    {
      id: 'Engineer',
      title: 'Detection Engineer',
      icon: Cpu,
      color: 'text-indigo-600',
      bg: 'bg-indigo-50',
      border: 'border-indigo-200',
      desc: 'Monitor Random Forest & Isolation Forest ML benchmarks, fine-tune feature importances, and inspect NSL-KDD baseline diffs.'
    },
    {
      id: 'Commander',
      title: 'Incident Response Commander',
      icon: Lock,
      color: 'text-rose-600',
      bg: 'bg-rose-50',
      border: 'border-rose-200',
      desc: 'Execute sandboxed host isolation, block malicious C2 IPs, tune high-value asset criticality, and approve remediation playbooks.'
    }
  ];

  return (
    <div className="min-h-screen bg-[#F5F7FA] text-slate-900 font-sans">
      {/* Landing Header */}
      <header className="border-b border-slate-200 bg-white sticky top-0 z-50 px-6 py-3.5 shadow-xs">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-blue-600 text-white shadow-xs">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-slate-900">
                Sentinel AI
              </span>
              <span className="ml-2 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-blue-50 text-blue-800 border border-blue-200">
                SOC PLATFORM
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => onOpenAuth('login')}
              className="flex items-center space-x-1.5 px-3.5 py-2 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-semibold border border-slate-300 transition"
            >
              <LogIn className="w-3.5 h-3.5 text-blue-600" />
              <span>Sign In</span>
            </button>

            <button
              onClick={() => onLaunchDashboard('Analyst')}
              className="flex items-center space-x-2 px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-xs transition active:scale-95"
            >
              <span>Enter Investigation Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 px-6 border-b border-slate-200 bg-white">
        <div className="max-w-5xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-800 text-xs font-mono font-semibold">
            <Radio className="w-3.5 h-3.5 text-blue-600" />
            <span>Cross-Layer Threat Fusion & Investigation Engine</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-900 leading-tight">
            Turn Fragmented Signals into an <br />
            <span className="text-blue-600">Understandable Threat Story</span>
          </h1>

          <p className="text-base text-slate-600 max-w-3xl mx-auto leading-relaxed">
            Security teams are overwhelmed by disconnected alerts. Sentinel AI correlates weak signals across Identity, Endpoint, Host, and Network layers into a clear, actionable attack progression story.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              onClick={() => onLaunchDashboard('Analyst')}
              className="flex items-center space-x-2 px-6 py-3 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm shadow-xs transition active:scale-95"
            >
              <PlayCircle className="w-4 h-4" />
              <span>Launch Live Investigation (INC-2048)</span>
            </button>
          </div>

          {/* Realistic SOC Investigation Preview Visual */}
          <div className="pt-8 max-w-4xl mx-auto">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-left space-y-3 font-mono text-xs shadow-xs">
              <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                <span className="font-bold text-slate-900">INCIDENT PREVIEW: INC-2048</span>
                <span className="badge-critical px-2 py-0.5 rounded text-[10px]">CRITICAL (SCORE 87)</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-6 gap-2 text-center text-[11px]">
                <div className="p-2 rounded bg-white border border-slate-200">
                  <span className="text-purple-700 block font-bold">10:41</span>
                  <span className="text-slate-800 font-semibold block">Suspicious Login</span>
                </div>
                <div className="p-2 rounded bg-white border border-slate-200">
                  <span className="text-blue-700 block font-bold">10:42</span>
                  <span className="text-slate-800 font-semibold block">New Device</span>
                </div>
                <div className="p-2 rounded bg-white border border-slate-200">
                  <span className="text-amber-700 block font-bold">10:43</span>
                  <span className="text-slate-800 font-semibold block">PowerShell</span>
                </div>
                <div className="p-2 rounded bg-white border border-slate-200">
                  <span className="text-rose-700 block font-bold">10:46</span>
                  <span className="text-slate-800 font-semibold block">Encoded Cmd</span>
                </div>
                <div className="p-2 rounded bg-white border border-slate-200">
                  <span className="text-rose-700 block font-bold">10:48</span>
                  <span className="text-slate-800 font-semibold block">C2 Exfil</span>
                </div>
                <div className="p-2 rounded bg-rose-100 border border-rose-300 text-rose-900 font-bold flex items-center justify-center">
                  ACTION READY
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Role Workspaces */}
      <section className="py-12 px-6 max-w-7xl mx-auto space-y-8">
        <div className="text-center space-y-1">
          <h2 className="text-xl font-bold text-slate-900">Tailored Operational Workspaces</h2>
          <p className="text-xs text-slate-600">Select a workspace to experienceSentinel AI from your role's perspective.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {roles.map((role) => {
            const Icon = role.icon;
            return (
              <div
                key={role.id}
                onClick={() => onLaunchDashboard(role.id)}
                className="p-5 rounded-xl bg-white border border-slate-200 hover:border-slate-300 cursor-pointer space-y-3 shadow-xs transition"
              >
                <div className="flex items-center justify-between">
                  <div className={`p-2.5 rounded-lg bg-slate-50 border border-slate-200 ${role.color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase">Role</span>
                </div>

                <h3 className="text-sm font-bold text-slate-900">{role.title}</h3>
                <p className="text-xs text-slate-600 leading-relaxed">{role.desc}</p>

                <button className="w-full py-2 px-3 rounded-md bg-slate-50 hover:bg-slate-100 text-slate-800 border border-slate-300 text-xs font-bold flex items-center justify-center space-x-1.5 transition">
                  <span>Enter as {role.id}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-blue-600" />
                </button>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
