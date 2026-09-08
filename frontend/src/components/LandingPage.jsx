import React, { useState } from 'react';
import {
  ShieldAlert, ShieldCheck, Cpu, ArrowRight, Lock, Eye, Layers, Server,
  LogIn, Radio, Activity, Bell, Network, Database, Zap, Radar, Bug,
  CheckCircle2, TrendingUp, Gauge, Waves, GitBranch, Boxes
} from 'lucide-react';

/**
 * Landing page — enterprise product presentation for the Sentinel AI console.
 *
 * Behaviour contract preserved from the original implementation:
 *  - Sign In            -> onOpenAuth('login')
 *  - Primary CTAs       -> onLaunchDashboard('Analyst')
 *  - Role workspaces    -> onLaunchDashboard(role.id)
 */
export default function LandingPage({ onLaunchDashboard, onOpenAuth }) {
  const [activeRole, setActiveRole] = useState('Analyst');

  const roles = [
    {
      id: 'Analyst',
      title: 'SOC Tier-2 Analyst',
      icon: Eye,
      accent: 'text-blue-600',
      chip: 'bg-blue-50 border-blue-200',
      desc: 'Correlate multi-layer signals, follow the threat trajectory curve, and review explainable risk scoring evidence.'
    },
    {
      id: 'Engineer',
      title: 'Detection Engineer',
      icon: Cpu,
      accent: 'text-indigo-600',
      chip: 'bg-indigo-50 border-indigo-200',
      desc: 'Benchmark Random Forest and Isolation Forest performance, inspect feature importances, and tune detection thresholds.'
    },
    {
      id: 'Commander',
      title: 'Incident Response Commander',
      icon: Lock,
      accent: 'text-rose-600',
      chip: 'bg-rose-50 border-rose-200',
      desc: 'Run sandboxed containment, block malicious infrastructure, weight asset criticality, and approve response playbooks.'
    }
  ];

  const capabilities = [
    {
      icon: Cpu,
      title: 'AI Intrusion Detection',
      accent: 'text-blue-600',
      chip: 'bg-blue-50',
      desc: 'A supervised Random Forest classifier pairs with an Isolation Forest anomaly detector so both known attack patterns and novel behaviour are caught.'
    },
    {
      icon: Layers,
      title: 'Multi-Class Classification',
      accent: 'text-violet-600',
      chip: 'bg-violet-50',
      desc: 'Nine labelled verdicts spanning SQL Injection, XSS, Brute Force, Malware C2, Phishing, DoS/DDoS, Probe and Unauthorized Access.'
    },
    {
      icon: Activity,
      title: 'Real-Time Monitoring',
      accent: 'text-emerald-600',
      chip: 'bg-emerald-50',
      desc: 'Streaming detections with per-event confidence, inference latency, throughput charts and class distribution built for wall-display use.'
    },
    {
      icon: ShieldCheck,
      title: 'Automatic IP Blocking',
      accent: 'text-rose-600',
      chip: 'bg-rose-50',
      desc: 'Malicious sources crossing the risk threshold are contained automatically, with a full audit trail. Enforcement is sandboxed by design.'
    },
    {
      icon: Bell,
      title: 'Admin Alerts',
      accent: 'text-amber-600',
      chip: 'bg-amber-50',
      desc: 'Critical escalations raise immediate toast notifications and collect in an alert centre so nothing time-sensitive is missed.'
    },
    {
      icon: Network,
      title: 'Cross-Layer Correlation',
      accent: 'text-sky-600',
      chip: 'bg-sky-50',
      desc: 'Identity, endpoint and network evidence is fused into a single incident with an evolving threat score instead of isolated alerts.'
    }
  ];

  const pipeline = [
    { icon: Waves, label: 'Telemetry', sub: 'Multi-layer feeds' },
    { icon: Boxes, label: 'Normalize', sub: 'Common schema' },
    { icon: Cpu, label: 'Detect', sub: 'RF + IsoForest' },
    { icon: GitBranch, label: 'Correlate', sub: 'Entity linking' },
    { icon: Gauge, label: 'Score', sub: 'Explainable risk' },
    { icon: ShieldCheck, label: 'Respond', sub: 'Sandboxed action' }
  ];

  const feedRows = [
    { time: '10:48:12', ip: '198.51.100.99', cls: 'SQL Injection', conf: 97, tone: 'rose', blocked: true },
    { time: '10:47:55', ip: '203.0.113.44', cls: 'Brute Force', conf: 93, tone: 'rose', blocked: true },
    { time: '10:47:31', ip: '45.83.192.7', cls: 'Malware / C2', conf: 89, tone: 'amber', blocked: false },
    { time: '10:47:02', ip: '10.0.4.18', cls: 'Benign', conf: 99, tone: 'emerald', blocked: false }
  ];

  const toneMap = {
    rose: 'text-rose-700 bg-rose-50 border-rose-200',
    amber: 'text-amber-700 bg-amber-50 border-amber-200',
    emerald: 'text-emerald-700 bg-emerald-50 border-emerald-200'
  };

  return (
    <div className="min-h-screen bg-[#F5F7FA] text-slate-900 font-sans">
      {/* ---------------- Navigation ---------------- */}
      <header className="border-b border-slate-200 bg-white/95 backdrop-blur sticky top-0 z-50 px-6 py-3">
        <div className="max-w-[1400px] mx-auto flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-600 text-white">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div className="leading-tight">
              <div className="text-lg font-bold tracking-tight text-slate-900">Sentinel AI</div>
              <div className="text-[10px] font-mono font-semibold text-slate-500 uppercase tracking-wider">
                AI Security Operations
              </div>
            </div>
          </div>

          <nav className="hidden lg:flex items-center gap-1" aria-label="Section navigation">
            {[
              { href: '#capabilities', label: 'Capabilities' },
              { href: '#architecture', label: 'Architecture' },
              { href: '#platform', label: 'Workspaces' }
            ].map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="px-3 py-1.5 rounded-md text-xs font-semibold text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
              >
                {item.label}
              </a>
            ))}
          </nav>

          <div className="flex items-center gap-2.5">
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-50 border border-emerald-200 text-[10px] font-mono font-bold text-emerald-700">
              <span className="live-dot bg-emerald-500" />
              SYSTEM ONLINE
            </span>

            <button
              type="button"
              onClick={() => onOpenAuth('login')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-white hover:bg-slate-50 text-slate-800 text-xs font-semibold border border-slate-300 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
            >
              <LogIn className="w-3.5 h-3.5 text-blue-600" />
              <span>Sign In</span>
            </button>

            <button
              type="button"
              onClick={() => onLaunchDashboard('Analyst')}
              className="flex items-center gap-2 px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition active:scale-95 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
            >
              <span>Open SOC Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* ---------------- Hero ---------------- */}
      <section className="relative border-b border-slate-200 bg-white overflow-hidden">
        <div className="absolute inset-0 bg-grid opacity-60 pointer-events-none" aria-hidden="true" />
        <div className="relative max-w-[1400px] mx-auto px-6 py-14 lg:py-20 grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
          {/* Copy */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-800 text-[11px] font-mono font-semibold">
              <Radio className="w-3.5 h-3.5 text-blue-600" />
              <span>Autonomous Threat Detection &amp; Response</span>
            </div>

            <h1 className="text-4xl sm:text-5xl xl:text-6xl font-extrabold tracking-tight leading-[1.08] text-slate-900">
              Stop triaging alerts.
              <br />
              <span className="text-gradient">Start acting on threats.</span>
            </h1>

            <p className="text-base text-slate-600 leading-relaxed max-w-xl">
              Sentinel AI classifies every event with a confidence score, fuses weak signals across identity,
              endpoint and network layers, and contains malicious infrastructure automatically — then shows you
              exactly why each decision was made.
            </p>

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => onLaunchDashboard('Analyst')}
                className="flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm transition active:scale-95 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
              >
                <Zap className="w-4 h-4" />
                <span>Launch Live Investigation</span>
              </button>
              <a
                href="#capabilities"
                className="flex items-center gap-2 px-5 py-3 rounded-lg bg-white hover:bg-slate-50 text-slate-800 font-semibold text-sm border border-slate-300 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
              >
                <span>Explore capabilities</span>
                <ArrowRight className="w-4 h-4 text-blue-600" />
              </a>
            </div>

            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 pt-2">
              {[
                { icon: Zap, text: 'Real-time inference' },
                { icon: Eye, text: 'Explainable scoring' },
                { icon: ShieldCheck, text: 'Sandboxed response' }
              ].map((chip) => {
                const Icon = chip.icon;
                return (
                  <span key={chip.text} className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    <Icon className="w-3.5 h-3.5 text-slate-400" />
                    {chip.text}
                  </span>
                );
              })}
            </div>
          </div>

          {/* Product preview */}
          <div className="lg:col-span-6">
            <div className="soc-elevated overflow-hidden">
              {/* Panel chrome */}
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 bg-slate-50">
                <div className="flex items-center gap-2">
                  <span className="live-dot bg-rose-500" />
                  <span className="text-[11px] font-mono font-bold text-slate-700">
                    LIVE DETECTION — INC-2048
                  </span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold badge-critical">
                  CRITICAL 87
                </span>
              </div>

              <div className="p-4 space-y-4">
                {/* Metric strip */}
                <div className="grid grid-cols-3 gap-2.5">
                  {[
                    { label: 'Events/sec', value: '1,284', tone: 'text-slate-900' },
                    { label: 'Confidence', value: '94%', tone: 'text-emerald-700' },
                    { label: 'Latency', value: '3.1ms', tone: 'text-blue-700' }
                  ].map((m) => (
                    <div key={m.label} className="rounded-lg bg-slate-50 border border-slate-200 p-2.5">
                      <div className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{m.label}</div>
                      <div className={`text-lg font-extrabold font-mono leading-none mt-1 ${m.tone}`}>{m.value}</div>
                    </div>
                  ))}
                </div>

                {/* Trajectory sparkline */}
                <div className="rounded-lg border border-slate-200 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                      Threat Trajectory
                    </span>
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold text-rose-700">
                      <TrendingUp className="w-3 h-3" /> +72 in 7m
                    </span>
                  </div>
                  <svg viewBox="0 0 300 64" className="w-full h-16" preserveAspectRatio="none" role="img" aria-label="Rising threat score trajectory">
                    <defs>
                      <linearGradient id="landingTrajectory" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2563eb" stopOpacity="0.3" />
                        <stop offset="100%" stopColor="#2563eb" stopOpacity="0" />
                      </linearGradient>
                    </defs>
                    <path d="M0 58 L50 54 L100 44 L150 34 L200 22 L250 14 L300 6 L300 64 L0 64 Z" fill="url(#landingTrajectory)" />
                    <path d="M0 58 L50 54 L100 44 L150 34 L200 22 L250 14 L300 6" fill="none" stroke="#2563eb" strokeWidth="2.5" strokeLinecap="round" />
                  </svg>
                </div>

                {/* Detection feed */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                    Classified Detections
                  </span>
                  {feedRows.map((row) => (
                    <div
                      key={row.time}
                      className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-2.5 py-2"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="text-[10px] font-mono text-slate-500 shrink-0">{row.time}</span>
                        <span className="text-[11px] font-mono font-semibold text-slate-800 truncate">{row.ip}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${toneMap[row.tone]}`}>
                          {row.cls}
                        </span>
                        <span className="text-[10px] font-mono font-bold text-slate-600 w-8 text-right">{row.conf}%</span>
                        {row.blocked ? (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-rose-600 text-white">
                            BLOCKED
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-slate-100 text-slate-500 border border-slate-200">
                            MONITOR
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Layer pills */}
                <div className="flex items-center gap-1.5 border-t border-slate-200 pt-3">
                  <span className="text-[10px] font-semibold text-slate-500">Layers fused:</span>
                  {['identity', 'endpoint', 'network', 'application'].map((l) => (
                    <span key={l} className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-50 text-blue-700 border border-blue-200 capitalize">
                      {l}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <p className="mt-2.5 text-[11px] text-slate-500 text-center">
              Illustrative console preview. All response actions run in a sandboxed demonstration environment.
            </p>
          </div>
        </div>
      </section>

      {/* ---------------- Proof bar ---------------- */}
      <section className="border-b border-slate-200 bg-white">
        <div className="max-w-[1400px] mx-auto px-6 py-6 grid grid-cols-2 lg:grid-cols-4 gap-5">
          {[
            { icon: Layers, label: 'Threat classes', value: '9', note: 'Supervised + anomaly' },
            { icon: Gauge, label: 'Model confidence', value: '94%', note: 'Weighted F1 on test split' },
            { icon: Zap, label: 'Inference latency', value: '~3ms', note: 'Per event, single node' },
            { icon: Network, label: 'Telemetry layers', value: '3', note: 'Identity / endpoint / network' }
          ].map((stat) => {
            const Icon = stat.icon;
            return (
              <div key={stat.label} className="flex items-start gap-3">
                <span className="rounded-lg bg-blue-50 p-2 shrink-0">
                  <Icon className="w-4 h-4 text-blue-600" />
                </span>
                <div className="min-w-0">
                  <div className="text-2xl font-extrabold font-mono text-slate-900 leading-none">{stat.value}</div>
                  <div className="text-xs font-semibold text-slate-700 mt-1">{stat.label}</div>
                  <div className="text-[11px] text-slate-500">{stat.note}</div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ---------------- Capabilities ---------------- */}
      <section id="capabilities" className="max-w-[1400px] mx-auto px-6 py-16 space-y-8 scroll-mt-20">
        <div className="max-w-2xl space-y-2">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-blue-700">Capabilities</span>
          <h2 className="text-3xl font-bold tracking-tight text-slate-900">
            Built for the full detection lifecycle
          </h2>
          <p className="text-sm text-slate-600 leading-relaxed">
            Detection, classification, correlation and response operate as one pipeline, so an analyst never has to
            reassemble the story by hand.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <article key={cap.title} className="soc-surface p-5 border border-[#D9E0E8] hover-lift space-y-3">
                <span className={`inline-flex rounded-lg p-2.5 ${cap.chip}`}>
                  <Icon className={`w-5 h-5 ${cap.accent}`} />
                </span>
                <h3 className="text-sm font-bold text-slate-900">{cap.title}</h3>
                <p className="text-xs text-slate-600 leading-relaxed">{cap.desc}</p>
              </article>
            );
          })}
        </div>
      </section>

      {/* ---------------- Architecture ---------------- */}
      <section id="architecture" className="border-y border-slate-200 bg-white scroll-mt-20">
        <div className="max-w-[1400px] mx-auto px-6 py-16 space-y-8">
          <div className="max-w-2xl space-y-2">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-blue-700">Architecture</span>
            <h2 className="text-3xl font-bold tracking-tight text-slate-900">
              A transparent detection pipeline
            </h2>
            <p className="text-sm text-slate-600 leading-relaxed">
              Machine learning contributes evidence; a deterministic reasoning layer decides how that evidence
              combines into an incident. Every score remains traceable.
            </p>
          </div>

          {/* Flow */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {pipeline.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={step.label} className="relative rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-center">
                  <span className="absolute -top-2 left-3 px-1.5 rounded bg-white border border-slate-200 text-[9px] font-mono font-bold text-slate-500">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <Icon className="w-5 h-5 text-blue-600 mx-auto" />
                  <div className="text-xs font-bold text-slate-900 mt-2">{step.label}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{step.sub}</div>
                </div>
              );
            })}
          </div>

          {/* Stack */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3 lg:col-span-2">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900">Model &amp; service stack</h3>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                {[
                  'scikit-learn', 'Random Forest', 'Isolation Forest',
                  'FastAPI service', 'PostgreSQL', 'MITRE ATT&CK'
                ].map((t) => (
                  <span key={t} className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-2 text-[11px] font-mono font-semibold text-slate-700 text-center">
                    {t}
                  </span>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                Models are trained and served through the same Python stack, so the features used at inference time
                are exactly those learned during training.
              </p>
            </div>

            <div className="soc-surface p-5 border border-[#D9E0E8] space-y-3">
              <div className="flex items-center gap-2">
                <Boxes className="w-4 h-4 text-violet-600" />
                <h3 className="text-sm font-bold text-slate-900">Modular by design</h3>
              </div>
              <ul className="space-y-2">
                {[
                  { icon: Radar, text: 'Pluggable detectors' },
                  { icon: Database, text: 'Swappable persistence' },
                  { icon: Bug, text: 'Isolated response sandbox' },
                  { icon: Activity, text: 'Stateless API workers' }
                ].map((item) => {
                  const Icon = item.icon;
                  return (
                    <li key={item.text} className="flex items-center gap-2 text-xs text-slate-600">
                      <Icon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      {item.text}
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- Role workspaces ---------------- */}
      <section id="platform" className="max-w-[1400px] mx-auto px-6 py-16 space-y-8 scroll-mt-20">
        <div className="max-w-2xl space-y-2">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-blue-700">Workspaces</span>
          <h2 className="text-3xl font-bold tracking-tight text-slate-900">
            Tailored to how your team works
          </h2>
          <p className="text-sm text-slate-600 leading-relaxed">
            Choose a workspace to enter the console with the views and controls that role depends on.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {roles.map((role) => {
            const Icon = role.icon;
            const isActive = activeRole === role.id;
            return (
              <button
                key={role.id}
                type="button"
                onMouseEnter={() => setActiveRole(role.id)}
                onFocus={() => setActiveRole(role.id)}
                onClick={() => onLaunchDashboard(role.id)}
                aria-label={`Enter the console as ${role.title}`}
                className={`text-left p-5 rounded-xl bg-white border space-y-3 transition hover-lift focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 ${
                  isActive ? 'border-blue-300' : 'border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className={`rounded-lg p-2.5 border ${role.chip}`}>
                    <Icon className={`w-5 h-5 ${role.accent}`} />
                  </span>
                  <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                    Workspace
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-900">{role.title}</h3>
                <p className="text-xs text-slate-600 leading-relaxed">{role.desc}</p>

                <span className="w-full py-2 px-3 rounded-md bg-slate-50 text-slate-800 border border-slate-300 text-xs font-bold flex items-center justify-center gap-1.5">
                  <span>Enter as {role.id}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-blue-600" />
                </span>
              </button>
            );
          })}
        </div>
      </section>

      {/* ---------------- Closing CTA ---------------- */}
      <section className="border-t border-slate-200 bg-white">
        <div className="max-w-[1400px] mx-auto px-6 py-14">
          <div className="soc-gradient-border p-8 lg:p-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="space-y-2 max-w-2xl">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900">
                See a multi-stage intrusion assemble itself
              </h2>
              <p className="text-sm text-slate-600 leading-relaxed">
                The console opens on a live correlated incident with its full evidence trail, ATT&amp;CK mapping and
                response options already in place.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onLaunchDashboard('Analyst')}
              className="shrink-0 flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm transition active:scale-95 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
            >
              <span>Open the SOC console</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      {/* ---------------- Footer ---------------- */}
      <footer className="border-t border-slate-200 bg-white">
        <div className="max-w-[1400px] mx-auto px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-md bg-blue-600 text-white">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
            <span className="text-xs font-bold text-slate-900">Sentinel AI</span>
            <span className="text-[10px] font-mono text-slate-400">SOC PLATFORM</span>
          </div>

          <p className="text-[11px] text-slate-500 text-center">
            Defensive research and demonstration platform. Response actions are simulated in a sandbox.
          </p>

          <p className="text-[11px] font-mono text-slate-400">
            &copy; {new Date().getFullYear()} Sentinel AI
          </p>
        </div>
      </footer>
    </div>
  );
}
