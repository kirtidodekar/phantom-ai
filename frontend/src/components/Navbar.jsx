import React from 'react';
import { ShieldAlert, Play, SkipForward, RotateCcw, Activity, BarChart2, Radio } from 'lucide-react';

export default function Navbar({
  onStartReplay,
  onStepReplay,
  onResetReplay,
  onOpenMetrics,
  isReplaying,
  currentStage
}) {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
      {/* Brand Logo & Title */}
      <div className="flex items-center space-x-3">
        <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 text-white shadow-lg shadow-cyan-500/20">
          <ShieldAlert className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent tracking-wide">
              SENTINEL-AI
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              v1.0 Hackathon
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Cross-Layer Cyber Threat Fusion & Early-Warning Trajectory Platform
          </p>
        </div>
      </div>

      {/* Replay Controls & Status */}
      <div className="flex items-center space-x-3">
        {/* Live Replay Indicator */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
          <Radio className={`w-4 h-4 ${isReplaying ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
          <span>Stage: <strong className="text-cyan-400">{currentStage || "Baseline Normal"}</strong></span>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
          <button
            onClick={onStartReplay}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium transition shadow-md shadow-cyan-900/30 active:scale-95"
            title="Auto-play full 5-stage attack scenario"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Full Replay</span>
          </button>

          <button
            onClick={onStepReplay}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition active:scale-95 border border-slate-700"
            title="Step to next attack stage"
          >
            <SkipForward className="w-3.5 h-3.5" />
            <span>Next Stage</span>
          </button>

          <button
            onClick={onResetReplay}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs font-medium transition active:scale-95 border border-slate-700"
            title="Reset telemetry & incident state"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>

        {/* Metrics Button */}
        <button
          onClick={onOpenMetrics}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-indigo-900/30 border border-indigo-500/30 text-indigo-300 hover:bg-indigo-900/50 hover:border-indigo-500/50 text-xs font-medium transition shadow-sm"
        >
          <BarChart2 className="w-4 h-4 text-indigo-400" />
          <span>ML Model Report</span>
        </button>
      </div>
    </header>
  );
}
