import React from 'react';
import { History, ShieldAlert, CheckCircle, Terminal, Key, Network } from 'lucide-react';

export default function AttackTimeline({ incident }) {
  if (!incident || !incident.attack_story || incident.attack_story.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6 text-center text-slate-400">
        <History className="w-10 h-10 mx-auto text-slate-600 mb-2" />
        <p>No attack story timeline recorded yet.</p>
      </div>
    );
  }

  const storyEntries = incident.attack_story;

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <History className="w-5 h-5 text-indigo-400" />
          <h2 className="text-base font-semibold text-slate-100">Attack Story & Chronological Timeline</h2>
        </div>
        <span className="text-xs font-mono text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/30">
          {storyEntries.length} Stage Events
        </span>
      </div>

      {/* Chronological Vertical Timeline */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {storyEntries.map((entry, idx) => {
          const isLatest = idx === storyEntries.length - 1;
          return (
            <div key={idx} className="relative group">
              {/* Timeline Marker Dot */}
              <div className={`absolute -left-6 top-1.5 w-3.5 h-3.5 rounded-full border-2 transition-all ${
                isLatest
                  ? 'bg-rose-500 border-white shadow-lg shadow-rose-500/50 animate-pulse'
                  : 'bg-slate-900 border-indigo-400 group-hover:border-cyan-400'
              }`} />

              <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 transition">
                <p className="text-xs font-mono text-slate-200 leading-relaxed">
                  {entry}
                </p>
                {isLatest && (
                  <span className="inline-block mt-2 px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 uppercase tracking-wider">
                    Current Active State
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
