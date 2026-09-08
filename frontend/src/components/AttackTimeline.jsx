import React from 'react';
import { History, ShieldAlert, Network } from 'lucide-react';

export default function AttackTimeline({ incident }) {
  if (!incident || !incident.attack_story || incident.attack_story.length === 0) {
    return (
      <div className="soc-surface rounded-2xl p-6 border border-[#D9E0E8] text-center text-slate-600">
        <History className="w-10 h-10 mx-auto text-slate-400 mb-2" />
        <p className="text-xs">No attack story timeline recorded yet.</p>
      </div>
    );
  }

  const storyEntries = incident.attack_story;

  return (
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <History className="w-5 h-5 text-violet-600" />
          <h2 className="text-sm font-bold text-slate-900">Attack Story & Chronological Timeline</h2>
        </div>
        <span className="text-xs font-mono font-bold px-2.5 py-1 rounded-lg bg-violet-50 text-violet-700 border border-violet-200 flex items-center space-x-1.5">
          <Network className="w-3.5 h-3.5" />
          <span>{storyEntries.length} Stage Events</span>
        </span>
      </div>

      {/* Chronological Vertical Timeline */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
        {storyEntries.map((entry, idx) => {
          const isLatest = idx === storyEntries.length - 1;
          return (
            <div key={idx} className="relative group">
              {/* Timeline Marker Dot */}
              <div className={`absolute -left-6 top-1.5 w-3.5 h-3.5 rounded-full border-2 transition-all ${
                isLatest
                  ? 'bg-rose-600 border-white shadow-md animate-pulse'
                  : 'bg-white border-violet-400 group-hover:border-blue-500'
              }`} />

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition">
                <p className="text-xs font-mono text-slate-700 leading-relaxed">
                  {entry}
                </p>
                {isLatest && (
                  <span className="inline-flex items-center space-x-1.5 mt-2 px-2 py-0.5 text-[10px] font-bold rounded bg-rose-50 text-rose-700 border border-rose-200 uppercase tracking-wider">
                    <ShieldAlert className="w-2.5 h-2.5" />
                    <span>Current Active State</span>
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
