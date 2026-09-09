import React from 'react';
import { Target, ExternalLink, ShieldAlert, Sparkles } from 'lucide-react';
import { cn } from '../lib/cn';

export default function MitreMatrix({ incident }) {
  const tag = incident?.mitre_tag || { id: 'T1110', name: 'Brute Force', description: 'Adversaries may use brute force techniques to gain access to accounts.' };

  const mappings = incident?.mitre_mappings || [
    { tactic: 'Credential Access', technique_id: tag.id || 'T1110', technique: tag.name || 'Brute Force' },
    { tactic: 'Initial Access', technique_id: 'T1078', technique: 'Valid Accounts' },
    { tactic: 'Execution', technique_id: 'T1059', technique: 'Command and Scripting Interpreter' },
    { tactic: 'Command and Control', technique_id: 'T1071', technique: 'Application Layer Protocol' }
  ];

  const tacticsList = [
    'Initial Access',
    'Execution',
    'Privilege Escalation',
    'Credential Access',
    'Defense Evasion',
    'Command and Control'
  ];

  return (
    <div className="soc-surface rounded-2xl p-6 border border-slate-200/90 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-rose-600" />
          <h2 className="text-sm font-extrabold text-slate-900">MITRE ATT&CK Matrix Heatmap</h2>
        </div>
        <span className="text-xs font-mono font-bold badge-critical px-2.5 py-1 rounded-lg flex items-center gap-1.5 shadow-2xs">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Active: {tag.id} ({tag.name})</span>
        </span>
      </div>

      {/* MITRE Description Banner */}
      {tag.description && (
        <div className="p-3.5 rounded-xl bg-purple-50/80 border border-purple-200 text-xs font-sans text-purple-900 leading-relaxed font-medium">
          <strong className="font-mono block mb-0.5">{tag.id} ({tag.name}):</strong>
          {tag.description}
        </div>
      )}

      {/* MITRE Grid Matrix */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {tacticsList.map((tactic) => {
          const matched = mappings.filter(m => m.tactic?.toLowerCase() === tactic.toLowerCase());
          const hasMatch = matched.length > 0;

          return (
            <div
              key={tactic}
              className={cn(
                'p-3.5 rounded-xl border flex flex-col justify-between min-h-[120px] transition-all shadow-2xs',
                hasMatch
                  ? 'bg-white border-rose-300 ring-1 ring-rose-200/60'
                  : 'bg-slate-50/80 border-slate-200'
              )}
            >
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block font-bold">
                  TACTIC
                </span>
                <p className="text-xs font-extrabold text-slate-900 mt-0.5">{tactic}</p>
              </div>

              <div className="mt-2 space-y-1.5">
                {hasMatch ? (
                  matched.map(item => (
                    <div
                      key={item.technique_id}
                      className="p-2 rounded-lg bg-rose-50 border border-rose-200 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-700 font-extrabold text-[11px]">{item.technique_id}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${item.technique_id.replace(/\./g, '/')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={`Open MITRE ATT&CK reference for ${item.technique_id}`}
                          className="text-slate-400 hover:text-slate-700"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <p className="text-[10px] text-rose-900 truncate mt-0.5 font-bold" title={item.technique}>
                        {item.technique}
                      </p>
                    </div>
                  ))
                ) : (
                  <span className="text-[10px] text-slate-400 block font-mono font-medium">No activity detected</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
