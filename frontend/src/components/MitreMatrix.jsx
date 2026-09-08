import React from 'react';
import { Target, ExternalLink, ShieldAlert } from 'lucide-react';

export default function MitreMatrix({ incident }) {
  if (!incident || !incident.mitre_mappings || incident.mitre_mappings.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6 text-center text-slate-400">
        <Target className="w-10 h-10 mx-auto text-slate-600 mb-2" />
        <p>No MITRE ATT&CK techniques mapped yet.</p>
      </div>
    );
  }

  const mappings = incident.mitre_mappings;

  const tacticsList = [
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Credential Access",
    "Defense Evasion",
    "Impact"
  ];

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Target className="w-5 h-5 text-rose-400" />
          <h2 className="text-base font-semibold text-slate-100">MITRE ATT&CK Taxonomy Mapping</h2>
        </div>
        <span className="text-xs font-mono text-rose-400 bg-rose-500/10 px-2.5 py-1 rounded-lg border border-rose-500/30">
          {mappings.length} Active Techniques
        </span>
      </div>

      {/* MITRE Grid Matrix */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
        {tacticsList.map((tactic) => {
          const matched = mappings.filter(m => m.tactic === tactic);
          const hasMatch = matched.length > 0;

          return (
            <div
              key={tactic}
              className={`p-3 rounded-xl border flex flex-col justify-between min-h-[110px] transition ${
                hasMatch
                  ? 'bg-slate-900/90 border-rose-500/40 shadow-lg shadow-rose-900/10'
                  : 'bg-slate-950/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block font-bold">
                  Tactic
                </span>
                <p className="text-xs font-bold text-slate-200 mt-0.5">{tactic}</p>
              </div>

              <div className="mt-2 space-y-1">
                {hasMatch ? (
                  matched.map(item => (
                    <div
                      key={item.technique_id}
                      className="p-1.5 rounded-lg bg-rose-950/80 border border-rose-500/30 text-[11px]"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-300 font-bold">{item.technique_id}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${item.technique_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-slate-400 hover:text-white"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <p className="text-[10px] text-rose-200 truncate mt-0.5" title={item.technique}>
                        {item.technique}
                      </p>
                    </div>
                  ))
                ) : (
                  <span className="text-[10px] text-slate-600 block font-mono">No detection</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
