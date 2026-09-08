import React from 'react';
import { Target, ExternalLink, ShieldAlert } from 'lucide-react';

export default function MitreMatrix({ incident }) {
  if (!incident || !incident.mitre_mappings || incident.mitre_mappings.length === 0) {
    return (
      <div className="soc-surface rounded-2xl p-6 border border-[#D9E0E8] text-center text-slate-600">
        <Target className="w-10 h-10 mx-auto text-slate-400 mb-2" />
        <p className="text-xs">No MITRE ATT&CK techniques mapped yet.</p>
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
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <Target className="w-5 h-5 text-rose-600" />
          <h2 className="text-sm font-bold text-slate-900">MITRE ATT&CK Taxonomy Mapping</h2>
        </div>
        <span className="text-xs font-mono font-bold badge-critical px-2.5 py-1 rounded-lg flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>{mappings.length} Active Techniques</span>
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
                  ? 'bg-white border-rose-200 shadow-xs'
                  : 'bg-slate-50 border-slate-200'
              }`}
            >
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block font-bold">
                  Tactic
                </span>
                <p className="text-xs font-bold text-slate-900 mt-0.5">{tactic}</p>
              </div>

              <div className="mt-2 space-y-1">
                {hasMatch ? (
                  matched.map(item => (
                    <div
                      key={item.technique_id}
                      className="p-1.5 rounded-lg bg-rose-50 border border-rose-200 text-[11px]"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-700 font-bold">{item.technique_id}</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${item.technique_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={`Open MITRE ATT&CK reference for ${item.technique_id}`}
                          className="text-slate-500 hover:text-slate-800"
                        >
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <p className="text-[10px] text-rose-800 truncate mt-0.5" title={item.technique}>
                        {item.technique}
                      </p>
                    </div>
                  ))
                ) : (
                  <span className="text-[10px] text-slate-500 block font-mono">No detection</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
