import React from 'react';
import { Network, User, Monitor, Terminal, Globe, ArrowRight, ShieldAlert } from 'lucide-react';
import { cn } from '../lib/cn';

export default function AttackGraph({ incident }) {
  if (!incident || !incident.graph_nodes || incident.graph_nodes.length === 0) {
    return (
      <div className="soc-surface rounded-2xl p-8 border border-slate-200/90 flex flex-col items-center justify-center min-h-[300px] text-slate-500 bg-white">
        <Network className="w-12 h-12 text-slate-400 mb-2" />
        <p className="text-sm font-bold text-slate-700">No Entity Graph Available</p>
        <p className="text-xs text-slate-500">Run telemetry simulation to map entity connections across layers.</p>
      </div>
    );
  }

  const nodes = incident.graph_nodes;
  const edges = incident.graph_edges || [];

  const getNodeIcon = (type) => {
    switch (type) {
      case 'user': return <User className="w-5 h-5 text-violet-600" />;
      case 'host': return <Monitor className="w-5 h-5 text-blue-600" />;
      case 'process': return <Terminal className="w-5 h-5 text-amber-600" />;
      case 'destination': return <Globe className="w-5 h-5 text-cyan-600" />;
      default: return <Network className="w-5 h-5 text-slate-500" />;
    }
  };

  const getNodeColor = (status) => {
    switch (status) {
      case 'compromised': return 'bg-rose-50/80 border-rose-200 text-rose-900 shadow-xs';
      case 'suspicious': return 'bg-amber-50/80 border-amber-200 text-amber-900 shadow-xs';
      default: return 'bg-white border-slate-200 text-slate-800 shadow-xs';
    }
  };

  return (
    <div className="soc-surface rounded-2xl p-6 border border-slate-200/90 relative overflow-hidden space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-violet-600" />
            <h2 className="text-sm font-extrabold text-slate-900">Interactive Attack & Entity Graph</h2>
          </div>
          <p className="text-xs text-slate-600 mt-0.5 font-medium">
            Topology mapping relationship flow: User → Host → Process Tree → C2/Destination.
          </p>
        </div>
        <span className="px-3 py-1 text-xs font-mono font-bold rounded-lg bg-violet-50 text-violet-700 border border-violet-200 flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>{nodes.length} Connected Nodes</span>
        </span>
      </div>

      {/* Visual Node Flow View */}
      <div className="p-6 rounded-xl bg-slate-50/80 border border-slate-200 min-h-[240px] flex flex-col justify-center gap-4">
        <div className="flex flex-wrap items-center justify-around gap-4">
          {nodes.map((node, idx) => (
            <React.Fragment key={node.id}>
              {/* Entity Node Card */}
              <div className={cn('p-4 rounded-xl border flex flex-col items-center text-center space-y-2 transition-all hover-lift min-w-[135px]', getNodeColor(node.status))}>
                <div className="p-2.5 rounded-xl bg-white border border-slate-200 shadow-2xs">
                  {getNodeIcon(node.type)}
                </div>
                <div>
                  <p className="text-xs font-extrabold truncate max-w-[120px] font-mono">{node.label}</p>
                  <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-slate-500 block mt-0.5">
                    {node.type} ({node.layer})
                  </span>
                </div>
                <span className={cn('text-[9px] px-2 py-0.5 rounded-md font-extrabold uppercase border',
                  node.status === 'compromised' ? 'bg-rose-100 text-rose-800 border-rose-200' : 'bg-amber-100 text-amber-800 border-amber-200'
                )}>
                  {node.status}
                </span>
              </div>

              {/* Edge Arrow separator */}
              {idx < nodes.length - 1 && (
                <div className="flex flex-col items-center text-slate-500 px-1">
                  <ArrowRight className="w-5 h-5 text-blue-600" />
                  <span className="text-[9px] font-mono text-blue-700 font-bold mt-0.5">
                    {edges[idx]?.relationship || 'linked'}
                  </span>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600 pt-3 border-t border-slate-200 font-medium">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="w-2.5 h-2.5 rounded-full bg-violet-500 inline-block" />
            <span>Identity</span>
          </span>
          <span className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
            <span>Endpoint</span>
          </span>
          <span className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
            <span>Process</span>
          </span>
          <span className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" />
            <span>Network</span>
          </span>
        </div>
        <span className="text-slate-500 font-mono text-[11px]">Multi-signal graph fusion</span>
      </div>
    </div>
  );
}
