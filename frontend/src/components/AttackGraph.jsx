import React from 'react';
import { Network, User, Monitor, Terminal, Globe, ArrowRight, ShieldAlert } from 'lucide-react';

export default function AttackGraph({ incident }) {
  if (!incident || !incident.graph_nodes || incident.graph_nodes.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6 flex flex-col items-center justify-center min-h-[280px] text-slate-400">
        <Network className="w-12 h-12 text-slate-600 mb-2" />
        <p className="text-sm font-medium">No Entity Graph Available</p>
        <p className="text-xs text-slate-500">Run telemetry replay to map entity connections across layers.</p>
      </div>
    );
  }

  const nodes = incident.graph_nodes;
  const edges = incident.graph_edges;

  const getNodeIcon = (type) => {
    switch (type) {
      case 'user': return <User className="w-5 h-5 text-purple-400" />;
      case 'host': return <Monitor className="w-5 h-5 text-cyan-400" />;
      case 'process': return <Terminal className="w-5 h-5 text-amber-400" />;
      case 'destination': return <Globe className="w-5 h-5 text-rose-400" />;
      default: return <Network className="w-5 h-5 text-slate-400" />;
    }
  };

  const getNodeColor = (status) => {
    switch (status) {
      case 'compromised': return 'bg-rose-950/80 border-rose-500/50 text-rose-200 shadow-lg shadow-rose-900/30';
      case 'suspicious': return 'bg-amber-950/80 border-amber-500/50 text-amber-200 shadow-lg shadow-amber-900/20';
      default: return 'bg-slate-900/80 border-slate-700 text-slate-200';
    }
  };

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl relative overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Network className="w-5 h-5 text-purple-400" />
            <h2 className="text-base font-semibold text-slate-100">Cross-Layer Attack & Entity Graph</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Topology mapping relationship flow: User → Host → Process Tree → C2/Destination.
          </p>
        </div>
        <span className="px-2.5 py-1 text-xs font-mono rounded-lg bg-purple-500/10 text-purple-300 border border-purple-500/30">
          {nodes.length} Entity Nodes
        </span>
      </div>

      {/* Visual Node Flow View */}
      <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 min-h-[220px] flex flex-col justify-center gap-4">
        <div className="flex flex-wrap items-center justify-around gap-4">
          {nodes.map((node, idx) => (
            <React.Fragment key={node.id}>
              {/* Entity Node Card */}
              <div className={`p-3.5 rounded-xl border flex flex-col items-center text-center space-y-1.5 transition-all transform hover:scale-105 min-w-[130px] ${getNodeColor(node.status)}`}>
                <div className="p-2 rounded-lg bg-slate-900/90 border border-slate-800">
                  {getNodeIcon(node.type)}
                </div>
                <div>
                  <p className="text-xs font-bold truncate max-w-[120px]">{node.label}</p>
                  <span className="text-[10px] uppercase font-mono tracking-wider opacity-75 block">
                    {node.type} ({node.layer})
                  </span>
                </div>
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
                  node.status === 'compromised' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-amber-500/20 text-amber-400'
                }`}>
                  {node.status}
                </span>
              </div>

              {/* Edge Arrow separator */}
              {idx < nodes.length - 1 && (
                <div className="flex flex-col items-center text-slate-500 px-1">
                  <ArrowRight className="w-5 h-5 text-cyan-400/70 animate-pulse" />
                  <span className="text-[9px] font-mono text-cyan-400/60 mt-0.5">
                    {edges[idx]?.relationship || "linked"}
                  </span>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-3 border-t border-slate-800/80 mt-3">
        <div className="flex items-center space-x-4">
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
            <span>Identity</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" />
            <span>Endpoint</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" />
            <span>Process</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-400 inline-block" />
            <span>Network</span>
          </span>
        </div>
        <span className="text-slate-500 font-mono">Entity-centric graph fusion</span>
      </div>
    </div>
  );
}
