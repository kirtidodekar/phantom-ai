import React from 'react';
import { Network, User, Monitor, Terminal, Globe, ArrowRight, ShieldAlert } from 'lucide-react';

export default function AttackGraph({ incident }) {
  if (!incident || !incident.graph_nodes || incident.graph_nodes.length === 0) {
    return (
      <div className="soc-surface rounded-2xl p-6 border border-[#D9E0E8] flex flex-col items-center justify-center min-h-[280px] text-slate-600">
        <Network className="w-12 h-12 text-slate-400 mb-2" />
        <p className="text-sm font-medium text-slate-700">No Entity Graph Available</p>
        <p className="text-xs text-slate-500">Run telemetry replay to map entity connections across layers.</p>
      </div>
    );
  }

  const nodes = incident.graph_nodes;
  const edges = incident.graph_edges;

  const getNodeIcon = (type) => {
    switch (type) {
      case 'user': return <User className="w-5 h-5 text-violet-600" />;
      case 'host': return <Monitor className="w-5 h-5 text-blue-600" />;
      case 'process': return <Terminal className="w-5 h-5 text-amber-600" />;
      case 'destination': return <Globe className="w-5 h-5 text-rose-600" />;
      default: return <Network className="w-5 h-5 text-slate-500" />;
    }
  };

  const getNodeColor = (status) => {
    switch (status) {
      case 'compromised': return 'bg-rose-50 border-rose-200 text-rose-900 shadow-xs';
      case 'suspicious': return 'bg-amber-50 border-amber-200 text-amber-900 shadow-xs';
      default: return 'bg-white border-slate-200 text-slate-800 shadow-xs';
    }
  };

  return (
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] relative overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Network className="w-5 h-5 text-violet-600" />
            <h2 className="text-sm font-bold text-slate-900">Cross-Layer Attack & Entity Graph</h2>
          </div>
          <p className="text-xs text-slate-600 mt-0.5">
            Topology mapping relationship flow: User → Host → Process Tree → C2/Destination.
          </p>
        </div>
        <span className="px-2.5 py-1 text-xs font-mono font-bold rounded-lg bg-violet-50 text-violet-700 border border-violet-200 flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>{nodes.length} Entity Nodes</span>
        </span>
      </div>

      {/* Visual Node Flow View */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 min-h-[220px] flex flex-col justify-center gap-4">
        <div className="flex flex-wrap items-center justify-around gap-4">
          {nodes.map((node, idx) => (
            <React.Fragment key={node.id}>
              {/* Entity Node Card */}
              <div className={`p-3.5 rounded-xl border flex flex-col items-center text-center space-y-1.5 transition-all transform hover:scale-105 min-w-[130px] ${getNodeColor(node.status)}`}>
                <div className="p-2 rounded-lg bg-white border border-slate-200">
                  {getNodeIcon(node.type)}
                </div>
                <div>
                  <p className="text-xs font-bold truncate max-w-[120px]">{node.label}</p>
                  <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">
                    {node.type} ({node.layer})
                  </span>
                </div>
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                  node.status === 'compromised' ? 'bg-rose-100 text-rose-800 border-rose-200' : 'bg-amber-100 text-amber-800 border-amber-200'
                }`}>
                  {node.status}
                </span>
              </div>

              {/* Edge Arrow separator */}
              {idx < nodes.length - 1 && (
                <div className="flex flex-col items-center text-slate-500 px-1">
                  <ArrowRight className="w-5 h-5 text-blue-600" />
                  <span className="text-[9px] font-mono text-blue-700 mt-0.5">
                    {edges[idx]?.relationship || "linked"}
                  </span>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-600 pt-3 border-t border-slate-200 mt-3">
        <div className="flex items-center space-x-4">
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-violet-500 inline-block" />
            <span>Identity</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
            <span>Endpoint</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
            <span>Process</span>
          </span>
          <span className="flex items-center space-x-1">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
            <span>Network</span>
          </span>
        </div>
        <span className="text-slate-500 font-mono">Entity-centric graph fusion</span>
      </div>
    </div>
  );
}
