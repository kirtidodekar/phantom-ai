import React from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts';
import { TrendingUp, AlertTriangle, Layers, ShieldCheck } from 'lucide-react';

export default function TrajectoryChart({ incident }) {
  if (!incident || !incident.score_history || incident.score_history.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6 flex flex-col items-center justify-center min-h-[300px] text-slate-400">
        <ShieldCheck className="w-12 h-12 text-slate-600 mb-2" />
        <p className="text-sm font-medium">No Active Threat Trajectory</p>
        <p className="text-xs text-slate-500">Run the incident replay or trigger telemetry events to visualize threat progression.</p>
      </div>
    );
  }

  const chartData = incident.score_history.map((item, idx) => ({
    step: `T+${idx * 5}s`,
    score: item.score,
    layer: item.layer,
    attack: item.attack_type || item.action,
    timestamp: item.timestamp ? item.timestamp.substring(11, 19) : `Step ${idx+1}`
  }));

  const currentScore = incident.threat_score;
  const riskLevel = incident.risk_breakdown?.risk_level || "LOW";

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
      case 'HIGH': return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
      case 'MEDIUM': return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
      default: return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    }
  };

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl relative overflow-hidden">
      {/* Background glow gradient */}
      <div className="absolute top-0 right-0 w-72 h-72 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header Info */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-slate-100">Threat Trajectory & Score Escalation</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time stateful risk trajectory evolving across Network, Endpoint, and Identity layers.
          </p>
        </div>

        {/* Threat Score Metric Badge */}
        <div className="flex items-center space-x-3 bg-slate-900/90 p-2 px-3.5 rounded-xl border border-slate-800">
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">Threat Score</span>
            <span className="text-2xl font-black tracking-tight bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
              {currentScore}/100
            </span>
          </div>
          <span className={`px-2.5 py-1 text-xs font-bold rounded-lg border uppercase ${getRiskColor(riskLevel)}`}>
            {riskLevel}
          </span>
        </div>
      </div>

      {/* Recharts Area Plot */}
      <div className="h-[220px] w-full mt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
            <XAxis dataKey="step" stroke="#94a3b8" fontSize={11} tickLine={false} />
            <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={11} tickLine={false} />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="glass-card p-3 rounded-xl border border-slate-700 shadow-2xl text-xs space-y-1">
                      <p className="font-bold text-cyan-300">{data.step} ({data.timestamp})</p>
                      <p className="text-slate-200">Threat Score: <strong className="text-white font-mono text-sm">{data.score}/100</strong></p>
                      <p className="text-slate-400 capitalize">Layer: <span className="text-amber-400">{data.layer}</span></p>
                      <p className="text-slate-400">Trigger: <span className="text-cyan-400">{data.attack}</span></p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <ReferenceLine y={60} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: "High Risk Threshold", fill: "#f59e0b", fontSize: 10 }} />
            <ReferenceLine y={80} stroke="#f43f5e" strokeDasharray="4 4" label={{ value: "Critical Threshold", fill: "#f43f5e", fontSize: 10 }} />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#06b6d4"
              strokeWidth={3}
              fillOpacity={1}
              fill="url(#scoreGradient)"
              dot={{ r: 5, fill: "#06b6d4", stroke: "#0f172a", strokeWidth: 2 }}
              activeDot={{ r: 8, fill: "#38bdf8", stroke: "#ffffff", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Layer badges footer */}
      <div className="flex items-center justify-between border-t border-slate-800/80 pt-3 mt-2 text-xs text-slate-400">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Fused Telemetry Layers:</span>
          <div className="flex items-center space-x-1.5">
            {['identity', 'endpoint', 'network'].map(layer => {
              const active = incident.layers_involved.includes(layer);
              return (
                <span
                  key={layer}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono capitalize border ${
                    active 
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-semibold' 
                      : 'bg-slate-900 text-slate-600 border-slate-800'
                  }`}
                >
                  {layer}
                </span>
              );
            })}
          </div>
        </div>

        <div className="text-slate-400 text-[11px]">
          Entity: <span className="font-mono text-slate-200">{incident.primary_entity}</span>
        </div>
      </div>
    </div>
  );
}
