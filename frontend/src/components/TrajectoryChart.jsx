import React from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts';
import { TrendingUp, AlertTriangle, Layers, ShieldCheck } from 'lucide-react';

export default function TrajectoryChart({ incident }) {
  if (!incident || !incident.score_history || incident.score_history.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6 flex flex-col items-center justify-center min-h-[300px] text-slate-500 bg-white">
        <ShieldCheck className="w-12 h-12 text-slate-400 mb-2" />
        <p className="text-sm font-medium text-slate-700">No Active Threat Trajectory</p>
        <p className="text-xs text-slate-500">Run telemetry replay to visualize real-time threat score progression.</p>
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
      case 'CRITICAL': return 'text-rose-800 border-rose-300 bg-rose-100';
      case 'HIGH': return 'text-amber-800 border-amber-300 bg-amber-100';
      case 'MEDIUM': return 'text-yellow-800 border-yellow-300 bg-yellow-100';
      default: return 'text-emerald-800 border-emerald-300 bg-emerald-100';
    }
  };

  return (
    <div className="glass-card rounded-2xl p-5 border border-slate-200 bg-white shadow-xs relative overflow-hidden">
      {/* Header Info */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-5 h-5 text-blue-600" />
            <h2 className="text-base font-bold text-slate-900">Threat Trajectory & Escalation Curve</h2>
          </div>
          <p className="text-xs text-slate-600 mt-0.5">
            Real-time stateful risk trajectory evolving across Network, Endpoint, and Identity layers.
          </p>
        </div>

        {/* Threat Score Metric Badge */}
        <div className="flex items-center space-x-3 bg-slate-50 p-2 px-3.5 rounded-xl border border-slate-200">
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-wider text-slate-500 block font-bold">Threat Score</span>
            <span className="text-2xl font-extrabold font-mono text-slate-900">
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
                <stop offset="5%" stopColor="#2563eb" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#2563eb" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.8} />
            <XAxis dataKey="step" stroke="#64748b" fontSize={11} tickLine={false} />
            <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} tickLine={false} />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="glass-card p-3 rounded-xl border border-slate-300 bg-white shadow-md text-xs space-y-1">
                      <p className="font-bold text-blue-700">{data.step} ({data.timestamp})</p>
                      <p className="text-slate-800">Threat Score: <strong className="text-slate-900 font-mono text-sm">{data.score}/100</strong></p>
                      <p className="text-slate-600 capitalize">Layer: <span className="text-amber-700 font-bold">{data.layer}</span></p>
                      <p className="text-slate-600">Trigger: <span className="text-blue-600 font-bold">{data.attack}</span></p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <ReferenceLine y={60} stroke="#d97706" strokeDasharray="4 4" label={{ value: "High Risk Threshold", fill: "#d97706", fontSize: 10 }} />
            <ReferenceLine y={80} stroke="#dc2626" strokeDasharray="4 4" label={{ value: "Critical Threshold", fill: "#dc2626", fontSize: 10 }} />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#2563eb"
              strokeWidth={3}
              fillOpacity={1}
              fill="url(#scoreGradient)"
              dot={{ r: 5, fill: "#2563eb", stroke: "#ffffff", strokeWidth: 2 }}
              activeDot={{ r: 8, fill: "#1d4ed8", stroke: "#ffffff", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Layer badges footer */}
      <div className="flex items-center justify-between border-t border-slate-200 pt-3 mt-2 text-xs text-slate-600">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-blue-600" />
          <span className="font-medium">Fused Telemetry Layers:</span>
          <div className="flex items-center space-x-1.5">
            {['identity', 'endpoint', 'network'].map(layer => {
              const active = incident.layers_involved.includes(layer);
              return (
                <span
                  key={layer}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono capitalize border ${
                    active 
                      ? 'bg-blue-100 text-blue-800 border-blue-200 font-semibold' 
                      : 'bg-slate-100 text-slate-400 border-slate-200'
                  }`}
                >
                  {layer}
                </span>
              );
            })}
          </div>
        </div>

        <div className="text-slate-600 text-[11px] font-mono">
          Entity: <span className="font-semibold text-slate-900">{incident.primary_entity}</span>
        </div>
      </div>
    </div>
  );
}
