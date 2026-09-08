import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import TrajectoryChart from './components/TrajectoryChart';
import AttackGraph from './components/AttackGraph';
import IncidentDetails from './components/IncidentDetails';
import AttackTimeline from './components/AttackTimeline';
import MitreMatrix from './components/MitreMatrix';
import BaselineDiff from './components/BaselineDiff';
import AnalystActions from './components/AnalystActions';
import MetricsModal from './components/MetricsModal';
import { ShieldAlert, RefreshCw, AlertCircle } from 'lucide-react';

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [currentStage, setCurrentStage] = useState("Stage 5: Network SQLi Data Exfiltration");
  const [isReplaying, setIsReplaying] = useState(false);
  const [isMetricsOpen, setIsMetricsOpen] = useState(false);

  const fetchIncidents = async () => {
    try {
      const res = await fetch('/api/incidents');
      const data = await res.json();
      if (data && data.incidents) {
        setIncidents(data.incidents);
        if (data.incidents.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data.incidents[0].incident_id);
        }
      }
    } catch (err) {
      console.error("Error fetching incidents:", err);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2500);
    return () => clearInterval(interval);
  }, []);

  const handleStartReplay = async () => {
    setIsReplaying(true);
    setCurrentStage("Executing Full 5-Stage Replay...");
    try {
      await fetch('/api/replay/start', { method: 'POST' });
      await fetchIncidents();
      setCurrentStage("Stage 5: Network SQLi Data Exfiltration");
    } catch (err) {
      console.error("Error starting replay:", err);
    } finally {
      setIsReplaying(false);
    }
  };

  const handleStepReplay = async () => {
    try {
      const res = await fetch('/api/replay/step', { method: 'POST' });
      const data = await res.json();
      if (data.stage_name) {
        setCurrentStage(data.stage_name);
      }
      await fetchIncidents();
    } catch (err) {
      console.error("Error stepping replay:", err);
    }
  };

  const handleResetReplay = async () => {
    try {
      await fetch('/api/replay/reset', { method: 'POST' });
      setCurrentStage("Baseline Normal");
      await fetchIncidents();
    } catch (err) {
      console.error("Error resetting replay:", err);
    }
  };

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-black">
      {/* Top Navbar */}
      <Navbar
        onStartReplay={handleStartReplay}
        onStepReplay={handleStepReplay}
        onResetReplay={handleResetReplay}
        onOpenMetrics={() => setIsMetricsOpen(true)}
        isReplaying={isReplaying}
        currentStage={currentStage}
      />

      {/* Main Container */}
      <main className="flex-1 p-6 space-y-6 max-w-[1700px] w-full mx-auto">
        {/* Top Row: Trajectory Chart (70%) + Active Incidents List (30%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8">
            <TrajectoryChart incident={activeIncident} />
          </div>

          <div className="lg:col-span-4 flex flex-col">
            <div className="glass-card rounded-2xl p-5 border border-slate-800 shadow-xl flex-1 flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-base font-semibold text-slate-100">Correlated Incidents</h2>
                </div>
                <span className="px-2 py-0.5 text-xs font-mono rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {incidents.length} Active
                </span>
              </div>

              <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[300px] pr-1">
                {incidents.length > 0 ? (
                  incidents.map((inc) => (
                    <div
                      key={inc.incident_id}
                      onClick={() => setSelectedIncidentId(inc.incident_id)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition ${
                        selectedIncidentId === inc.incident_id
                          ? 'bg-slate-900 border-cyan-500/60 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/40'
                          : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-xs font-bold text-cyan-300">{inc.incident_id}</span>
                        <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                          inc.threat_score >= 80 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                          inc.threat_score >= 60 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                          'bg-emerald-500/20 text-emerald-300'
                        }`}>
                          {inc.risk_breakdown?.risk_level || "LOW"} ({inc.threat_score})
                        </span>
                      </div>
                      <p className="text-xs font-semibold text-slate-200 truncate">{inc.title}</p>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                        <span className="capitalize text-slate-300">Entity: {inc.primary_entity}</span>
                        <span className="font-mono text-slate-500">{inc.layers_involved.length} Layers</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-slate-500 text-xs font-mono">
                    No correlated incidents active.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Middle Row: Attack Graph (50%) + Explainable Risk Breakdown (50%) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <AttackGraph incident={activeIncident} />
          <IncidentDetails incident={activeIncident} />
        </div>

        {/* Third Row: Attack Story Timeline (50%) + MITRE ATT&CK Matrix (50%) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <AttackTimeline incident={activeIncident} />
          <MitreMatrix incident={activeIncident} />
        </div>

        {/* Fourth Row: Counterfactual Diff View + Analyst Controls */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <BaselineDiff incidentId={activeIncident?.incident_id} />
          <AnalystActions incident={activeIncident} onRefreshIncident={fetchIncidents} />
        </div>
      </main>

      {/* Model Report Modal */}
      <MetricsModal isOpen={isMetricsOpen} onClose={() => setIsMetricsOpen(false)} />
    </div>
  );
}
