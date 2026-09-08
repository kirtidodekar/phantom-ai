import React, { useState } from 'react';
import { ShieldAlert, Lock, ThumbsUp, ThumbsDown, Sliders, CheckCircle, ShieldCheck } from 'lucide-react';

export default function AnalystActions({ incident, onRefreshIncident }) {
  const [actionLog, setActionLog] = useState(null);
  const [criticality, setCriticality] = useState(incident?.asset_criticality || "Standard");
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  if (!incident) return null;

  const handleSimulateBlock = async (actionType, targetId) => {
    try {
      const res = await fetch('/api/actions/simulate-block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_type: actionType,
          target_id: targetId,
          incident_id: incident.incident_id
        })
      });
      const data = await res.json();
      setActionLog(data);
      if (onRefreshIncident) onRefreshIncident();
    } catch (err) {
      console.error("Error running sandboxed action:", err);
    }
  };

  const handleToggleCriticality = async (newCriticality) => {
    setCriticality(newCriticality);
    try {
      await fetch('/api/asset/criticality', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          entity_id: incident.primary_entity,
          criticality: newCriticality
        })
      });
      if (onRefreshIncident) onRefreshIncident();
    } catch (err) {
      console.error("Error toggling criticality:", err);
    }
  };

  const handleFeedback = async (type) => {
    try {
      await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incident.incident_id,
          feedback_type: type,
          notes: "Analyst validated threat trajectory during hackathon demo."
        })
      });
      setFeedbackSubmitted(true);
    } catch (err) {
      console.error("Error submitting feedback:", err);
    }
  };

  return (
    <div className="soc-surface rounded-2xl p-5 border border-[#D9E0E8] space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-blue-600" />
          <h2 className="text-sm font-bold text-slate-900">Analyst Controls & Sandboxed Response</h2>
        </div>
        <span className="text-xs font-mono font-bold badge-success px-2.5 py-1 rounded-lg flex items-center space-x-1.5">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Safety Isolated</span>
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* 1. Sandboxed Actions */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <span className="text-xs font-bold text-slate-900 block uppercase">
            1. One-Click Mitigation Action
          </span>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => handleSimulateBlock('ISOLATE_HOST', 'WKS-042')}
              className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-semibold transition active:scale-95"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Simulate Isolate Host (WKS-042)</span>
            </button>

            <button
              onClick={() => handleSimulateBlock('BLOCK_IP', '198.51.100.99')}
              className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 text-xs font-semibold transition active:scale-95"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Simulate Block C2 IP (198.51.100.99)</span>
            </button>
          </div>
        </div>

        {/* 2. Asset Criticality Context */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <span className="text-xs font-bold text-slate-900 block uppercase">
            2. Asset Criticality Weight
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleToggleCriticality('Standard')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold border transition ${
                criticality === 'Standard'
                  ? 'bg-blue-50 text-blue-700 border-blue-300'
                  : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50'
              }`}
            >
              Standard Asset
            </button>
            <button
              onClick={() => handleToggleCriticality('High Value Target')}
              className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold border transition ${
                criticality === 'High Value Target'
                  ? 'bg-violet-50 text-violet-700 border-violet-300 shadow-xs'
                  : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50'
              }`}
            >
              High Value Target (+15)
            </button>
          </div>
        </div>

        {/* 3. Analyst Feedback Loop */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <span className="text-xs font-bold text-slate-900 block uppercase">
            3. Detection Feedback Loop
          </span>
          {feedbackSubmitted ? (
            <div className="flex items-center space-x-2 text-emerald-700 text-xs font-semibold p-2 rounded bg-emerald-50 border border-emerald-200">
              <CheckCircle className="w-4 h-4 text-emerald-600" />
              <span>Feedback logged into tuning engine!</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleFeedback('USEFUL')}
                className="flex-1 py-2 px-3 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-semibold flex items-center justify-center space-x-1.5 transition"
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>True Positive</span>
              </button>
              <button
                onClick={() => handleFeedback('FALSE_POSITIVE')}
                className="flex-1 py-2 px-3 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-semibold flex items-center justify-center space-x-1.5 transition"
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>False Positive</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Sandboxed Action Output Log */}
      {actionLog && (
        <div className="p-3.5 rounded-xl bg-blue-50 border border-blue-200 text-xs font-mono font-semibold text-blue-800 animate-fadeIn flex flex-wrap items-center justify-between gap-2">
          <span>{actionLog.message}</span>
          <span className="text-[10px] text-slate-600 uppercase px-2 py-0.5 rounded bg-white border border-slate-200">
            Audit Log ID: {actionLog.action_id}
          </span>
        </div>
      )}
    </div>
  );
}
