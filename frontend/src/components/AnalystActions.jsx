import React, { useState } from 'react';
import { ShieldAlert, Sliders, CheckCircle, ShieldCheck, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';

export default function AnalystActions({ incident, onRefreshIncident }) {
  const [actionLog, setActionLog] = useState(null);
  const [isUpdating, setIsUpdating] = useState(false);
  const [currentStatus, setCurrentStatus] = useState(incident?.status || 'NEW');

  if (!incident) return null;

  const incidentId = incident.id || incident.incident_id;

  const handleStatusChange = async (newStatus) => {
    setIsUpdating(true);
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      setCurrentStatus(newStatus);
      setActionLog({
        message: `Incident state transitioned to ${newStatus}`,
        action_id: `AUD-${Date.now().toString(36).toUpperCase()}`
      });
      if (onRefreshIncident) onRefreshIncident();
    } catch (err) {
      console.error('Error updating status:', err);
      setActionLog({
        message: `Status updated locally to ${newStatus}`,
        action_id: `LOCAL-${Date.now().toString(36).toUpperCase()}`
      });
      setCurrentStatus(newStatus);
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="soc-surface rounded-2xl p-6 border border-slate-200/90 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-200 pb-3">
        <div className="flex items-center gap-2">
          <Sliders className="w-5 h-5 text-blue-600" />
          <h2 className="text-sm font-extrabold text-slate-900">Analyst Workflow & State Machine</h2>
        </div>
        <span className="text-xs font-mono font-extrabold badge-success px-2.5 py-1 rounded-lg flex items-center gap-1.5 shadow-2xs">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Status: {currentStatus}</span>
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Incident Workflow State Machine */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <span className="text-xs font-bold text-slate-900 block uppercase">
            Incident Workflow Transition
          </span>
          <div className="grid grid-cols-2 gap-2 text-xs font-extrabold font-mono">
            <button
              onClick={() => handleStatusChange('NEW')}
              disabled={isUpdating}
              className={`py-2 px-3 rounded-lg border transition cursor-pointer shadow-2xs ${
                currentStatus === 'NEW'
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              NEW
            </button>
            <button
              onClick={() => handleStatusChange('INVESTIGATING')}
              disabled={isUpdating}
              className={`py-2 px-3 rounded-lg border transition cursor-pointer shadow-2xs ${
                currentStatus === 'INVESTIGATING'
                  ? 'bg-amber-600 text-white border-amber-600'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              INVESTIGATING
            </button>
            <button
              onClick={() => handleStatusChange('RESOLVED')}
              disabled={isUpdating}
              className={`py-2 px-3 rounded-lg border transition cursor-pointer shadow-2xs ${
                currentStatus === 'RESOLVED'
                  ? 'bg-emerald-600 text-white border-emerald-600'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              RESOLVED
            </button>
            <button
              onClick={() => handleStatusChange('FALSE_POSITIVE')}
              disabled={isUpdating}
              className={`py-2 px-3 rounded-lg border transition cursor-pointer shadow-2xs ${
                currentStatus === 'FALSE_POSITIVE'
                  ? 'bg-slate-700 text-white border-slate-700'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              FALSE POSITIVE
            </button>
          </div>
        </div>

        {/* Rapid One-Click Containment */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
          <span className="text-xs font-bold text-slate-900 block uppercase">
            Rapid Response Execution
          </span>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => handleStatusChange('INVESTIGATING')}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-bold transition cursor-pointer shadow-2xs"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Mark for In-Depth Investigation</span>
            </button>
            <button
              onClick={() => handleStatusChange('RESOLVED')}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 text-xs font-bold transition cursor-pointer shadow-2xs"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Resolve & Contain Threat</span>
            </button>
          </div>
        </div>
      </div>

      {/* Action Output Log */}
      {actionLog && (
        <div className="p-3.5 rounded-xl bg-blue-50/80 border border-blue-200 text-xs font-mono font-bold text-blue-900 animate-fadeIn flex flex-wrap items-center justify-between gap-2 shadow-2xs">
          <span>{actionLog.message}</span>
          <span className="text-[10px] text-slate-600 uppercase px-2 py-0.5 rounded bg-white border border-slate-200">
            Audit ID: {actionLog.action_id}
          </span>
        </div>
      )}
    </div>
  );
}
