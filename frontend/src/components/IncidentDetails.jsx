import React, { useEffect, useState } from 'react';
import { Calculator, ShieldAlert, Code2, Copy, Check } from 'lucide-react';
import { api } from '../lib/api';

export default function IncidentDetails({ incident, incidentId: propId }) {
  const [loadedIncident, setLoadedIncident] = useState(incident);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState('formula');

  const activeId = incident?.id || incident?.incident_id || propId;

  useEffect(() => {
    if (propId && (!incident || (incident.id !== propId && incident.incident_id !== propId))) {
      setLoading(true);
      api.getIncident(propId).then((data) => {
        if (data) setLoadedIncident(data);
        setLoading(false);
      });
    } else {
      setLoadedIncident(incident);
    }
  }, [propId, incident]);

  const inc = loadedIncident || incident;

  const handleCopyJson = () => {
    if (!inc) return;
    navigator.clipboard.writeText(JSON.stringify(inc, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="soc-surface rounded-2xl p-10 border border-slate-200/90 text-center text-slate-500 font-mono text-xs">
        Fetching live incident metadata from GET /api/incidents/{propId}...
      </div>
    );
  }

  if (!inc) {
    return (
      <div className="soc-surface rounded-2xl p-8 border border-slate-200/90 text-center text-slate-600">
        <Calculator className="w-10 h-10 mx-auto text-slate-400 mb-2" />
        <p className="text-xs font-bold">No active incident selected.</p>
      </div>
    );
  }

  const rb = inc.risk_breakdown || {
    rule_score: 40,
    ml_score: 30,
    agreement_bonus: 20,
    total_score: inc.threat_score || 90,
    details: []
  };

  const signals = inc.signals_involved || [];
  const timeline = inc.timeline || [];

  return (
    <div className="soc-surface rounded-2xl p-6 border border-slate-200/90 space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <ShieldAlert className="w-5 h-5 text-blue-600" />
            <h2 className="text-base font-extrabold text-slate-900 font-mono">{inc.id || inc.incident_id}</h2>
            <span className={`px-2.5 py-0.5 text-[10px] font-mono font-extrabold rounded-lg ${
              (inc.threat_score || 0) >= 80 ? 'badge-critical' : (inc.threat_score || 0) >= 60 ? 'badge-warning' : 'badge-success'
            }`}>
              {inc.risk_band || 'CRITICAL'} ({inc.threat_score || 90}/100)
            </span>
            <span className="px-2.5 py-0.5 text-[10px] font-mono font-extrabold bg-blue-50 text-blue-700 rounded-lg border border-blue-200">
              {inc.status || 'NEW'}
            </span>
          </div>
          <p className="text-xs text-slate-600 mt-1 font-medium">
            Primary Target Entity: <strong className="text-slate-900 font-mono">{inc.entity_id || inc.primary_entity}</strong>
          </p>
        </div>

        {/* Subtab Switcher */}
        <div className="flex items-center gap-2">
          <div className="flex rounded-xl bg-slate-100 p-1 border border-slate-200">
            {[
              { id: 'formula', label: 'Risk Equation' },
              { id: 'signals', label: `Signals (${signals.length || timeline.length})` },
              { id: 'json', label: 'Raw JSON Payload' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id)}
                className={`px-3 py-1.5 text-xs font-extrabold rounded-lg transition cursor-pointer ${
                  activeSubTab === tab.id
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <button
            onClick={handleCopyJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white border border-slate-300 text-xs font-bold text-slate-700 hover:bg-slate-50 transition cursor-pointer shadow-2xs"
            title="Copy Raw Incident JSON"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
          </button>
        </div>
      </div>

      {/* Explanation Banner */}
      {inc.explanation && (
        <div className="p-4 rounded-xl bg-blue-50/70 border border-blue-200 text-xs text-slate-800 leading-relaxed font-medium">
          <span className="font-extrabold text-blue-900 block mb-1 font-mono">Explainability Engine Narrative:</span>
          {inc.explanation}
        </div>
      )}

      {/* Tab 1: Mathematical Risk Breakdown */}
      {activeSubTab === 'formula' && (
        <div className="space-y-4">
          <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-700">
            Explainable Risk Scoring Equation
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center shadow-2xs">
              <span className="text-[10px] text-slate-500 font-bold block uppercase">Rule Match</span>
              <span className="text-xl font-extrabold text-blue-600">+{rb.rule_score || 40}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">Deterministic</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center shadow-2xs">
              <span className="text-[10px] text-slate-500 font-bold block uppercase">ML Anomaly</span>
              <span className="text-xl font-extrabold text-violet-600">+{rb.ml_score || 30}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">IsolationForest</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center shadow-2xs">
              <span className="text-[10px] text-slate-500 font-bold block uppercase">Agreement Bonus</span>
              <span className="text-xl font-extrabold text-amber-700">+{rb.agreement_bonus || 20}</span>
              <span className="text-[10px] text-slate-400 block mt-0.5">Multi-Signal</span>
            </div>

            <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-center shadow-2xs">
              <span className="text-[10px] text-rose-700 font-bold block uppercase">Total Threat Score</span>
              <span className="text-xl font-extrabold text-rose-700">{rb.total_score || inc.threat_score || 90}</span>
              <span className="text-[10px] text-rose-600 block mt-0.5">/ 100 Scale</span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Signals Involved List */}
      {activeSubTab === 'signals' && (
        <div className="space-y-3">
          <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-700">
            Recorded Telemetry Ingestion Evidence ({signals.length || timeline.length})
          </h3>

          <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1 font-mono text-xs">
            {signals.length === 0 && timeline.length === 0 ? (
              <p className="text-xs text-slate-500 p-4 bg-slate-50 rounded-xl">No raw signals captured yet.</p>
            ) : (
              (signals.length > 0 ? signals : timeline).map((sig, idx) => (
                <div
                  key={sig.event_id || idx}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 shadow-2xs hover-lift transition"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-100 text-blue-800">
                        {sig.source_type || 'signal'}
                      </span>
                      <span className="font-bold text-slate-900 truncate">
                        {sig.event_type || sig.details?.event_type || sig.details?.sub_event || 'telemetry_event'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 truncate font-medium">
                      {sig.summary || (sig.details ? JSON.stringify(sig.details) : 'Signal recorded')}
                    </p>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-[10px] text-slate-500 block font-semibold">
                      {sig.timestamp ? new Date(sig.timestamp).toLocaleTimeString() : 'Recent'}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Formatted JSON Payload */}
      {activeSubTab === 'json' && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-extrabold uppercase tracking-wider text-slate-700">
              Raw REST API Incident Schema
            </span>
          </div>
          <pre className="p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs overflow-x-auto max-h-[400px] border border-slate-800 leading-relaxed">
            {JSON.stringify(inc, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
