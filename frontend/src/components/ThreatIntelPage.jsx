import React from 'react';
import MitreMatrix from './MitreMatrix';
import { Target, ArrowDown, ShieldAlert, Sparkles, BookOpen } from 'lucide-react';
import { Card, CardHeader } from './ui/Primitives';

export default function ThreatIntelPage({ activeIncident }) {
  const entityId = activeIncident?.entity_id || activeIncident?.primary_entity || 'user:attacker_mallory';
  const tag = activeIncident?.mitre_tag || { id: 'T1110', name: 'Brute Force' };

  const timeline = activeIncident?.timeline || [];
  const storyNarrative = timeline.length > 0
    ? timeline.map((t, idx) => ({
        time: t.timestamp ? new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : `T+${idx * 2}m`,
        phase: t.source_type?.toUpperCase() || 'SIGNAL',
        tactic: `${tag.id} ${tag.name}`,
        desc: t.summary || `Observed anomalous signal from ${t.source_type}: ${t.event_type}`,
        confidence: `${Math.min(96, 75 + idx * 7)}%`,
        badge: idx === timeline.length - 1 ? 'badge-critical' : 'badge-warning',
        layer: t.source_type || 'endpoint'
      }))
    : [
        {
          time: 'Phase 1: 08:30:15',
          phase: 'Identity Authentication Velocity',
          tactic: `${tag.id} ${tag.name}`,
          desc: `Abnormal failed authentication velocity detected on account ${entityId}. 6 failed attempts in 60s (+3.42σ baseline divergence).`,
          confidence: '82%',
          badge: 'badge-warning',
          layer: 'identity'
        },
        {
          time: 'Phase 2: 08:32:40',
          phase: 'Endpoint Process Anomaly Spawn',
          tactic: 'T1059 Command & Scripting Interpreter',
          desc: 'Host sensor flags unexpected process spawn: sshd → bash execution on SRV-AUTH01 deviating from standard system baseline.',
          confidence: '89%',
          badge: 'badge-danger',
          layer: 'endpoint'
        },
        {
          time: 'Phase 3: 08:34:10',
          phase: 'Application Gateway Probe',
          tactic: 'T1071 Application Layer Protocol',
          desc: 'API gateway logs confirm unauthorized 401 probes matching user session attempting privilege escalation on admin routes.',
          confidence: '96%',
          badge: 'badge-critical',
          layer: 'application'
        }
      ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-6 border border-slate-200/90 flex flex-wrap items-center justify-between gap-6 bg-gradient-to-r from-white via-slate-50 to-amber-50/20">
        <div className="flex items-center gap-3.5">
          <div className="p-2.5 rounded-xl bg-amber-600 text-white shadow-md shadow-amber-500/20">
            <Target className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-extrabold text-slate-900 tracking-tight">
              Threat Story Narrative & MITRE ATT&CK Matrix
            </h1>
            <p className="text-xs text-slate-600 font-medium mt-0.5">
              Reconstructs multi-signal telemetry into an explainable chronological story mapped directly against MITRE adversary techniques.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Incident: <strong className="text-blue-700">{activeIncident?.id || activeIncident?.incident_id}</strong>
          </span>
          <span className="text-slate-500 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
            Target: <strong className="text-slate-900">{entityId}</strong>
          </span>
        </div>
      </div>

      {/* AI Explainability Narrative Highlight Card */}
      {activeIncident?.explanation && (
        <div className="soc-surface p-5 border border-blue-200 bg-gradient-to-r from-blue-50/70 to-indigo-50/40 text-xs text-slate-800 leading-relaxed space-y-1.5">
          <div className="flex items-center gap-2 text-blue-900 font-extrabold font-mono text-xs">
            <BookOpen className="w-4 h-4 text-blue-600" />
            <span>AI Multi-Signal Correlation Narrative:</span>
          </div>
          <p className="font-medium text-slate-700">{activeIncident.explanation}</p>
        </div>
      )}

      {/* Main Grid: Threat Story Progression Timeline + MITRE Matrix Context */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (55%): Chronological Story Cards */}
        <div className="lg:col-span-6 space-y-4">
          <div className="soc-surface p-6 border border-slate-200/90 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h3 className="text-sm font-extrabold text-slate-900">
                Investigation Story Evolution
              </h3>
              <span className="text-[10px] font-mono font-bold text-slate-500">
                CHRONOLOGICAL RECONSTRUCTION
              </span>
            </div>

            <div className="space-y-3.5">
              {storyNarrative.map((item, idx) => (
                <React.Fragment key={idx}>
                  <div className="p-4 rounded-xl bg-slate-50/80 border border-slate-200 space-y-2 font-mono text-xs hover-lift transition">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{item.time}</span>
                        <span className="text-slate-300">•</span>
                        <span className="font-extrabold text-blue-700">{item.phase}</span>
                      </div>
                      <span className={`${item.badge} px-2 py-0.5 text-[9px] font-extrabold rounded-md uppercase`}>
                        CONFIDENCE {item.confidence}
                      </span>
                    </div>

                    <p className="text-slate-700 font-sans text-xs leading-relaxed font-medium">
                      {item.desc}
                    </p>

                    <div className="pt-1 flex items-center justify-between">
                      <span className="inline-block px-2 py-0.5 rounded-md bg-white text-slate-700 border border-slate-300 text-[10px] font-bold">
                        Technique: {item.tactic}
                      </span>
                      <span className="text-[10px] font-bold uppercase text-slate-400 font-mono">
                        {item.layer}
                      </span>
                    </div>
                  </div>

                  {idx < storyNarrative.length - 1 && (
                    <div className="flex justify-center my-1">
                      <ArrowDown className="w-4 h-4 text-slate-400 animate-bounce" />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (45%): MITRE ATT&CK Matrix */}
        <div className="lg:col-span-6 space-y-6">
          <MitreMatrix incident={activeIncident} />
        </div>
      </div>
    </div>
  );
}
