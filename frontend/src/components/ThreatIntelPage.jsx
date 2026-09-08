import React from 'react';
import AttackTimeline from './AttackTimeline';
import MitreMatrix from './MitreMatrix';
import { Target, History, ShieldAlert, ArrowDown } from 'lucide-react';

export default function ThreatIntelPage({ activeIncident }) {
  const storyNarrative = [
    {
      time: "10:41",
      phase: "Initial Access",
      tactic: "T1078 Valid Accounts",
      desc: "Off-hours login attempt detected for service account admin_service from untrusted external IP (198.51.100.88).",
      confidence: "72%",
      badge: "badge-primary"
    },
    {
      time: "10:43",
      phase: "Execution",
      tactic: "T1059.001 PowerShell",
      desc: "Webserver parent process w3wp.exe spawned elevated cmd.exe running encoded PowerShell command payload.",
      confidence: "84%",
      badge: "badge-warning"
    },
    {
      time: "10:46",
      phase: "Persistence",
      tactic: "T1053.005 Scheduled Task",
      desc: "Created unauthorized schtasks persistence job configured to execute upon system reboot.",
      confidence: "89%",
      badge: "badge-danger"
    },
    {
      time: "10:48",
      phase: "Command & Control",
      tactic: "T1071.001 Web Protocols",
      desc: "Active HTTP GET/POST C2 communication established with rare external host 198.51.100.99 with 14.8 MB outbound payload.",
      confidence: "96%",
      badge: "badge-critical"
    }
  ];

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
            <Target className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900">Threat Story & Narrative Evolution</h1>
            <p className="text-xs text-slate-600">
              Step-by-step chronological narrative connecting raw events into an explainable, contextual threat progression story.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-500">Active Investigation: <strong className="text-slate-900">{activeIncident?.incident_id || "INC-2048"}</strong></span>
        </div>
      </div>

      {/* Main Grid: Threat Story Timeline + MITRE Matrix Context */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (55%): Chronological Story Cards */}
        <div className="lg:col-span-7 space-y-3">
          <div className="soc-surface p-5 border border-[#D9E0E8] space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Investigation Story Progression</h3>

            <div className="space-y-3">
              {storyNarrative.map((item, idx) => (
                <React.Fragment key={idx}>
                  <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-900">{item.time}</span>
                        <span className="text-slate-400">•</span>
                        <span className="font-bold text-blue-700">{item.phase}</span>
                      </div>
                      <span className={`${item.badge} px-2 py-0.5 text-[10px] font-bold rounded uppercase`}>
                        CONFIDENCE {item.confidence}
                      </span>
                    </div>

                    <p className="text-slate-700 font-sans text-xs leading-relaxed">{item.desc}</p>

                    <span className="inline-block px-2 py-0.5 rounded bg-white text-slate-600 border border-slate-300 text-[10px]">
                      Technique: {item.tactic}
                    </span>
                  </div>

                  {idx < storyNarrative.length - 1 && (
                    <div className="flex justify-center my-1">
                      <ArrowDown className="w-4 h-4 text-slate-400" />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (45%): MITRE ATT&CK Framework */}
        <div className="lg:col-span-5 space-y-5">
          <MitreMatrix incident={activeIncident} />
        </div>
      </div>
    </div>
  );
}
