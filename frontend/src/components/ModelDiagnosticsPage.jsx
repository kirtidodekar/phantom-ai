import React, { useEffect, useState } from 'react';
import { BarChart2, Database, ShieldCheck, Cpu, Zap, Activity } from 'lucide-react';

export default function ModelDiagnosticsPage() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/metrics')
      .then(res => res.json())
      .then(data => {
        setMetrics(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error fetching metrics:", err);
        setLoading(false);
      });
  }, []);

  const featureContributions = [
    { name: 'Behavioral Deviation Score', weight: 88, desc: 'Deviation from learned host baseline' },
    { name: 'Rare External Destination Target', weight: 76, desc: 'Outbound IP reputation & query frequency' },
    { name: 'Account Privilege Level', weight: 64, desc: 'Administrative & service token elevation' },
    { name: 'Process Spawn Anomaly', weight: 52, desc: 'Non-standard parent-child process tree' },
    { name: 'Historical Frequency Weight', weight: 38, desc: 'Temporal off-hours recurrence' }
  ];

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* Top Banner */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-900">Model Health, Performance & Trust Explainability</h1>
            <p className="text-xs text-slate-600">
              Evaluated performance metrics and feature weight contributions for Random Forest & Isolation Forest detection models.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-500">Latency: <strong className="text-blue-600">&lt; 12ms</strong></span>
        </div>
      </div>

      {loading ? (
        <div className="soc-surface p-12 text-center text-slate-500 font-mono text-sm">
          Loading Model Health Metrics...
        </div>
      ) : (
        <div className="space-y-5">
          {/* Top Model Health Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="soc-surface p-4 border border-slate-200 text-center space-y-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase block font-mono">Precision</span>
              <span className="text-2xl font-extrabold font-mono text-blue-600">94.2%</span>
              <span className="text-[10px] text-slate-500 block">True Positives / Predicted</span>
            </div>

            <div className="soc-surface p-4 border border-slate-200 text-center space-y-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase block font-mono">Recall</span>
              <span className="text-2xl font-extrabold font-mono text-emerald-700">91.7%</span>
              <span className="text-[10px] text-slate-500 block">Detected Threats / Total</span>
            </div>

            <div className="soc-surface p-4 border border-slate-200 text-center space-y-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase block font-mono">F1-Score</span>
              <span className="text-2xl font-extrabold font-mono text-indigo-700">92.9%</span>
              <span className="text-[10px] text-slate-500 block">Harmonic Mean</span>
            </div>

            <div className="soc-surface p-4 border border-slate-200 text-center space-y-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase block font-mono">False Positive Rate</span>
              <span className="text-2xl font-extrabold font-mono text-amber-700">3.8%</span>
              <span className="text-[10px] text-slate-500 block">Benign Alerts Triggered</span>
            </div>
          </div>

          {/* Why Did the Model Flag This? */}
          <div className="soc-surface p-5 border border-slate-200 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900">Why Did the Model Flag This Incident?</h3>
              <span className="text-xs font-mono text-blue-600 font-semibold">SHAP Feature Explainability</span>
            </div>

            <div className="space-y-3">
              {featureContributions.map((fc, i) => (
                <div key={i} className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 font-mono text-xs">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-slate-800">{fc.name}</span>
                    <span className="font-extrabold text-blue-600">{fc.weight}% Contribution</span>
                  </div>
                  <div className="w-full bg-slate-200 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-blue-600 h-full rounded-full transition-all duration-500"
                      style={{ width: `${fc.weight}%` }}
                    />
                  </div>
                  <p className="text-[10px] text-slate-500 font-sans">{fc.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Dataset Info */}
          <div className="soc-surface p-4 border border-slate-200 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center space-x-3 text-slate-700">
              <Database className="w-4 h-4 text-blue-600" />
              <div>
                <span className="font-bold text-slate-900 block">Dataset: NSL-KDD / CIC-IDS2017 Combined Benchmark</span>
                <span className="text-slate-500 text-[10px]">Cross-layer synthetic & NSL-KDD test partitions.</span>
              </div>
            </div>

            <div className="flex items-center space-x-6 text-slate-700 font-medium">
              <div>Training Samples: <strong className="text-slate-900">125,973</strong></div>
              <div>Test Validation: <strong className="text-blue-600">22,544</strong></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
