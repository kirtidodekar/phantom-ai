import React, { useEffect, useState } from 'react';
import { X, BarChart2, CheckCircle2, ShieldCheck, Database } from 'lucide-react';

export default function MetricsModal({ isOpen, onClose }) {
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/metrics')
        .then(res => res.json())
        .then(data => setMetrics(data))
        .catch(err => console.error("Error fetching metrics:", err));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
      <div className="glass-card rounded-2xl p-6 border border-slate-700 shadow-2xl max-w-2xl w-full relative space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg bg-slate-900 border border-slate-800 transition"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
            <BarChart2 className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100">ML Model Evaluation Report</h2>
            <p className="text-xs text-slate-400">
              Scikit-Learn Random Forest Classifier & Isolation Forest performance metrics on NSL-KDD / CIC-IDS2017 distribution.
            </p>
          </div>
        </div>

        {metrics ? (
          <div className="space-y-4">
            {/* Top Stat Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">Precision</span>
                <span className="text-xl font-black text-cyan-400">{(metrics.precision * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">Recall</span>
                <span className="text-xl font-black text-emerald-400">{(metrics.recall * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">F1-Score</span>
                <span className="text-xl font-black text-indigo-400">{(metrics.f1_score * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block">False Pos Rate</span>
                <span className="text-xl font-black text-amber-400">{(metrics.false_positive_rate * 100).toFixed(1)}%</span>
              </div>
            </div>

            {/* Feature Importances */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider block">
                Top Explainable Feature Importances
              </span>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                {Object.entries(metrics.feature_importances || {}).map(([feat, imp]) => (
                  <div key={feat} className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 truncate max-w-[140px]">{feat}</span>
                    <span className="text-cyan-400 font-bold">{(imp * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Dataset Info */}
            <div className="flex items-center justify-between text-xs text-slate-400 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
              <div className="flex items-center space-x-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Dataset: {metrics.dataset_name}</span>
              </div>
              <span className="font-mono text-slate-300">Total Samples: {metrics.total_samples} (Test: {metrics.test_samples})</span>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center text-slate-400 font-mono text-sm">
            Loading evaluation report...
          </div>
        )}
      </div>
    </div>
  );
}
