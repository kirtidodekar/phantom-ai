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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fadeIn">
      <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-xl max-w-2xl w-full relative space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          aria-label="Close model evaluation report"
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-800 p-1 rounded-lg bg-slate-100 border border-slate-200 transition"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-blue-50 text-blue-700 border border-blue-200">
            <BarChart2 className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">ML Model Evaluation Report</h2>
            <p className="text-xs text-slate-600">
              Scikit-Learn Random Forest Classifier & Isolation Forest performance metrics on NSL-KDD / CIC-IDS2017 distribution.
            </p>
          </div>
        </div>

        {metrics ? (
          <div className="space-y-4">
            {/* Top Stat Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-500 block">Precision</span>
                <span className="text-xl font-black font-mono text-blue-600">{(metrics.precision * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-500 block">Recall</span>
                <span className="text-xl font-black font-mono text-emerald-700">{(metrics.recall * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-500 block">F1-Score</span>
                <span className="text-xl font-black font-mono text-violet-600">{(metrics.f1_score * 100).toFixed(1)}%</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-center">
                <span className="text-[10px] uppercase font-semibold text-slate-500 block">False Pos Rate</span>
                <span className="text-xl font-black font-mono text-amber-700">{(metrics.false_positive_rate * 100).toFixed(1)}%</span>
              </div>
            </div>

            {/* Feature Importances */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                <span>Top Explainable Feature Importances</span>
              </span>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                {Object.entries(metrics.feature_importances || {}).map(([feat, imp]) => (
                  <div key={feat} className="flex items-center justify-between p-2 rounded bg-white border border-slate-200">
                    <span className="text-slate-600 truncate max-w-[140px]">{feat}</span>
                    <span className="text-blue-600 font-bold">{(imp * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Dataset Info */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 p-3 rounded-xl bg-slate-50 border border-slate-200">
              <div className="flex items-center space-x-2">
                <Database className="w-4 h-4 text-blue-600" />
                <span>Dataset: {metrics.dataset_name}</span>
              </div>
              <span className="font-mono font-semibold text-slate-800 flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                <span>Total Samples: {metrics.total_samples} (Test: {metrics.test_samples})</span>
              </span>
            </div>
          </div>
        ) : (
          <div className="p-8 text-center text-slate-500 font-mono text-sm">
            Loading evaluation report...
          </div>
        )}
      </div>
    </div>
  );
}
