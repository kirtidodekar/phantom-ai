import React, { useState } from 'react';
import { X, LogIn, UserPlus, ShieldAlert, CheckCircle2, History, User, Lock, Mail } from 'lucide-react';

export default function AuthModal({ isOpen, onClose, mode, onLoginSuccess }) {
  const [authMode, setAuthMode] = useState(mode || 'login');
  const [email, setEmail] = useState('analyst@sentinel.ai');
  const [password, setPassword] = useState('••••••••');
  const [selectedRole, setSelectedRole] = useState('SOC Tier-2 Analyst');
  const [name, setName] = useState('Alex Rivera');

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onLoginSuccess({
      name: authMode === 'signup' ? name : 'Alex Rivera',
      email: email,
      role: selectedRole
    });
    onClose();
  };

  const sampleSessionHistory = [
    { id: 'SESS-904', date: 'Today, 14:22', action: 'Replayed 5-Stage SQLi Exfiltration', role: 'SOC Tier-2 Analyst' },
    { id: 'SESS-881', date: 'Yesterday, 09:15', action: 'Simulated C2 IP Block (198.51.100.99)', role: 'IR Commander' },
    { id: 'SESS-812', date: 'Sep 06, 16:40', action: 'Evaluated RF Model FPR & Feature Importances', role: 'Detection Engineer' }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-md animate-fadeIn">
      <div className="glass-card rounded-2xl p-6 border border-slate-200 bg-white shadow-xl max-w-lg w-full relative space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-700 p-1 rounded-lg bg-slate-100 border border-slate-200 transition"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-blue-100 text-blue-700 border border-blue-200">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">
              {authMode === 'login' ? 'Sign In to Sentinel-AI Workspace' : 'Create SOC Analyst Account'}
            </h2>
            <p className="text-xs text-slate-600">
              Access your personal session history, active incidents, and threat playbooks.
            </p>
          </div>
        </div>

        {/* Auth Mode Toggle */}
        <div className="flex rounded-xl bg-slate-100 p-1 border border-slate-200 text-xs">
          <button
            onClick={() => setAuthMode('login')}
            className={`flex-1 py-1.5 rounded-lg font-bold transition ${
              authMode === 'login' ? 'bg-white text-blue-700 shadow-xs border border-slate-200' : 'text-slate-600'
            }`}
          >
            Sign In
          </button>
          <button
            onClick={() => setAuthMode('signup')}
            className={`flex-1 py-1.5 rounded-lg font-bold transition ${
              authMode === 'signup' ? 'bg-white text-blue-700 shadow-xs border border-slate-200' : 'text-slate-600'
            }`}
          >
            Register Account
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {authMode === 'signup' && (
            <div>
              <label className="block text-slate-700 mb-1 font-semibold">Full Name</label>
              <div className="relative">
                <User className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Alex Rivera"
                  className="w-full pl-8 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-medium"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-slate-700 mb-1 font-semibold">Security Email</label>
            <div className="relative">
              <Mail className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@sentinel.ai"
                className="w-full pl-8 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-medium"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-700 mb-1 font-semibold">Operational Role Workspace</label>
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 focus:outline-none focus:border-blue-500 font-mono font-medium"
            >
              <option value="SOC Tier-2 Analyst">SOC Tier-2 Analyst (Threat Correlation & Graph)</option>
              <option value="Detection Engineer">Detection Engineer (ML Models & Baseline Tuning)</option>
              <option value="IR Commander">IR Commander (Containment & Action Playbooks)</option>
            </select>
          </div>

          <button
            type="submit"
            className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-sm transition active:scale-95"
          >
            {authMode === 'login' ? 'Sign In & Launch Dashboard' : 'Create & Access Platform'}
          </button>
        </form>

        {/* Personal Session History Preview */}
        {authMode === 'login' && (
          <div className="pt-3 border-t border-slate-200 space-y-2">
            <span className="text-[11px] font-mono font-bold text-slate-600 flex items-center space-x-1.5">
              <History className="w-3.5 h-3.5 text-blue-600" />
              <span>Recent Personal Audit History</span>
            </span>

            <div className="space-y-1.5 max-h-[100px] overflow-y-auto">
              {sampleSessionHistory.map((sess) => (
                <div key={sess.id} className="p-2 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between text-[10px] font-mono">
                  <div>
                    <span className="text-slate-800 font-semibold block">{sess.action}</span>
                    <span className="text-slate-500">{sess.date}</span>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-blue-100 text-blue-800 border border-blue-200">
                    {sess.role.split(' ')[0]}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
