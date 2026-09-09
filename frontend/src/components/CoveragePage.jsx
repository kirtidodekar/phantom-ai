import React, { useCallback, useEffect, useState } from 'react';
import {
  Layers, Globe, Cpu, Server, Play, Pause,
  Send, Terminal, Zap, ShieldAlert, CheckCircle2, Clock
} from 'lucide-react';
import { Card, LiveDot } from './ui/Primitives';
import { api } from '../lib/api';
import { useNotifications } from '../lib/notifications';
import { cn } from '../lib/cn';

export default function CoveragePage({ currentUser }) {
  const { notify } = useNotifications();

  const [coverage, setCoverage] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [activeFormTab, setActiveFormTab] = useState('network');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [ingestionLogs, setIngestionLogs] = useState([]);

  // Form states for manual injection
  const [netForm, setNetForm] = useState({
    src_ip: '192.168.1.50',
    dest_ip: '203.0.113.55',
    src_port: 54321,
    dest_port: 443,
    protocol: 'TCP',
    bytes_transferred: 52428800,
    duration: 5.2,
  });

  const [epForm, setEpForm] = useState({
    host_id: 'SRV-AUTH01',
    user: 'attacker_mallory',
    event_type: 'login_fail',
    process_name: 'sshd',
    parent_process: 'init',
  });

  const [appForm, setAppForm] = useState({
    endpoint: '/api/v1/admin/users',
    method: 'POST',
    status_code: 401,
    response_time_ms: 112.5,
    user_id: 'attacker_mallory',
    client_ip: '192.168.1.50',
    session_id: 'sess-8891',
  });

  const fetchCoverage = useCallback(async () => {
    const data = await api.getCoverage();
    if (data) {
      setCoverage(data);
    }
  }, []);

  useEffect(() => {
    fetchCoverage();
    const timer = setInterval(fetchCoverage, 3000);
    return () => clearInterval(timer);
  }, [fetchCoverage]);

  const handleStartSim = async () => {
    try {
      const res = await api.startSimulation();
      setSimulating(true);
      notify({
        severity: 'success',
        title: 'Simulator Active',
        message: res?.message || 'Background multi-signal telemetry simulator started.',
      });
      fetchCoverage();
    } catch (err) {
      notify({ severity: 'danger', title: 'Simulator Error', message: err.message });
    }
  };

  const handleStopSim = async () => {
    try {
      const res = await api.stopSimulation();
      setSimulating(false);
      notify({
        severity: 'info',
        title: 'Simulator Paused',
        message: res?.message || 'Telemetry simulation paused.',
      });
      fetchCoverage();
    } catch (err) {
      notify({ severity: 'danger', title: 'Simulator Error', message: err.message });
    }
  };

  const handleInjectNetwork = async (e) => {
    if (e) e.preventDefault();
    setIsSubmitting(true);
    try {
      const payload = {
        ...netForm,
        src_port: Number(netForm.src_port),
        dest_port: Number(netForm.dest_port),
        bytes_transferred: Number(netForm.bytes_transferred),
        duration: Number(netForm.duration),
      };
      const res = await api.ingestNetwork(payload);
      notify({ severity: 'success', title: 'Network Flow Ingested', message: `Event ID: ${res?.event_id}` });
      setIngestionLogs((prev) => [
        { time: new Date().toLocaleTimeString(), type: 'NETWORK', tone: 'text-cyan-700 bg-cyan-50 border-cyan-200', res },
        ...prev.slice(0, 11),
      ]);
      fetchCoverage();
    } catch (err) {
      notify({ severity: 'danger', title: 'Ingestion Failed', message: err.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleInjectEndpoint = async (e) => {
    if (e) e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await api.ingestEndpoint(epForm);
      notify({ severity: 'success', title: 'Endpoint Event Ingested', message: `Event ID: ${res?.event_id}` });
      setIngestionLogs((prev) => [
        { time: new Date().toLocaleTimeString(), type: 'ENDPOINT', tone: 'text-blue-700 bg-blue-50 border-blue-200', res },
        ...prev.slice(0, 11),
      ]);
      fetchCoverage();
    } catch (err) {
      notify({ severity: 'danger', title: 'Ingestion Failed', message: err.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleInjectApp = async (e) => {
    if (e) e.preventDefault();
    setIsSubmitting(true);
    try {
      const payload = {
        ...appForm,
        status_code: Number(appForm.status_code),
        response_time_ms: Number(appForm.response_time_ms),
      };
      const res = await api.ingestApplication(payload);
      notify({ severity: 'success', title: 'Application Log Ingested', message: `Event ID: ${res?.event_id}` });
      setIngestionLogs((prev) => [
        { time: new Date().toLocaleTimeString(), type: 'APPLICATION', tone: 'text-emerald-700 bg-emerald-50 border-emerald-200', res },
        ...prev.slice(0, 11),
      ]);
      fetchCoverage();
    } catch (err) {
      notify({ severity: 'danger', title: 'Ingestion Failed', message: err.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Preset Ingestion Emitters for Fast SOC Testing
  const applyPreset = (preset) => {
    if (preset === 'brute_force') {
      setActiveFormTab('endpoint');
      setEpForm({
        host_id: 'SRV-AUTH01',
        user: 'attacker_mallory',
        event_type: 'login_fail',
        process_name: 'sshd',
        parent_process: 'init',
      });
    } else if (preset === 'c2_exfil') {
      setActiveFormTab('network');
      setNetForm({
        src_ip: '192.168.1.50',
        dest_ip: '203.0.113.55',
        src_port: 49152,
        dest_port: 443,
        protocol: 'TCP',
        bytes_transferred: 104857600,
        duration: 12.8,
      });
    } else if (preset === 'api_probe') {
      setActiveFormTab('application');
      setAppForm({
        endpoint: '/api/v1/admin/users',
        method: 'POST',
        status_code: 401,
        response_time_ms: 180.2,
        user_id: 'attacker_mallory',
        client_ip: '192.168.1.50',
        session_id: 'sess-8891',
      });
    }
  };

  const netCov = coverage?.network || { total_events: 0, active_entities_count: 0 };
  const epCov = coverage?.endpoint || { total_events: 0, active_entities_count: 0 };
  const appCov = coverage?.application || { total_events: 0, active_entities_count: 0 };
  const totalEvents = coverage?.total_ingested_events || (netCov.total_events + epCov.total_events + appCov.total_events);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner: Ingestion Engine Stats & Simulator Controls */}
      <div className="soc-surface p-6 border border-slate-200/90 flex flex-wrap items-center justify-between gap-6 bg-gradient-to-r from-white via-slate-50 to-cyan-50/20">
        <div className="space-y-1.5 max-w-2xl">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-600 text-white shadow-md shadow-cyan-500/20">
              <Layers className="w-5 h-5" />
            </div>
            <h2 className="text-base font-extrabold text-slate-900 tracking-tight">
              Multi-Signal Telemetry Ingestion & Coverage Engine
            </h2>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed font-medium">
            Ingests, normalizes, and correlates concurrent telemetry across 3 observation layers: Network packet flows, Endpoint host sensor logs, and Application API gateway streams.
          </p>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-3xl font-extrabold font-mono text-slate-900 leading-none">
              {totalEvents.toLocaleString()}
            </div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 mt-1">Total Packets Ingested</div>
          </div>

          <div className="h-10 w-px bg-slate-200" />

          {simulating ? (
            <button
              onClick={handleStopSim}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs transition shadow-md shadow-amber-500/20 cursor-pointer"
            >
              <Pause className="w-4 h-4 fill-current" />
              <span>Pause Simulator</span>
            </button>
          ) : (
            <button
              onClick={handleStartSim}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs transition shadow-md shadow-blue-500/20 cursor-pointer"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Launch Simulator</span>
            </button>
          )}
        </div>
      </div>

      {/* 3-Card Signal Coverage Overview with Distinct Accents */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Network Layer Card */}
        <Card className="space-y-4 border-cyan-200/90 bg-gradient-to-b from-white to-cyan-50/30">
          <div className="flex items-start justify-between">
            <div className="p-3 rounded-xl bg-cyan-50 border border-cyan-200 text-cyan-600 shadow-2xs">
              <Globe className="w-5 h-5" />
            </div>
            <LiveDot tone={netCov.total_events > 0 ? 'cyan' : 'neutral'} label={netCov.total_events > 0 ? 'ACTIVE STREAM' : 'IDLE'} />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-slate-900">1. Network Telemetry Layer</h3>
            <p className="text-[11px] font-mono text-cyan-700 font-bold mt-0.5">POST /ingest/network</p>
          </div>
          <div className="grid grid-cols-2 gap-3 pt-3 border-t border-slate-100 font-mono text-xs">
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">TOTAL EVENTS</span>
              <strong className="text-slate-900 text-lg font-extrabold">{netCov.total_events || 0}</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">ENTITIES</span>
              <strong className="text-slate-900 text-lg font-extrabold">{netCov.active_entities_count || 0}</strong>
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-500 flex items-center gap-1.5 truncate">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Last seen: {netCov.last_event_at ? new Date(netCov.last_event_at).toLocaleTimeString() : 'Awaiting flows...'}</span>
          </div>
        </Card>

        {/* Endpoint Layer Card */}
        <Card className="space-y-4 border-blue-200/90 bg-gradient-to-b from-white to-blue-50/30">
          <div className="flex items-start justify-between">
            <div className="p-3 rounded-xl bg-blue-50 border border-blue-200 text-blue-600 shadow-2xs">
              <Cpu className="w-5 h-5" />
            </div>
            <LiveDot tone={epCov.total_events > 0 ? 'primary' : 'neutral'} label={epCov.total_events > 0 ? 'ACTIVE STREAM' : 'IDLE'} />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-slate-900">2. Endpoint Host Sensor</h3>
            <p className="text-[11px] font-mono text-blue-700 font-bold mt-0.5">POST /ingest/endpoint</p>
          </div>
          <div className="grid grid-cols-2 gap-3 pt-3 border-t border-slate-100 font-mono text-xs">
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">TOTAL EVENTS</span>
              <strong className="text-slate-900 text-lg font-extrabold">{epCov.total_events || 0}</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">HOSTS</span>
              <strong className="text-slate-900 text-lg font-extrabold">{epCov.active_entities_count || 0}</strong>
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-500 flex items-center gap-1.5 truncate">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Last seen: {epCov.last_event_at ? new Date(epCov.last_event_at).toLocaleTimeString() : 'Awaiting host events...'}</span>
          </div>
        </Card>

        {/* Application Layer Card */}
        <Card className="space-y-4 border-emerald-200/90 bg-gradient-to-b from-white to-emerald-50/30">
          <div className="flex items-start justify-between">
            <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-600 shadow-2xs">
              <Server className="w-5 h-5" />
            </div>
            <LiveDot tone={appCov.total_events > 0 ? 'success' : 'neutral'} label={appCov.total_events > 0 ? 'ACTIVE STREAM' : 'IDLE'} />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-slate-900">3. Application Gateway Layer</h3>
            <p className="text-[11px] font-mono text-emerald-700 font-bold mt-0.5">POST /ingest/application</p>
          </div>
          <div className="grid grid-cols-2 gap-3 pt-3 border-t border-slate-100 font-mono text-xs">
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">TOTAL EVENTS</span>
              <strong className="text-slate-900 text-lg font-extrabold">{appCov.total_events || 0}</strong>
            </div>
            <div className="p-2.5 rounded-lg bg-white border border-slate-200">
              <span className="text-[10px] text-slate-500 block uppercase font-bold">SERVICES</span>
              <strong className="text-slate-900 text-lg font-extrabold">{appCov.active_entities_count || 0}</strong>
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-500 flex items-center gap-1.5 truncate">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Last seen: {appCov.last_event_at ? new Date(appCov.last_event_at).toLocaleTimeString() : 'Awaiting API logs...'}</span>
          </div>
        </Card>
      </div>

      {/* 1-Click Threat Simulation Presets */}
      <div className="soc-surface p-5 border border-slate-200/90 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-600" />
            <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-800">
              1-Click Threat Emitter Presets
            </h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono font-semibold">Pre-populates payload in studio below</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button
            type="button"
            onClick={() => applyPreset('brute_force')}
            className="p-3 rounded-xl bg-white border border-slate-200 hover:border-amber-300 hover:bg-amber-50/40 text-left transition hover-lift cursor-pointer shadow-2xs"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Brute Force Burst</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-100 text-amber-800">ENDPOINT</span>
            </div>
            <p className="text-[11px] text-slate-600 mt-1">Emits rapid SSH login failures on SRV-AUTH01.</p>
          </button>

          <button
            type="button"
            onClick={() => applyPreset('api_probe')}
            className="p-3 rounded-xl bg-white border border-slate-200 hover:border-emerald-300 hover:bg-emerald-50/40 text-left transition hover-lift cursor-pointer shadow-2xs"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Admin API Probe</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-100 text-emerald-800">APPLICATION</span>
            </div>
            <p className="text-[11px] text-slate-600 mt-1">Emits 401 unauthorized probe to /api/v1/admin/users.</p>
          </button>

          <button
            type="button"
            onClick={() => applyPreset('c2_exfil')}
            className="p-3 rounded-xl bg-white border border-slate-200 hover:border-cyan-300 hover:bg-cyan-50/40 text-left transition hover-lift cursor-pointer shadow-2xs"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">Large C2 Exfiltration</span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-100 text-cyan-800">NETWORK</span>
            </div>
            <p className="text-[11px] text-slate-600 mt-1">Emits high-volume 100MB flow to 203.0.113.55.</p>
          </button>
        </div>
      </div>

      {/* Interactive Ingestion Emitter Studio & Real-Time Terminal Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 soc-surface p-6 border border-slate-200/90 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <div className="flex items-center gap-2.5">
              <Send className="w-4 h-4 text-blue-600" />
              <h3 className="text-sm font-extrabold text-slate-900">Live Telemetry Ingestion Studio</h3>
            </div>
            <div className="flex rounded-xl bg-slate-100 p-1 border border-slate-200">
              {['network', 'endpoint', 'application'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveFormTab(tab)}
                  className={cn(
                    'px-3 py-1.5 text-xs font-extrabold rounded-lg transition capitalize cursor-pointer',
                    activeFormTab === tab
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-500 hover:text-slate-800'
                  )}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>

          {/* Form: Network */}
          {activeFormTab === 'network' && (
            <form onSubmit={handleInjectNetwork} className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Source IP (Internal Host)</label>
                  <input
                    type="text"
                    value={netForm.src_ip}
                    onChange={(e) => setNetForm({ ...netForm, src_ip: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white focus:outline-none focus:border-cyan-600 font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Destination IP (C2 Target)</label>
                  <input
                    type="text"
                    value={netForm.dest_ip}
                    onChange={(e) => setNetForm({ ...netForm, dest_ip: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white focus:outline-none focus:border-cyan-600 font-bold"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Src Port</label>
                  <input
                    type="number"
                    value={netForm.src_port}
                    onChange={(e) => setNetForm({ ...netForm, src_port: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Dest Port</label>
                  <input
                    type="number"
                    value={netForm.dest_port}
                    onChange={(e) => setNetForm({ ...netForm, dest_port: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Protocol</label>
                  <select
                    value={netForm.protocol}
                    onChange={(e) => setNetForm({ ...netForm, protocol: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold cursor-pointer"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Bytes Transferred</label>
                  <input
                    type="number"
                    value={netForm.bytes_transferred}
                    onChange={(e) => setNetForm({ ...netForm, bytes_transferred: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Duration (seconds)</label>
                  <input
                    type="number"
                    step="0.1"
                    value={netForm.duration}
                    onChange={(e) => setNetForm({ ...netForm, duration: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-700 text-white font-bold text-xs transition disabled:opacity-50 cursor-pointer shadow-md shadow-cyan-500/20"
              >
                {isSubmitting ? 'Ingesting Flow...' : 'Emit Network Flow (POST /ingest/network)'}
              </button>
            </form>
          )}

          {/* Form: Endpoint */}
          {activeFormTab === 'endpoint' && (
            <form onSubmit={handleInjectEndpoint} className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Host ID</label>
                  <input
                    type="text"
                    value={epForm.host_id}
                    onChange={(e) => setEpForm({ ...epForm, host_id: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">User Account</label>
                  <input
                    type="text"
                    value={epForm.user}
                    onChange={(e) => setEpForm({ ...epForm, user: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-bold text-slate-700 block mb-1">Event Type</label>
                <select
                  value={epForm.event_type}
                  onChange={(e) => setEpForm({ ...epForm, event_type: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold cursor-pointer"
                >
                  <option value="login_fail">login_fail (Brute Force trigger)</option>
                  <option value="login_success">login_success</option>
                  <option value="process_start">process_start (Suspicious execution)</option>
                  <option value="file_access">file_access (Sensitive credential access)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Process Name</label>
                  <input
                    type="text"
                    value={epForm.process_name}
                    onChange={(e) => setEpForm({ ...epForm, process_name: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Parent Process</label>
                  <input
                    type="text"
                    value={epForm.parent_process}
                    onChange={(e) => setEpForm({ ...epForm, parent_process: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs transition disabled:opacity-50 cursor-pointer shadow-md shadow-blue-500/20"
              >
                {isSubmitting ? 'Ingesting Event...' : 'Emit Endpoint Event (POST /ingest/endpoint)'}
              </button>
            </form>
          )}

          {/* Form: Application */}
          {activeFormTab === 'application' && (
            <form onSubmit={handleInjectApp} className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Endpoint Path</label>
                  <input
                    type="text"
                    value={appForm.endpoint}
                    onChange={(e) => setAppForm({ ...appForm, endpoint: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">HTTP Method</label>
                  <select
                    value={appForm.method}
                    onChange={(e) => setAppForm({ ...appForm, method: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold cursor-pointer"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">HTTP Status Code</label>
                  <input
                    type="number"
                    value={appForm.status_code}
                    onChange={(e) => setAppForm({ ...appForm, status_code: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Response Time (ms)</label>
                  <input
                    type="number"
                    step="0.1"
                    value={appForm.response_time_ms}
                    onChange={(e) => setAppForm({ ...appForm, response_time_ms: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">User ID</label>
                  <input
                    type="text"
                    value={appForm.user_id}
                    onChange={(e) => setAppForm({ ...appForm, user_id: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-700 block mb-1">Client IP</label>
                  <input
                    type="text"
                    value={appForm.client_ip}
                    onChange={(e) => setAppForm({ ...appForm, client_ip: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 bg-slate-50 focus:bg-white font-bold"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs transition disabled:opacity-50 cursor-pointer shadow-md shadow-emerald-500/20"
              >
                {isSubmitting ? 'Ingesting Log...' : 'Emit API Log (POST /ingest/application)'}
              </button>
            </form>
          )}
        </div>

        {/* Real-Time Live ACK Ingestion Terminal */}
        <div className="lg:col-span-5 soc-surface p-6 border border-slate-200/90 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-slate-700" />
                <h3 className="text-sm font-extrabold text-slate-900">Live Ingestion Stream ACK</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                STREAM ACTIVE
              </span>
            </div>

            <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
              {ingestionLogs.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400 font-mono bg-slate-50/50 rounded-xl border border-dashed border-slate-200">
                  <Terminal className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                  Emit a manual telemetry packet or start the attack simulator to see live JSON ACK logs.
                </div>
              ) : (
                ingestionLogs.map((log, idx) => (
                  <div key={idx} className={cn('p-3 rounded-xl border text-xs font-mono space-y-1.5 shadow-2xs', log.tone)}>
                    <div className="flex justify-between items-center">
                      <span className="font-extrabold">[{log.type}]</span>
                      <span className="text-[10px] opacity-75 font-semibold">{log.time}</span>
                    </div>
                    <div className="text-[11px] truncate font-medium">
                      Entity: <strong className="text-slate-900">{log.res?.entity_id}</strong>
                    </div>
                    <div className="text-[10px] opacity-75 truncate">
                      Event ID: {log.res?.event_id}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-100 border border-slate-200 text-[11px] font-mono text-slate-600 flex items-center justify-between">
            <span>Protocol: HTTP/1.1 JSON Ingestion</span>
            <span className="text-emerald-700 font-bold">200 OK</span>
          </div>
        </div>
      </div>
    </div>
  );
}
