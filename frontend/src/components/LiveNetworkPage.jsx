import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, CartesianGrid, Cell,
} from 'recharts';
import {
  Radio, Play, Square, RotateCcw, Network, Activity, Server, Globe,
  ShieldAlert, AlertTriangle, Lock, Wifi, Database, Eye, Gauge,
} from 'lucide-react';
import { Card, CardHeader, StatCard, Meter, RiskBadge, LiveDot, Pill, Donut } from './ui/Primitives';
import { api } from '../lib/api';
import { useNotifications } from '../lib/notifications';
import { useDefense } from '../lib/defense';
import { cn } from '../lib/cn';

/**
 * Live Network page.
 *
 * Renders ONLY real captured telemetry. When the monitoring host cannot
 * capture (missing Npcap/libpcap, insufficient privileges, bad interface) this
 * page shows the precise blocking reason and remediation instead of inventing
 * packet data. Empty tables mean "nothing observed", never "pretend traffic".
 */

const PROTO_COLORS = {
  TCP: '#2563EB', UDP: '#7C3AED', ICMP: '#B7791F',
  HTTP: '#0EA5E9', ICMPv6: '#16805C',
};

const REFRESH_MS = 2500; // matches the platform-wide polling cadence

function formatBytes(value = 0) {
  if (value < 1024) return `${Math.round(value)} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

function shortTime(iso) {
  if (!iso) return '--:--:--';
  const idx = String(iso).indexOf('T');
  return idx >= 0 ? String(iso).substring(idx + 1, idx + 9) : String(iso);
}

export default function LiveNetworkPage({ currentUser, onOpenEntity }) {
  const { notify } = useNotifications();
  const { blockIp, isBlocked } = useDefense();

  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [packets, setPackets] = useState([]);
  const [ips, setIps] = useState({ top_sources: [], top_destinations: [] });
  const [connections, setConnections] = useState([]);
  const [threats, setThreats] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('auto');
  const [captureFilter, setCaptureFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [controlError, setControlError] = useState(null);
  const [loading, setLoading] = useState(true);

  const alertedRef = useRef(new Set());
  const role = currentUser?.role || 'SOC Tier-2 Analyst';

  const refresh = useCallback(async () => {
    const [s, st, pk, ip, cn2, th] = await Promise.all([
      api.getNetworkStatus(),
      api.getNetworkStats(),
      api.getNetworkPackets(80),
      api.getNetworkIps(12),
      api.getNetworkConnections(25),
      api.getNetworkThreats(30),
    ]);

    if (s) setStatus(s);
    if (st) setStats(st);
    setPackets(pk?.packets || []);
    setIps(ip || { top_sources: [], top_destinations: [] });
    setConnections(cn2?.connections || []);

    const list = th?.threats || [];
    setThreats(list);
    setLoading(false);

    // Admin alerting for high-severity NETWORK detections.
    list.forEach((t) => {
      if (t.threat_score >= 70 && !alertedRef.current.has(t.threat_id)) {
        alertedRef.current.add(t.threat_id);
        notify({
          severity: t.threat_score >= 80 ? 'critical' : 'warning',
          title: `${t.threat_type} from ${t.source_ip}`,
          message: `Score ${t.threat_score}/100 · ${t.mitre_id || 'network'} · live capture`,
        });
      }
    });
  }, [notify]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    api.getNetworkInterfaces().then((data) => {
      if (cancelled) return;
      setInterfaces(data?.interfaces || []);
    });
    return () => { cancelled = true; };
  }, []);

  const monitoring = Boolean(status?.monitoring);
  const capability = status?.capability || {};
  const capturePossible = capability.capture_possible !== false;

  const handleStart = async () => {
    setBusy(true);
    setControlError(null);
    try {
      const res = await api.startNetworkMonitor(
        { interface: selectedInterface, capture_filter: captureFilter },
        role,
      );
      notify({
        severity: 'success',
        title: 'Live capture started',
        message: `Interface ${res?.interface || selectedInterface}`,
      });
      await refresh();
    } catch (error) {
      setControlError(error.message);
      notify({ severity: 'danger', title: 'Capture could not start', message: error.message });
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    setBusy(true);
    setControlError(null);
    try {
      await api.stopNetworkMonitor(role);
      notify({ severity: 'info', title: 'Live capture stopped', message: 'Returned to DEMO/replay mode.' });
      await refresh();
    } catch (error) {
      setControlError(error.message);
    } finally {
      setBusy(false);
    }
  };

  const handleReset = async () => {
    setBusy(true);
    try {
      await api.resetNetworkMonitor(role);
      alertedRef.current.clear();
      await refresh();
    } catch (error) {
      setControlError(error.message);
    } finally {
      setBusy(false);
    }
  };

  const handleBlock = (t) => {
    blockIp({
      ip: t.source_ip,
      attackType: t.threat_type,
      score: t.threat_score,
      reason: `Network detection ${t.mitre_id || ''}`.trim(),
      mode: 'manual',
      incidentId: t.incident_id || 'network',
    });
  };

  const rateHistory = (stats?.rate_history || []).map((r, i) => ({
    idx: i,
    pps: r.packets_per_second,
    bps: r.bytes_per_second,
  }));
  const protocolData = Object.entries(stats?.protocol_distribution || {}).map(([name, value]) => ({
    name, value, color: PROTO_COLORS[name] || '#7A8797',
  }));
  const topPorts = (stats?.top_ports || []).map((p) => ({ name: String(p.port), hits: p.hits }));
  const topSources = (ips.top_sources || []).slice(0, 8).map((s) => ({
    name: s.ip, packets: s.packet_count, score: s.threat_score,
  }));

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------- Mode + capability banner ---------------- */}
      <div className={cn(
        'soc-surface p-5 border flex flex-wrap items-center justify-between gap-4',
        monitoring ? 'border-emerald-200' : 'border-[#D9E0E8]',
      )}>
        <div className="space-y-1.5 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-600" />
              Live Network Monitoring
            </h2>
            <span className={cn(
              'px-2 py-0.5 rounded text-[10px] font-mono font-bold border',
              monitoring
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-slate-100 text-slate-600 border-slate-200',
            )}>
              {monitoring ? 'LIVE NETWORK TELEMETRY' : 'DEMO / REPLAY MODE'}
            </span>
            {monitoring && <LiveDot tone="success" label="CAPTURING" />}
          </div>
          <p className="text-xs text-slate-600">
            {monitoring
              ? `Observing real packets on ${status?.interface || 'interface'}. Header metadata only — payloads are never stored.`
              : 'No live capture running. Charts and tables below show only real captured telemetry.'}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <label className="sr-only" htmlFor="net-iface">Capture interface</label>
          <select
            id="net-iface"
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={monitoring || busy}
            className="px-2.5 py-1.5 rounded-md bg-slate-50 border border-slate-300 text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600 disabled:opacity-60"
          >
            <option value="auto">auto (default route)</option>
            {interfaces.map((nic) => (
              <option key={nic.name} value={nic.name}>
                {(nic.description || nic.name || '').substring(0, 42)}
              </option>
            ))}
          </select>

          <label className="sr-only" htmlFor="net-filter">BPF capture filter</label>
          <input
            id="net-filter"
            value={captureFilter}
            onChange={(e) => setCaptureFilter(e.target.value)}
            placeholder="BPF filter (optional)"
            disabled={monitoring || busy}
            className="w-40 px-2.5 py-1.5 rounded-md bg-slate-50 border border-slate-300 text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600 disabled:opacity-60"
          />

          {!monitoring ? (
            <button
              type="button"
              onClick={handleStart}
              disabled={busy || !capturePossible}
              title={capturePossible ? 'Start authorized packet capture' : 'Capture backend unavailable'}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{busy ? 'Starting…' : 'Start Monitoring'}</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleStop}
              disabled={busy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-bold transition disabled:opacity-50"
            >
              <Square className="w-3.5 h-3.5" />
              <span>Stop</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleReset}
            disabled={busy}
            aria-label="Reset network statistics"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-600 border border-slate-300 text-xs font-semibold transition disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* ---------------- Honest unavailability / error reporting ---------------- */}
      {!capturePossible && (
        <div className="soc-surface p-5 border border-amber-200 bg-amber-50 space-y-2" role="alert">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-700 shrink-0 mt-0.5" />
            <div className="min-w-0 space-y-1">
              <h3 className="text-sm font-bold text-slate-900">
                Packet capture unavailable on this host
              </h3>
              <p className="text-xs text-slate-700">
                Reason: <span className="font-mono font-bold">{capability.reason || 'unknown'}</span>
              </p>
              {capability.remediation && (
                <p className="text-xs text-slate-700">{capability.remediation}</p>
              )}
              <p className="text-[11px] text-slate-600">
                The platform will not fabricate packets. Live tables stay empty until real capture is possible.
                DEMO/replay mode remains fully available.
              </p>
            </div>
          </div>
        </div>
      )}

      {controlError && (
        <div className="soc-surface p-4 border border-rose-200 bg-rose-50 text-xs text-rose-800" role="alert">
          <span className="font-bold">Control error: </span>
          <span className="font-mono">{controlError}</span>
        </div>
      )}

      {/* ---------------- Status KPIs ---------------- */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard icon={Wifi} label="Interface" tone="primary"
          value={(status?.interface || 'none').toString().substring(0, 12)}
          footer={status?.capture_filter ? `filter: ${status.capture_filter}` : 'no filter'} />
        <StatCard icon={Activity} label="Packets/sec" tone="primary"
          value={status?.packets_per_second ?? 0}
          spark={rateHistory.map((r) => r.pps)} />
        <StatCard icon={Gauge} label="Bytes/sec" tone="violet"
          value={formatBytes(status?.bytes_per_second || 0)} />
        <StatCard icon={Server} label="Connections" tone="neutral"
          value={status?.active_connections ?? 0}
          footer={`${status?.unique_source_ips ?? 0} source IPs`} />
        <StatCard icon={Globe} label="Unique IPs" tone="success"
          value={(status?.unique_source_ips ?? 0) + (status?.unique_destination_ips ?? 0)} />
        <StatCard icon={ShieldAlert} label="Network Threats" tone="danger"
          value={status?.threat_count ?? 0}
          footer={`${status?.packets_dropped ?? 0} pkts dropped`} />
      </div>

      {/* ---------------- Throughput + protocol ---------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <Card className="lg:col-span-8 space-y-3">
          <CardHeader icon={Activity} title="Traffic Throughput"
            subtitle="Packets/sec and bytes/sec across recent aggregation windows" />
          <div className="h-[210px] w-full">
            {rateHistory.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-400">
                <Eye className="w-8 h-8 mb-2" />
                <p className="text-xs font-medium text-slate-500">No traffic observed yet</p>
                <p className="text-[11px]">Start monitoring on an authorized interface to populate this chart.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={rateHistory} margin={{ top: 10, right: 16, left: -18, bottom: 0 }}>
                  <defs>
                    <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.28} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="idx" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="soc-surface p-3 rounded-xl border border-slate-300 bg-white shadow-md text-xs space-y-1">
                        <p className="font-bold text-blue-700">Window #{d.idx}</p>
                        <p className="text-slate-800">Packets/sec: <strong className="font-mono">{d.pps}</strong></p>
                        <p className="text-slate-600">Bytes/sec: <strong className="font-mono">{formatBytes(d.bps)}</strong></p>
                      </div>
                    );
                  }} />
                  <Area type="monotone" dataKey="pps" stroke="#2563eb" strokeWidth={2.5}
                    fill="url(#ppsGradient)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
          {stats?.deviation?.available && (
            <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 pt-3 text-xs">
              <span className="text-slate-500 font-semibold">Baseline deviation:</span>
              <span className="font-mono text-slate-800">
                normal {stats.deviation.baseline_packets_per_second} pkt/s → current {stats.deviation.current_packets_per_second} pkt/s
              </span>
              <Pill tone={stats.deviation.deviation_percent > 100 ? 'danger' : 'success'}>
                {stats.deviation.deviation_percent > 0 ? '+' : ''}{stats.deviation.deviation_percent}%
              </Pill>
            </div>
          )}
        </Card>

        <Card className="lg:col-span-4 space-y-3">
          <CardHeader icon={Network} title="Protocol Distribution" subtitle="Share of observed packets" />
          {protocolData.length === 0 ? (
            <p className="text-xs text-slate-500 py-8 text-center">No protocol data observed.</p>
          ) : (
            <div className="flex items-center gap-4">
              <Donut data={protocolData} size={140} centerLabel="protocols"
                centerValue={protocolData.length} />
              <div className="space-y-1.5 min-w-0 flex-1">
                {protocolData.map((p) => (
                  <div key={p.name} className="flex items-center justify-between gap-2 text-xs">
                    <span className="flex items-center gap-1.5 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: p.color }} />
                      <span className="font-mono font-semibold text-slate-800 truncate">{p.name}</span>
                    </span>
                    <span className="font-mono text-slate-600">{p.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* ---------------- Top sources + ports ---------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="space-y-3">
          <CardHeader icon={Globe} title="Top Source IPs" subtitle="Ranked by observed packet volume" />
          <div className="h-[180px] w-full">
            {topSources.length === 0 ? (
              <p className="text-xs text-slate-500 py-14 text-center">No sources observed.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topSources} margin={{ top: 4, right: 12, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={9} tickLine={false} interval={0} angle={-18} textAnchor="end" height={42} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 10, border: '1px solid #cbd5e1' }} />
                  <Bar dataKey="packets" radius={[4, 4, 0, 0]}>
                    {topSources.map((s, i) => (
                      <Cell key={i} fill={s.score >= 80 ? '#C43D4B' : s.score >= 60 ? '#B7791F' : '#2563EB'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card className="space-y-3">
          <CardHeader icon={Lock} title="Most Targeted Ports" subtitle="Destination port hit counts" />
          <div className="h-[180px] w-full">
            {topPorts.length === 0 ? (
              <p className="text-xs text-slate-500 py-14 text-center">No port activity observed.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPorts} margin={{ top: 4, right: 12, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 10, border: '1px solid #cbd5e1' }} />
                  <Bar dataKey="hits" fill="#7C3AED" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      {/* ---------------- Network threats ---------------- */}
      <Card className="space-y-3">
        <CardHeader icon={ShieldAlert} title="Network Threats" accent="text-rose-600"
          subtitle="Detections from aggregated evidence, scored by the existing trajectory engine"
          right={<Pill tone={threats.length ? 'danger' : 'success'}>{threats.length} detected</Pill>} />
        {threats.length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center">
            No network threats detected. Benign traffic intentionally raises no incident.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th scope="col" className="py-2 pr-3">Time</th>
                  <th scope="col" className="py-2 pr-3">Source IP</th>
                  <th scope="col" className="py-2 pr-3">Threat</th>
                  <th scope="col" className="py-2 pr-3">Confidence</th>
                  <th scope="col" className="py-2 pr-3">Score</th>
                  <th scope="col" className="py-2 pr-3">Risk</th>
                  <th scope="col" className="py-2 pr-3">MITRE</th>
                  <th scope="col" className="py-2 pr-3">Incident</th>
                  <th scope="col" className="py-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {threats.map((t) => (
                  <tr key={t.threat_id} className={cn(
                    'hover:bg-slate-50 transition',
                    t.threat_score >= 80 && 'bg-rose-50/60',
                  )}>
                    <td className="py-2 pr-3 font-mono text-slate-500">{shortTime(t.detected_at)}</td>
                    <td className="py-2 pr-3 font-mono font-semibold text-slate-900">{t.source_ip}</td>
                    <td className="py-2 pr-3 text-slate-800">{t.threat_type}</td>
                    <td className="py-2 pr-3 w-24">
                      <div className="flex items-center gap-1.5">
                        <Meter value={(t.confidence || 0) * 100} height={5} className="w-12" />
                        <span className="font-mono text-slate-600">{Math.round((t.confidence || 0) * 100)}%</span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 font-mono font-bold text-slate-900">{t.threat_score}</td>
                    <td className="py-2 pr-3"><RiskBadge score={t.threat_score} showScore={false} /></td>
                    <td className="py-2 pr-3">
                      {t.mitre_id ? <Pill tone="violet">{t.mitre_id}</Pill> : <span className="text-slate-400">—</span>}
                    </td>
                    <td className="py-2 pr-3 font-mono text-[10px] text-blue-700">{t.incident_id || '—'}</td>
                    <td className="py-2">
                      {isBlocked(t.source_ip) ? (
                        <Pill tone="danger">BLOCKED</Pill>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleBlock(t)}
                          className="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-[10px] font-bold transition"
                        >
                          Block (sim)
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ---------------- IP intelligence ---------------- */}
      <Card className="space-y-3">
        <CardHeader icon={Globe} title="IP Intelligence" subtitle="Live per-address statistics and risk"
          right={<span className="text-[11px] text-slate-500 font-mono">click a row for details</span>} />
        {(ips.top_sources || []).length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center">No IP activity observed.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th scope="col" className="py-2 pr-3">IP Address</th>
                  <th scope="col" className="py-2 pr-3">Packets</th>
                  <th scope="col" className="py-2 pr-3">Bytes</th>
                  <th scope="col" className="py-2 pr-3">Conns</th>
                  <th scope="col" className="py-2 pr-3">Ports</th>
                  <th scope="col" className="py-2 pr-3">Rate</th>
                  <th scope="col" className="py-2 pr-3">Score</th>
                  <th scope="col" className="py-2">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {ips.top_sources.map((s) => (
                  <tr
                    key={s.ip}
                    onClick={() => onOpenEntity && onOpenEntity({
                      id: s.ip, label: s.ip, type: 'destination',
                      risk_score: s.threat_score, status: s.risk_level, layer: 'network',
                    })}
                    className="hover:bg-slate-50 cursor-pointer transition"
                  >
                    <td className="py-2 pr-3 font-mono font-semibold text-slate-900">{s.ip}</td>
                    <td className="py-2 pr-3 font-mono text-slate-700">{s.packet_count}</td>
                    <td className="py-2 pr-3 font-mono text-slate-600">{formatBytes(s.byte_count)}</td>
                    <td className="py-2 pr-3 font-mono text-slate-600">{s.connection_count}</td>
                    <td className="py-2 pr-3 font-mono text-slate-600">{s.unique_destination_ports}</td>
                    <td className="py-2 pr-3 font-mono text-slate-600">{s.traffic_rate}/s</td>
                    <td className="py-2 pr-3 font-mono font-bold text-slate-900">{s.threat_score}</td>
                    <td className="py-2"><RiskBadge score={s.threat_score} showScore={false} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ---------------- Live packets ---------------- */}
      <Card className="space-y-3">
        <CardHeader icon={Radio} title="Live Packet Metadata" accent="text-emerald-600"
          subtitle="Header fields only — payload content is never captured or stored"
          right={<Pill tone="neutral">{packets.length} recent</Pill>} />
        {loading ? (
          <div className="space-y-2">
            {[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-6 w-full" />)}
          </div>
        ) : packets.length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center">
            No packets captured. {capturePossible
              ? 'Start monitoring to observe live traffic.'
              : 'Capture backend unavailable on this host.'}
          </p>
        ) : (
          <div className="max-h-[380px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-white">
                <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th scope="col" className="py-2 pr-3">Time</th>
                  <th scope="col" className="py-2 pr-3">Source</th>
                  <th scope="col" className="py-2 pr-3">Destination</th>
                  <th scope="col" className="py-2 pr-3">Proto</th>
                  <th scope="col" className="py-2 pr-3">S.Port</th>
                  <th scope="col" className="py-2 pr-3">D.Port</th>
                  <th scope="col" className="py-2 pr-3">Size</th>
                  <th scope="col" className="py-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {packets.map((p, i) => (
                  <tr key={`${p.connection_id}-${i}`} className="hover:bg-slate-50 transition feed-row-enter">
                    <td className="py-1.5 pr-3 font-mono text-slate-500">{shortTime(p.timestamp)}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-800">{p.source_ip}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-800">{p.destination_ip}</td>
                    <td className="py-1.5 pr-3">
                      <span className="font-mono font-semibold" style={{ color: PROTO_COLORS[p.protocol] || '#526071' }}>
                        {p.protocol}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{p.source_port ?? '—'}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{p.destination_port ?? '—'}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{p.packet_size}B</td>
                    <td className="py-1.5">
                      <span className="font-mono text-[10px] text-slate-500 uppercase">
                        {p.tcp_flags || p.direction}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ---------------- Active connections ---------------- */}
      <Card className="space-y-3">
        <CardHeader icon={Server} title="Most Active Connections" subtitle="Recent flows by 5-tuple" />
        {connections.length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center">No active flows observed.</p>
        ) : (
          <div className="max-h-[260px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-white">
                <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th scope="col" className="py-2 pr-3">Source</th>
                  <th scope="col" className="py-2 pr-3">Destination</th>
                  <th scope="col" className="py-2 pr-3">Proto</th>
                  <th scope="col" className="py-2 pr-3">Packets</th>
                  <th scope="col" className="py-2 pr-3">Bytes</th>
                  <th scope="col" className="py-2 pr-3">Duration</th>
                  <th scope="col" className="py-2">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {connections.map((c) => (
                  <tr key={c.connection_id} className="hover:bg-slate-50 transition">
                    <td className="py-1.5 pr-3 font-mono text-slate-800">{c.source_ip}:{c.source_port ?? '—'}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-800">{c.destination_ip}:{c.destination_port ?? '—'}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{c.protocol}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{c.packet_count}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{formatBytes(c.byte_count)}</td>
                    <td className="py-1.5 pr-3 font-mono text-slate-600">{c.duration_seconds}s</td>
                    <td className="py-1.5">
                      <Pill tone={c.failed ? 'danger' : 'success'}>{c.failed ? 'RESET' : 'OK'}</Pill>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ---------------- Privacy + persistence footer ---------------- */}
      <div className="soc-surface p-4 border border-[#D9E0E8] flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px] text-slate-600">
        <span className="flex items-center gap-1.5 font-semibold text-slate-700">
          <Database className="w-3.5 h-3.5 text-blue-600" />
          Retention: {status?.config?.retention_minutes ?? 60} min
        </span>
        <span>Threat threshold: <strong className="font-mono">{status?.config?.threat_threshold ?? 70}</strong></span>
        <span>Auto-block: <strong className="font-mono">{status?.config?.auto_block ? 'ON' : 'OFF (sandboxed)'}</strong></span>
        <span>Windows: <strong className="font-mono">{(status?.config?.windows || []).join('s / ')}s</strong></span>
        <span>Persisted packets: <strong className="font-mono">{status?.packets_persisted ?? 0}</strong></span>
        <span className="text-slate-500">Metadata only — no payload capture.</span>
      </div>
    </div>
  );
}
