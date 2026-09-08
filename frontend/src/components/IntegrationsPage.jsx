import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Database,
  Cloud,
  Server,
  Cpu,
  Network,
  Radio,
  Wifi,
  Activity,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Zap,
  Camera,
  Thermometer,
  Router,
  Layers,
  ArrowRight,
  Boxes,
  Settings,
  Send,
  Gauge,
  HardDrive,
  Package,
  GitBranch,
} from 'lucide-react';
import { Card, CardHeader, StatCard, Toggle, Meter, RiskBadge, Sparkline, Donut, Pill } from './ui/Primitives';
import { api } from '../lib/api';
import { useNotifications } from '../lib/notifications';
import { cn } from '../lib/cn';

/**
 * IntegrationsPage — enterprise fit-and-finish view: where Sentinel AI sends
 * its findings (SIEM/SOAR), how it scales out across cloud regions, and what
 * IoT estate it covers.
 *
 * Data comes from `api.getIntegrations()`. That call fails soft, so a complete
 * representative dataset is used whenever the backend is unreachable — the page
 * is always populated rather than showing a broken shell.
 */

/* ------------------------------------------------------------------ */
/* Fallback dataset                                                    */
/* ------------------------------------------------------------------ */

const FALLBACK = {
  siem: [
    {
      name: 'Splunk Enterprise Security',
      vendor: 'Splunk',
      status: 'connected',
      protocol: 'HTTP Event Collector (HEC)',
      format: 'CIM / CEF',
      events_forwarded: 4821904,
      last_sync: '4s ago',
      latency_ms: 38,
      throughput: [12, 18, 15, 22, 26, 21, 29, 33, 28, 35, 31, 38],
    },
    {
      name: 'IBM QRadar',
      vendor: 'IBM',
      status: 'connected',
      protocol: 'Syslog CEF (TLS 6514)',
      format: 'CEF',
      events_forwarded: 2140377,
      last_sync: '11s ago',
      latency_ms: 64,
      throughput: [9, 11, 14, 12, 17, 16, 19, 18, 22, 20, 24, 23],
    },
    {
      name: 'Microsoft Sentinel',
      vendor: 'Microsoft',
      status: 'degraded',
      protocol: 'Graph Security API',
      format: 'OCSF',
      events_forwarded: 1687215,
      last_sync: '2m 40s ago',
      latency_ms: 412,
      throughput: [21, 19, 23, 16, 12, 14, 9, 11, 7, 10, 6, 8],
    },
    {
      name: 'Elastic Security',
      vendor: 'Elastic',
      status: 'connected',
      protocol: 'Elastic Bulk API',
      format: 'ECS',
      events_forwarded: 6903488,
      last_sync: '2s ago',
      latency_ms: 21,
      throughput: [28, 31, 30, 36, 34, 41, 39, 45, 43, 49, 47, 52],
    },
  ],
  cloud: [
    { provider: 'AWS', region: 'us-east-1', status: 'healthy', nodes: 14, ingest_gbps: 4.8, autoscale: true, utilization: 68 },
    { provider: 'Azure', region: 'westeurope', status: 'healthy', nodes: 9, ingest_gbps: 3.1, autoscale: true, utilization: 54 },
    { provider: 'GCP', region: 'asia-south1', status: 'scaling', nodes: 6, ingest_gbps: 1.9, autoscale: true, utilization: 87 },
  ],
  iot: {
    total_devices: 1428,
    online: 1362,
    at_risk: 37,
    protocols: [
      { name: 'MQTT', value: 612 },
      { name: 'CoAP', value: 341 },
      { name: 'Zigbee', value: 289 },
      { name: 'BLE', value: 186 },
    ],
    devices: [
      { id: 'CAM-0142', type: 'IP Camera', protocol: 'MQTT', ip: '10.42.7.14', firmware: 'v2.1.8', status: 'online', risk_score: 91 },
      { id: 'PLC-0031', type: 'PLC Controller', protocol: 'CoAP', ip: '10.42.11.31', firmware: 'v4.0.2', status: 'online', risk_score: 84 },
      { id: 'MTR-2207', type: 'Smart Meter', protocol: 'Zigbee', ip: '10.42.19.207', firmware: 'v1.6.0', status: 'online', risk_score: 62 },
      { id: 'PMP-0088', type: 'Infusion Pump', protocol: 'BLE', ip: '10.42.23.88', firmware: 'v3.2.1', status: 'degraded', risk_score: 88 },
      { id: 'THM-1140', type: 'Thermostat', protocol: 'MQTT', ip: '10.42.7.140', firmware: 'v5.4.0', status: 'online', risk_score: 24 },
      { id: 'CAM-0219', type: 'IP Camera', protocol: 'MQTT', ip: '10.42.7.219', firmware: 'v1.9.4', status: 'online', risk_score: 47 },
      { id: 'GTW-0004', type: 'Edge Gateway', protocol: 'CoAP', ip: '10.42.2.4', firmware: 'v7.1.0', status: 'online', risk_score: 18 },
      { id: 'LCK-0512', type: 'Smart Lock', protocol: 'Zigbee', ip: '10.42.19.12', firmware: 'v2.0.9', status: 'offline', risk_score: 71 },
      { id: 'SNS-3301', type: 'Vibration Sensor', protocol: 'BLE', ip: '10.42.23.101', firmware: 'v1.1.2', status: 'online', risk_score: 31 },
    ],
  },
};

const PROTOCOL_COLORS = {
  MQTT: '#2563EB',
  CoAP: '#7C3AED',
  Zigbee: '#16805C',
  BLE: '#B7791F',
};

const STATUS_TONE = {
  connected: 'success',
  healthy: 'success',
  online: 'success',
  degraded: 'warning',
  scaling: 'warning',
  disconnected: 'neutral',
  offline: 'neutral',
};

const DEVICE_ICONS = {
  'IP Camera': Camera,
  Thermostat: Thermometer,
  'PLC Controller': Cpu,
  'Smart Meter': Gauge,
  'Infusion Pump': Activity,
  'Edge Gateway': Router,
  'Smart Lock': HardDrive,
  'Vibration Sensor': Radio,
};

const VENDOR_ICONS = {
  Splunk: Database,
  IBM: Server,
  Microsoft: Cloud,
  Elastic: Layers,
};

const PIPELINE = [
  { label: 'Telemetry Sources', sub: 'network · endpoint · identity · IoT', icon: Radio },
  { label: 'Normalization', sub: 'schema unification', icon: Layers },
  { label: 'AI Detection', sub: 'RandomForest + IsolationForest', icon: Cpu },
  { label: 'Correlation', sub: 'cross-layer entity graph', icon: Network },
  { label: 'Risk Scoring', sub: 'stateful trajectory', icon: Gauge },
  { label: 'SIEM / SOAR Export', sub: 'CEF · ECS · OCSF', icon: Send },
];

const ARCHITECTURE_NOTES = [
  { title: 'Pluggable Detectors', body: 'Each model registers behind a common detector interface, so new classifiers drop in without touching the pipeline.', icon: Boxes },
  { title: 'Stateless API Workers', body: 'Request handlers keep no session affinity, so any worker can serve any tenant and restarts cost nothing.', icon: Server },
  { title: 'Horizontal Scale-Out', body: 'Ingest partitions by entity hash, letting each region add nodes independently as traffic grows.', icon: GitBranch },
  { title: 'Versioned Model Registry', body: 'Every artifact is pinned by version and hash, making rollback and A/B evaluation a config change.', icon: Package },
];

const IOT_ATTACK_CLASSES = [
  { name: 'Probe / Reconnaissance', desc: 'Sweeps and fingerprinting against exposed device services.' },
  { name: 'DDoS / Mirai-style Botnet', desc: 'Mass-recruited devices generating volumetric floods.' },
  { name: 'Malware C2', desc: 'Beaconing from implanted firmware to external controllers.' },
  { name: 'Unauthorized Access', desc: 'Default-credential and replay attempts on device management planes.' },
];

const nf = new Intl.NumberFormat('en-US');

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function IntegrationsPage() {
  const { notify } = useNotifications();

  const [data, setData] = useState(FALLBACK);
  const [live, setLive] = useState(false);
  const [forwarding, setForwarding] = useState(() =>
    Object.fromEntries(FALLBACK.siem.map((s) => [s.name, s.status !== 'disconnected']))
  );
  const [autoscale, setAutoscale] = useState(() =>
    Object.fromEntries(FALLBACK.cloud.map((c) => [`${c.provider}:${c.region}`, c.autoscale]))
  );
  const [protocolFilter, setProtocolFilter] = useState('ALL');

  /* ---- load integration status (fail-soft to the local dataset) ---- */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const remote = await api.getIntegrations();
      if (cancelled || !remote) return;
      const merged = {
        siem: remote.siem?.length ? remote.siem : FALLBACK.siem,
        cloud: remote.cloud?.length ? remote.cloud : FALLBACK.cloud,
        iot: remote.iot?.devices?.length ? remote.iot : FALLBACK.iot,
      };
      setData(merged);
      setLive(true);
      setForwarding(Object.fromEntries(merged.siem.map((s) => [s.name, s.status !== 'disconnected'])));
      setAutoscale(Object.fromEntries(merged.cloud.map((c) => [`${c.provider}:${c.region}`, c.autoscale ?? true])));
    })();
    return () => { cancelled = true; };
  }, []);

  const siem = data.siem ?? FALLBACK.siem;
  const cloud = data.cloud ?? FALLBACK.cloud;
  const iot = data.iot ?? FALLBACK.iot;

  /* ---- handlers ---------------------------------------------------- */
  const toggleForwarding = useCallback((connector, value) => {
    setForwarding((prev) => ({ ...prev, [connector.name]: value }));
    notify({
      severity: value ? 'success' : 'warning',
      title: value ? `Forwarding resumed → ${connector.vendor}` : `Forwarding paused → ${connector.vendor}`,
      message: value
        ? `${connector.name} is receiving normalized events over ${connector.protocol}.`
        : `${connector.name} will stop receiving events. Findings stay queued locally.`,
    });
  }, [notify]);

  const toggleAutoscale = useCallback((node, value) => {
    const key = `${node.provider}:${node.region}`;
    setAutoscale((prev) => ({ ...prev, [key]: value }));
    notify({
      severity: 'info',
      title: value ? `Autoscaling enabled — ${node.region}` : `Autoscaling disabled — ${node.region}`,
      message: value
        ? `${node.provider} ${node.region} will add ingest nodes as throughput climbs.`
        : `${node.provider} ${node.region} is pinned at ${node.nodes} nodes.`,
    });
  }, [notify]);

  /* ---- derived ----------------------------------------------------- */
  const totalEvents = useMemo(
    () => siem.reduce((sum, s) => sum + (s.events_forwarded ?? 0), 0),
    [siem]
  );
  const activeConnectors = useMemo(
    () => siem.filter((s) => forwarding[s.name] && s.status !== 'disconnected').length,
    [siem, forwarding]
  );
  const totalNodes = useMemo(() => cloud.reduce((sum, c) => sum + (c.nodes ?? 0), 0), [cloud]);
  const aggregateIngest = useMemo(
    () => cloud.reduce((sum, c) => sum + (c.ingest_gbps ?? 0), 0),
    [cloud]
  );
  const regionsOnline = useMemo(
    () => cloud.filter((c) => c.status !== 'offline').length,
    [cloud]
  );

  const protocolData = useMemo(() => {
    const list = iot.protocols?.length
      ? iot.protocols
      : Object.entries(
          (iot.devices ?? []).reduce((acc, d) => ({ ...acc, [d.protocol]: (acc[d.protocol] ?? 0) + 1 }), {})
        ).map(([name, value]) => ({ name, value }));
    return list.map((p) => ({
      name: typeof p === 'string' ? p : p.name,
      value: typeof p === 'string' ? 1 : p.value,
      color: PROTOCOL_COLORS[typeof p === 'string' ? p : p.name] ?? '#64748B',
    }));
  }, [iot]);

  const protocolOptions = useMemo(
    () => ['ALL', ...Array.from(new Set((iot.devices ?? []).map((d) => d.protocol)))],
    [iot]
  );

  const visibleDevices = useMemo(() => {
    const devices = iot.devices ?? [];
    return protocolFilter === 'ALL' ? devices : devices.filter((d) => d.protocol === protocolFilter);
  }, [iot, protocolFilter]);

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------- Header ---------------- */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-start justify-between gap-4 shadow-xs">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 shrink-0">
            <Network className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-bold text-slate-900">Integrations, Scale-Out &amp; IoT Coverage</h1>
            <p className="text-xs text-slate-600 leading-snug">
              Where findings are exported, how ingest scales across regions, and which parts of the device estate
              Sentinel currently observes.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
          <Pill tone={live ? 'success' : 'neutral'}>{live ? 'LIVE STATUS' : 'REFERENCE STATUS'}</Pill>
          <span className="text-slate-500">
            Events forwarded: <strong className="text-slate-900">{nf.format(totalEvents)}</strong>
          </span>
        </div>
      </div>

      {/* ---------------- SIEM connectors ---------------- */}
      <Card className="space-y-4">
        <CardHeader
          icon={Database}
          title="SIEM / SOAR Connectors"
          subtitle="Normalized incidents are pushed downstream so existing analyst workflows stay unchanged."
          right={<Pill tone="primary">{activeConnectors}/{siem.length} FORWARDING</Pill>}
        />

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {siem.map((connector) => {
            const Icon = VENDOR_ICONS[connector.vendor] ?? Database;
            const tone = STATUS_TONE[connector.status] ?? 'neutral';
            const enabled = forwarding[connector.name] ?? true;
            return (
              <div
                key={connector.name}
                className="rounded-lg border border-slate-200 bg-white p-4 space-y-3 hover-lift"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5 min-w-0">
                    <span className="rounded-lg bg-slate-50 border border-slate-200 p-2 shrink-0">
                      <Icon className="w-4 h-4 text-blue-600" />
                    </span>
                    <div className="min-w-0">
                      <p className="text-xs font-bold text-slate-900 truncate">{connector.name}</p>
                      <p className="text-[11px] text-slate-500">{connector.vendor}</p>
                    </div>
                  </div>
                  <Pill tone={tone}>{String(connector.status).toUpperCase()}</Pill>
                </div>

                <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Transport</dt>
                    <dd className="text-[11px] font-mono text-slate-800 truncate">{connector.protocol}</dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Events Forwarded</dt>
                    <dd className="text-[11px] font-mono font-bold text-slate-900">
                      {nf.format(connector.events_forwarded ?? 0)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Last Sync</dt>
                    <dd className="text-[11px] font-mono text-slate-800">{connector.last_sync ?? '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Latency</dt>
                    <dd
                      className={cn(
                        'text-[11px] font-mono font-bold',
                        (connector.latency_ms ?? 0) > 250 ? 'text-amber-700' : 'text-emerald-700'
                      )}
                    >
                      {connector.latency_ms ?? '—'} ms
                    </dd>
                  </div>
                </dl>

                <div className="flex items-center gap-3">
                  <div className="h-9 flex-1 min-w-0">
                    <Sparkline data={connector.throughput ?? []} tone={tone === 'warning' ? 'warning' : 'primary'} />
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 shrink-0">throughput / 12m</span>
                </div>

                <div className="border-t border-slate-200 pt-3 space-y-2">
                  <Toggle
                    checked={enabled}
                    onChange={(value) => toggleForwarding(connector, value)}
                    tone="success"
                    label="Forward events"
                    description={`Serialized as ${connector.format ?? 'ECS'}`}
                  />
                </div>
              </div>
            );
          })}
        </div>

        <p className="flex items-start gap-1.5 text-[11px] text-slate-500 border-t border-slate-200 pt-3 leading-snug">
          <Send className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-px" />
          Forwarding format is negotiated per connector — CEF for syslog-based receivers, ECS for Elastic, and OCSF for
          Graph-based ingestion. Field mapping happens once during normalization, so adding a receiver does not require
          a new transform.
        </p>
      </Card>

      {/* ---------------- Cloud deployment ---------------- */}
      <Card className="space-y-4">
        <CardHeader
          icon={Cloud}
          title="Cloud Deployment & Regional Scale-Out"
          subtitle="Ingest workers run per region so telemetry is processed close to where it is produced."
          right={<Pill tone="success">{regionsOnline}/{cloud.length} REGIONS ONLINE</Pill>}
        />

        {/* aggregate strip */}
        <div className="grid grid-cols-3 gap-2.5">
          {[
            { label: 'Total Nodes', value: nf.format(totalNodes), icon: Server },
            { label: 'Aggregate Ingest', value: `${aggregateIngest.toFixed(1)} Gbps`, icon: Zap },
            { label: 'Regions Online', value: `${regionsOnline} / ${cloud.length}`, icon: Globe },
          ].map((m) => {
            const Icon = m.icon;
            return (
              <div key={m.label} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 flex items-center gap-2.5">
                <Icon className="w-4 h-4 text-blue-600 shrink-0" />
                <div className="min-w-0">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{m.label}</p>
                  <p className="text-sm font-extrabold font-mono text-slate-900 leading-tight">{m.value}</p>
                </div>
              </div>
            );
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {cloud.map((node) => {
            const key = `${node.provider}:${node.region}`;
            const tone = STATUS_TONE[node.status] ?? 'neutral';
            const util = node.utilization ?? 60;
            return (
              <div key={key} className="rounded-lg border border-slate-200 bg-white p-4 space-y-3 hover-lift">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-slate-900">{node.provider}</p>
                    <p className="text-[11px] font-mono text-slate-500 truncate">{node.region}</p>
                  </div>
                  <Pill tone={tone}>{String(node.status).toUpperCase()}</Pill>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Nodes</p>
                    <p className="text-lg font-extrabold font-mono text-slate-900 leading-tight">{node.nodes ?? 0}</p>
                  </div>
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Ingest</p>
                    <p className="text-lg font-extrabold font-mono text-slate-900 leading-tight">
                      {(node.ingest_gbps ?? 0).toFixed(1)}
                      <span className="text-[11px] font-bold text-slate-500"> Gbps</span>
                    </p>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[10px] font-mono">
                    <span className="font-bold uppercase tracking-wider text-slate-500">Capacity Utilization</span>
                    <span className={cn('font-bold', util >= 85 ? 'text-rose-700' : util >= 70 ? 'text-amber-700' : 'text-emerald-700')}>
                      {util}%
                    </span>
                  </div>
                  <Meter value={util} tone={util >= 85 ? 'danger' : util >= 70 ? 'warning' : 'success'} />
                </div>

                <div className="border-t border-slate-200 pt-3">
                  <Toggle
                    checked={autoscale[key] ?? true}
                    onChange={(value) => toggleAutoscale(node, value)}
                    label="Autoscale"
                    description="Add nodes automatically past 80% utilization"
                  />
                </div>
              </div>
            );
          })}
        </div>

        <p className="flex items-start gap-1.5 text-[11px] text-slate-500 border-t border-slate-200 pt-3 leading-snug">
          <Settings className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-px" />
          Ingest is partitioned by entity hash, so a region under load can add workers without rebalancing the others.
          That keeps detection latency flat as monitored traffic grows from a lab estate to enterprise volume.
        </p>
      </Card>

      {/* ---------------- IoT coverage ---------------- */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <Card className="xl:col-span-4 space-y-4">
          <CardHeader
            icon={Wifi}
            accent="text-violet-600"
            title="IoT Estate"
            subtitle="Constrained devices monitored through gateway telemetry."
          />

          <div className="grid grid-cols-1 sm:grid-cols-3 xl:grid-cols-1 gap-4">
            <StatCard icon={Boxes} label="Total Devices" value={nf.format(iot.total_devices ?? 0)} tone="primary" />
            <StatCard icon={ShieldCheck} label="Online" value={nf.format(iot.online ?? 0)} tone="success" />
            <StatCard icon={AlertTriangle} label="At Risk" value={nf.format(iot.at_risk ?? 0)} tone="danger" />
          </div>

          <div className="flex flex-col items-center gap-3 border-t border-slate-200 pt-4">
            <Donut data={protocolData} centerLabel="devices" size={168} />
            <ul className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full">
              {protocolData.map((p) => (
                <li key={p.name} className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="flex items-center gap-1.5 min-w-0">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: p.color }} />
                    <span className="font-semibold text-slate-700 truncate">{p.name}</span>
                  </span>
                  <span className="font-mono font-bold text-slate-900 shrink-0">{nf.format(p.value)}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card className="xl:col-span-8 space-y-4">
          <CardHeader
            icon={Radio}
            accent="text-violet-600"
            title="Monitored Devices"
            subtitle="Rows shaded rose exceed the at-risk threshold and are prioritized for triage."
            right={
              <div className="flex items-center gap-2">
                <label htmlFor="protocol-filter" className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  Protocol
                </label>
                <select
                  id="protocol-filter"
                  value={protocolFilter}
                  onChange={(e) => setProtocolFilter(e.target.value)}
                  className="rounded-md border border-slate-300 bg-white px-2 py-1 text-[11px] font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                >
                  {protocolOptions.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
            }
          />

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <caption className="sr-only">Monitored IoT devices with protocol, firmware and risk</caption>
              <thead>
                <tr className="border-b border-slate-200">
                  {['Device ID', 'Type', 'Protocol', 'IP', 'Firmware', 'Status', 'Risk'].map((h) => (
                    <th
                      key={h}
                      scope="col"
                      className="px-2 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleDevices.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-2 py-8 text-center text-xs text-slate-500">
                      No devices match the {protocolFilter} filter.
                    </td>
                  </tr>
                ) : (
                  visibleDevices.map((device) => {
                    const Icon = DEVICE_ICONS[device.type] ?? Cpu;
                    const atRisk = (device.risk_score ?? 0) >= 80;
                    return (
                      <tr
                        key={device.id}
                        className={cn(
                          'border-b border-slate-100 last:border-0 transition-colors',
                          atRisk ? 'bg-rose-50/70 hover:bg-rose-50' : 'hover:bg-slate-50'
                        )}
                      >
                        <td className="px-2 py-2.5 text-xs font-mono font-bold text-slate-900 whitespace-nowrap">
                          {device.id}
                        </td>
                        <td className="px-2 py-2.5 whitespace-nowrap">
                          <span className="flex items-center gap-1.5 text-xs text-slate-700">
                            <Icon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            {device.type}
                          </span>
                        </td>
                        <td className="px-2 py-2.5 whitespace-nowrap">
                          <span
                            className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                            style={{
                              color: PROTOCOL_COLORS[device.protocol] ?? '#475569',
                              backgroundColor: `${PROTOCOL_COLORS[device.protocol] ?? '#475569'}14`,
                            }}
                          >
                            {device.protocol}
                          </span>
                        </td>
                        <td className="px-2 py-2.5 text-[11px] font-mono text-slate-700 whitespace-nowrap">{device.ip}</td>
                        <td className="px-2 py-2.5 text-[11px] font-mono text-slate-500 whitespace-nowrap">{device.firmware}</td>
                        <td className="px-2 py-2.5 whitespace-nowrap">
                          <Pill tone={STATUS_TONE[device.status] ?? 'neutral'}>{String(device.status).toUpperCase()}</Pill>
                        </td>
                        <td className="px-2 py-2.5 whitespace-nowrap"><RiskBadge score={device.risk_score ?? 0} /></td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="border-t border-slate-200 pt-3 space-y-2">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">IoT attack classes covered</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {IOT_ATTACK_CLASSES.map((cls) => (
                <div key={cls.name} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                  <p className="text-[11px] font-bold text-slate-800">{cls.name}</p>
                  <p className="text-[10px] text-slate-500 leading-snug">{cls.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* ---------------- Architecture strip ---------------- */}
      <Card className="space-y-4">
        <CardHeader
          icon={Layers}
          title="Detection Pipeline & Modular Design"
          subtitle="Each stage is independently deployable, which is what makes horizontal scale-out practical."
        />

        <div className="flex flex-wrap items-stretch gap-2 overflow-x-auto pb-1">
          {PIPELINE.map((stage, idx) => {
            const Icon = stage.icon;
            return (
              <React.Fragment key={stage.label}>
                <div className="flex-1 min-w-[136px] rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5">
                  <Icon className="w-4 h-4 text-blue-600" />
                  <p className="mt-1.5 text-[11px] font-bold text-slate-900 leading-tight">{stage.label}</p>
                  <p className="text-[10px] font-mono text-slate-500 leading-snug">{stage.sub}</p>
                </div>
                {idx < PIPELINE.length - 1 && (
                  <div className="flex items-center shrink-0" aria-hidden="true">
                    <ArrowRight className="w-4 h-4 text-slate-400" />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 border-t border-slate-200 pt-4">
          {ARCHITECTURE_NOTES.map((note) => {
            const Icon = note.icon;
            return (
              <div key={note.title} className="rounded-lg border border-slate-200 bg-white p-3.5 space-y-1.5 hover-lift">
                <span className="inline-flex rounded-lg bg-blue-50 border border-blue-200 p-1.5">
                  <Icon className="w-3.5 h-3.5 text-blue-600" />
                </span>
                <p className="text-xs font-bold text-slate-900">{note.title}</p>
                <p className="text-[11px] text-slate-600 leading-snug">{note.body}</p>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
