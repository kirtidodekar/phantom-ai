import React, { useCallback, useEffect, useState } from 'react';
import {
  Layers, Cpu, Globe, User, Server, Play, Square, ShieldCheck, AlertTriangle,
  Radio, Database, Lock, MapPin, CheckCircle2, XCircle, FileText,
} from 'lucide-react';
import { Card, CardHeader, StatCard, Meter, Pill, LiveDot } from './ui/Primitives';
import { api } from '../lib/api';
import { useNotifications } from '../lib/notifications';
import { cn } from '../lib/cn';

/**
 * Telemetry Coverage page.
 *
 * Answers two questions honestly:
 *   1. Which of the four telemetry layers is the platform ACTUALLY observing
 *      right now (not merely which it supports)?
 *   2. Where does the collected security telemetry physically reside?
 *
 * Sensor controls surface the precise blocking reason when a host cannot
 * support a sensor, rather than reporting a false success.
 */

const LAYER_META = {
  network: { icon: Globe, label: 'Network', accent: 'text-rose-600', chip: 'bg-rose-50' },
  endpoint: { icon: Cpu, label: 'Endpoint', accent: 'text-blue-600', chip: 'bg-blue-50' },
  identity: { icon: User, label: 'Identity', accent: 'text-violet-600', chip: 'bg-violet-50' },
  application: { icon: Server, label: 'Application', accent: 'text-emerald-600', chip: 'bg-emerald-50' },
};

const LAYER_ORDER = ['network', 'endpoint', 'identity', 'application'];

export default function CoveragePage({ currentUser }) {
  const { notify } = useNotifications();
  const role = currentUser?.role || 'SOC Tier-2 Analyst';

  const [coverage, setCoverage] = useState(null);
  const [sensors, setSensors] = useState(null);
  const [sovereignty, setSovereignty] = useState(null);
  const [events, setEvents] = useState({ endpoint: [], application: [] });
  const [busy, setBusy] = useState(null);
  const [errors, setErrors] = useState({});

  const refresh = useCallback(async () => {
    const [cov, sens, sov, epEv, appEv] = await Promise.all([
      api.getLayerCoverage(),
      api.getSensorStatus(),
      api.getSovereignty(),
      api.getSensorEvents('endpoint', 20),
      api.getSensorEvents('application', 20),
    ]);
    if (cov) setCoverage(cov);
    if (sens) setSensors(sens);
    if (sov) setSovereignty(sov);
    setEvents({ endpoint: epEv?.events || [], application: appEv?.events || [] });
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 4000);
    return () => clearInterval(timer);
  }, [refresh]);

  const toggleSensor = async (name, running) => {
    setBusy(name);
    setErrors((e) => ({ ...e, [name]: null }));
    try {
      if (running) {
        await api.stopSensor(name, role);
        notify({ severity: 'info', title: `${name} sensor stopped` });
      } else {
        await api.startSensor(name, role);
        notify({ severity: 'success', title: `${name} sensor started`, message: 'Observing real host telemetry.' });
      }
      await refresh();
    } catch (error) {
      setErrors((e) => ({ ...e, [name]: error.message }));
      notify({ severity: 'danger', title: `${name} sensor could not start`, message: error.message });
    } finally {
      setBusy(null);
    }
  };

  const liveCount = coverage?.layers_live ?? 0;
  const crossReady = coverage?.cross_layer_ready;

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------- Coverage summary ---------------- */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-600" />
            Telemetry Layer Coverage
          </h2>
          <p className="text-xs text-slate-600 max-w-2xl">
            Live observation status for each of the four signal sources. Cross-layer
            correlation needs at least two live layers sharing an entity.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-2xl font-extrabold font-mono text-slate-900 leading-none">
              {liveCount}/4
            </div>
            <div className="text-[10px] uppercase tracking-wide text-slate-500">layers live</div>
          </div>
          <Pill tone={crossReady ? 'success' : 'warning'}>
            {crossReady ? 'CROSS-LAYER READY' : 'SINGLE LAYER'}
          </Pill>
        </div>
      </div>

      {/* ---------------- Layer grid ---------------- */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
        {LAYER_ORDER.map((key) => {
          const meta = LAYER_META[key];
          const info = coverage?.layers?.[key] || {};
          const Icon = meta.icon;
          const live = info.live;
          const available = info.available;

          return (
            <Card key={key} className={cn('space-y-3', live && 'border-emerald-200')}>
              <div className="flex items-start justify-between">
                <span className={cn('rounded-lg p-2.5', meta.chip)}>
                  <Icon className={cn('w-5 h-5', meta.accent)} />
                </span>
                {live
                  ? <LiveDot tone="success" label="LIVE" />
                  : <Pill tone={available ? 'neutral' : 'warning'}>
                      {available ? 'IDLE' : 'UNAVAILABLE'}
                    </Pill>}
              </div>

              <div>
                <h3 className="text-sm font-bold text-slate-900">{meta.label}</h3>
                <p className="text-[10px] font-mono text-slate-500 mt-0.5">{info.sensor || '—'}</p>
              </div>

              <ul className="space-y-1">
                {(info.detects || []).slice(0, 5).map((d) => (
                  <li key={d} className="flex items-start gap-1.5 text-[11px] text-slate-600">
                    <CheckCircle2 className={cn('w-3 h-3 shrink-0 mt-0.5',
                      live ? 'text-emerald-600' : 'text-slate-300')} />
                    {d}
                  </li>
                ))}
              </ul>

              {info.note && (
                <p className="text-[10px] text-slate-500 border-t border-slate-200 pt-2 leading-relaxed">
                  {info.note}
                </p>
              )}
            </Card>
          );
        })}
      </div>

      {/* ---------------- Sensor controls ---------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {['endpoint', 'application'].map((name) => {
          const s = sensors?.[name];
          const cap = s?.capability || {};
          const running = Boolean(s?.running);
          const possible = cap.capture_possible !== false;
          const meta = LAYER_META[name];
          const Icon = meta.icon;

          return (
            <Card key={name} className="space-y-4">
              <CardHeader
                icon={Icon}
                accent={meta.accent}
                title={`${meta.label} Sensor`}
                subtitle={name === 'endpoint'
                  ? 'Observes real local process activity via psutil'
                  : 'Tails real web access logs for request-content signals'}
                right={running ? <LiveDot tone="success" label="RUNNING" /> : <Pill tone="neutral">STOPPED</Pill>}
              />

              <div className="grid grid-cols-3 gap-2.5">
                {name === 'endpoint' ? (
                  <>
                    <Mini label="Processes seen" value={s?.processes_observed ?? 0} />
                    <Mini label="Events" value={s?.events_emitted ?? 0} />
                    <Mini label="Susp. chains" value={s?.suspicious_chains ?? 0} />
                  </>
                ) : (
                  <>
                    <Mini label="Lines read" value={s?.lines_read ?? 0} />
                    <Mini label="Requests" value={s?.requests_parsed ?? 0} />
                    <Mini label="Signature hits" value={s?.signature_hits ?? 0} />
                  </>
                )}
              </div>

              {/* Honest unavailability */}
              {!possible && (
                <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 space-y-1">
                  <p className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-700" />
                    Sensor unavailable
                  </p>
                  <p className="text-[11px] font-mono text-slate-700">{cap.reason}</p>
                  {cap.remediation && (
                    <p className="text-[11px] text-slate-600">{cap.remediation}</p>
                  )}
                </div>
              )}

              {errors[name] && (
                <p className="text-[11px] font-mono text-rose-700 bg-rose-50 border border-rose-200 rounded p-2">
                  {errors[name]}
                </p>
              )}

              {name === 'application' && (cap.configured_paths || []).length > 0 && (
                <div className="space-y-1">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Log paths</p>
                  {cap.configured_paths.map((path) => (
                    <p key={path} className="text-[11px] font-mono text-slate-700 flex items-center gap-1.5 truncate">
                      {(cap.readable_paths || []).includes(path)
                        ? <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
                        : <XCircle className="w-3 h-3 text-rose-600 shrink-0" />}
                      <span className="truncate">{path}</span>
                    </p>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-between gap-3 border-t border-slate-200 pt-3">
                <span className="text-[11px] font-mono text-slate-500 truncate">
                  entity: {s?.entity || '—'}
                </span>
                <button
                  type="button"
                  onClick={() => toggleSensor(name, running)}
                  disabled={busy === name || (!possible && !running)}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition disabled:opacity-50',
                    running
                      ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200'
                      : 'bg-blue-600 hover:bg-blue-700 text-white',
                  )}
                >
                  {running ? <Square className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>{busy === name ? 'Working…' : running ? 'Stop' : 'Start'}</span>
                </button>
              </div>

              {/* Real observations */}
              {(events[name] || []).length > 0 && (
                <div className="space-y-1.5 border-t border-slate-200 pt-3 max-h-[200px] overflow-y-auto">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                    Recent observations
                  </p>
                  {events[name].map((ev, i) => (
                    <div key={i} className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px]">
                      {name === 'endpoint' ? (
                        <>
                          <span className="font-mono font-bold text-slate-900">{ev.process_name}</span>
                          <span className="text-slate-500"> ← {ev.parent_process || 'unknown'}</span>
                          <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                            {ev.chain_suspicious && <Pill tone="danger">SUSPICIOUS CHAIN</Pill>}
                            {ev.encoded_command && <Pill tone="warning">ENCODED CMD</Pill>}
                            {ev.privileged && <Pill tone="violet">PRIVILEGED</Pill>}
                            {ev.incident_id && <span className="font-mono text-[10px] text-blue-700">{ev.incident_id}</span>}
                          </div>
                        </>
                      ) : (
                        <>
                          <span className="font-mono font-bold text-slate-900">{ev.client_ip}</span>
                          <span className="font-mono text-slate-600"> {ev.method} {String(ev.path).substring(0, 44)}</span>
                          <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                            {(ev.families || []).map((f) => <Pill key={f} tone="danger">{f}</Pill>)}
                            <span className="font-mono text-[10px] text-slate-500">
                              status {ev.status} · sig {ev.payload_pattern_score}
                            </span>
                            {ev.incident_id && <span className="font-mono text-[10px] text-blue-700">{ev.incident_id}</span>}
                          </div>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          );
        })}
      </div>

      {/* ---------------- Data sovereignty ---------------- */}
      <Card className="space-y-4">
        <CardHeader
          icon={Lock}
          title="Data Sovereignty Posture"
          accent="text-violet-600"
          subtitle="Where collected security telemetry physically resides"
          right={sovereignty && (
            <Pill tone={sovereignty.residency_compliant ? 'success' : 'danger'}>
              {sovereignty.residency_compliant ? 'WITHIN POLICY' : 'POLICY BREACH'}
            </Pill>
          )}
        />

        {!sovereignty ? (
          <div className="skeleton h-16 w-full" />
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard icon={Database} label="Hosting model" tone={
                sovereignty.hosting_model === 'self_hosted' ? 'success' : 'warning'
              } value={String(sovereignty.hosting_model).replace(/_/g, ' ')} />
              <StatCard icon={MapPin} label="Jurisdiction" tone="neutral"
                value={String(sovereignty.jurisdiction_class).replace(/_/g, ' ')}
                footer={sovereignty.declared_region || 'region not declared'} />
              <StatCard icon={Server} label="Datastore" tone="primary"
                value={sovereignty.datastore_backend} />
              <StatCard icon={Radio} label="Telemetry leaves host"
                tone={sovereignty.sovereignty_properties?.telemetry_leaves_host ? 'danger' : 'success'}
                value={sovereignty.sovereignty_properties?.telemetry_leaves_host ? 'YES' : 'NO'} />
            </div>

            {(sovereignty.findings || []).length > 0 && (
              <div className="space-y-2">
                {sovereignty.findings.map((f, i) => (
                  <div key={i} className="p-3 rounded-lg bg-amber-50 border border-amber-200 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                    <p className="text-xs text-slate-700 leading-relaxed">{f}</p>
                  </div>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 border-t border-slate-200 pt-3">
              {[
                ['Models run locally', sovereignty.sovereignty_properties?.models_run_locally],
                ['No third-party inference', !sovereignty.sovereignty_properties?.inference_sent_to_third_party],
                ['No external intel calls', !sovereignty.sovereignty_properties?.external_threat_intel_calls],
                ['Self-hostable end to end', sovereignty.sovereignty_properties?.self_hostable_end_to_end],
              ].map(([label, ok]) => (
                <span key={label} className="flex items-center gap-2 text-xs text-slate-700">
                  {ok
                    ? <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    : <XCircle className="w-4 h-4 text-rose-600 shrink-0" />}
                  {label}
                </span>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-1.5 border-t border-slate-200 pt-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mr-1">
                Open standards
              </span>
              {(sovereignty.sovereignty_properties?.open_standards || []).map((s) => (
                <Pill key={s} tone="primary">{s}</Pill>
              ))}
            </div>
          </>
        )}
      </Card>

      {/* ---------------- Cross-layer explainer ---------------- */}
      <Card className="space-y-3">
        <CardHeader icon={ShieldCheck} title="How Cross-Layer Correlation Fires"
          subtitle="All local sensors must agree on the entity for evidence to converge" />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {LAYER_ORDER.map((k, i) => {
            const meta = LAYER_META[k];
            const Icon = meta.icon;
            const live = coverage?.layers?.[k]?.live;
            return (
              <div key={k} className={cn(
                'rounded-xl border p-3 text-center',
                live ? 'bg-emerald-50 border-emerald-200' : 'bg-slate-50 border-slate-200',
              )}>
                <Icon className={cn('w-5 h-5 mx-auto', live ? meta.accent : 'text-slate-400')} />
                <div className="text-xs font-bold text-slate-900 mt-1.5">{meta.label}</div>
                <div className="text-[10px] font-mono text-slate-500">
                  {live ? 'contributing' : 'not observed'}
                </div>
              </div>
            );
          })}
        </div>
        <p className="text-[11px] text-slate-600 leading-relaxed border-t border-slate-200 pt-3">
          <FileText className="w-3.5 h-3.5 text-slate-400 inline mr-1" />
          {coverage?.note || 'Set NETWORK_LOCAL_ENTITY so every local sensor reports the same entity.'}
          {' '}Scoring rewards convergence: 2 layers +12, 3 layers +25, all 4 layers +32.
        </p>
      </Card>
    </div>
  );
}

function Mini({ label, value }) {
  return (
    <div className="rounded-lg bg-slate-50 border border-slate-200 p-2.5">
      <div className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-base font-extrabold font-mono text-slate-900 leading-none mt-1">{value}</div>
    </div>
  );
}
