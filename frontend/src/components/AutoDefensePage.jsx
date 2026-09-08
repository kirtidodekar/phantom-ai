import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Ban,
  Activity,
  Timer,
  Brain,
  Zap,
  Lock,
  KeyRound,
  Server,
  Network,
  Plus,
  SlidersHorizontal,
  AlertTriangle,
  Gauge,
  Unlock,
} from 'lucide-react';
import { Card, CardHeader, StatCard, Toggle, Meter, RiskBadge, LiveDot, Pill } from './ui/Primitives';
import { api } from '../lib/api';
import { useDefense } from '../lib/defense';
import { useNotifications, relativeTime } from '../lib/notifications';
import { cn } from '../lib/cn';

/**
 * AutoDefensePage — console for the automatic malicious-IP blocking subsystem
 * and the adaptive (deep reinforcement learning) response policy.
 *
 * The active blocklist is rendered straight from the shared defense store
 * (`useDefense`) so a block issued from the Live Monitor shows up here and
 * vice-versa. Configuration changes are additionally pushed to the backend
 * through `api.setDefenseConfig` so the server-side policy stays in step.
 *
 * IMPORTANT: every enforcement path on this page is SANDBOXED. Nothing here
 * mutates a real firewall, switch ACL or identity provider.
 */

/* ------------------------------------------------------------------ */
/* Constants + fallback data (used when the backend is unreachable)    */
/* ------------------------------------------------------------------ */

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

const ATTACK_TYPES = [
  'SQL Injection',
  'Brute Force',
  'DDoS',
  'Port Scan / Probe',
  'Malware C2',
  'Data Exfiltration',
  'Privilege Escalation',
  'Unauthorized Access',
];

/** Deterministic, representative DQN telemetry. Not a trained agent. */
const FALLBACK_POLICY = {
  algorithm: 'Deep Q-Network (DQN)',
  episodes_trained: 1840,
  epsilon: 0.08,
  avg_reward: 41.6,
  effective_threshold: 78,
  mitigation_rate: 97.4,
  mean_time_to_block_s: 1.8,
  reward_history: [
    { episode: 0, reward: -12.4 },
    { episode: 80, reward: -6.1 },
    { episode: 160, reward: 1.8 },
    { episode: 240, reward: 7.5 },
    { episode: 320, reward: 11.2 },
    { episode: 400, reward: 15.9 },
    { episode: 480, reward: 14.3 },
    { episode: 560, reward: 20.7 },
    { episode: 640, reward: 24.1 },
    { episode: 720, reward: 22.6 },
    { episode: 800, reward: 27.8 },
    { episode: 880, reward: 31.4 },
    { episode: 960, reward: 30.2 },
    { episode: 1040, reward: 34.6 },
    { episode: 1120, reward: 36.1 },
    { episode: 1200, reward: 35.4 },
    { episode: 1280, reward: 38.7 },
    { episode: 1360, reward: 40.2 },
    { episode: 1440, reward: 39.5 },
    { episode: 1520, reward: 41.1 },
    { episode: 1600, reward: 42.4 },
    { episode: 1680, reward: 41.8 },
    { episode: 1760, reward: 43.0 },
    { episode: 1840, reward: 43.6 },
  ],
  actions: [
    { action: 'BLOCK_IP', q_value: 8.94, selected_count: 1462 },
    { action: 'ISOLATE_HOST', q_value: 6.12, selected_count: 388 },
    { action: 'RATE_LIMIT', q_value: 4.75, selected_count: 512 },
    { action: 'REVOKE_TOKEN', q_value: 3.41, selected_count: 174 },
    { action: 'MONITOR', q_value: 1.86, selected_count: 2904 },
  ],
};

const ACTION_META = {
  BLOCK_IP: { icon: Ban, tone: 'danger', blurb: 'Drops all ingress from the source address at the edge.' },
  ISOLATE_HOST: { icon: Server, tone: 'warning', blurb: 'Quarantines the endpoint to a restricted VLAN.' },
  RATE_LIMIT: { icon: Gauge, tone: 'primary', blurb: 'Throttles the flow instead of severing it outright.' },
  REVOKE_TOKEN: { icon: KeyRound, tone: 'violet', blurb: 'Invalidates the session / OAuth token for the identity.' },
  MONITOR: { icon: Activity, tone: 'neutral', blurb: 'Keeps observing without interrupting the session.' },
};

const PLAYBOOK = [
  {
    action: 'BLOCK_IP',
    title: 'Block IP',
    icon: Ban,
    what: 'Adds the source address to the edge denylist and drops every subsequent packet from it.',
    target: '203.0.113.201',
  },
  {
    action: 'ISOLATE_HOST',
    title: 'Isolate Host',
    icon: Server,
    what: 'Moves the compromised endpoint into a quarantine VLAN with management access only.',
    target: 'WKSTN-4412',
  },
  {
    action: 'RATE_LIMIT',
    title: 'Rate Limit',
    icon: Gauge,
    what: 'Applies a token-bucket cap so a noisy-but-uncertain flow degrades instead of dying.',
    target: 'edge-gw-02',
  },
  {
    action: 'REVOKE_TOKEN',
    title: 'Revoke Token',
    icon: KeyRound,
    what: 'Kills the active session and refresh token for the implicated identity.',
    target: 'svc_admin@corp',
  },
];

/** Candidate addresses used by the sandboxed BLOCK_IP playbook simulation. */
const SIM_CANDIDATES = ['203.0.113.201', '198.51.100.37', '192.0.2.148', '203.0.113.77', '198.51.100.212'];

const nf = new Intl.NumberFormat('en-US');

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export default function AutoDefensePage() {
  const {
    autoBlock, setAutoBlock,
    threshold, setThreshold,
    adaptive, setAdaptive,
    blocked, blockIp, unblockIp, isBlocked,
    autoBlockedCount,
  } = useDefense();
  const { notify } = useNotifications();

  const [policy, setPolicy] = useState(FALLBACK_POLICY);
  const [policyLive, setPolicyLive] = useState(false);
  const [serverSnapshot, setServerSnapshot] = useState(null);
  const [form, setForm] = useState({ ip: '', attackType: ATTACK_TYPES[0], score: 90 });
  const [formError, setFormError] = useState('');
  const [, setTick] = useState(0);

  const configTimer = useRef(null);

  /* ---- load the adaptive policy snapshot (fail-soft to local data) ---- */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const [remote, blocklist] = await Promise.all([api.getDefensePolicy(), api.getBlocklist()]);
      if (cancelled) return;
      if (remote && Array.isArray(remote.reward_history) && remote.reward_history.length) {
        setPolicy({ ...FALLBACK_POLICY, ...remote });
        setPolicyLive(true);
      }
      // The shared store stays the source of truth for what is rendered; the
      // server snapshot is surfaced separately so drift is visible.
      if (blocklist) setServerSnapshot(blocklist);
    })();
    return () => { cancelled = true; };
  }, []);

  /* ---- keep the "blocked at" relative timestamps fresh ---- */
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 30000);
    return () => clearInterval(id);
  }, []);

  /* ---- flush any pending debounced config push on unmount ---- */
  useEffect(() => {
    const ref = configTimer;
    return () => { if (ref.current) clearTimeout(ref.current); };
  }, []);

  /* ---- config sync helpers ---------------------------------------- */
  const pushConfig = useCallback(
    (next) => api.setDefenseConfig({
      auto_block_enabled: next.autoBlock,
      threshold: next.threshold,
      adaptive_enabled: next.adaptive,
    }),
    []
  );

  const onAutoBlockChange = useCallback((value) => {
    setAutoBlock(value);
    pushConfig({ autoBlock: value, threshold, adaptive });
    notify({
      severity: value ? 'success' : 'warning',
      title: value ? 'Automatic IP blocking ARMED' : 'Automatic IP blocking DISARMED',
      message: value
        ? `Malicious verdicts scoring >= ${threshold} will be blocked automatically (sandboxed).`
        : 'Detections will be logged for analyst review only. No enforcement will fire.',
    });
  }, [setAutoBlock, pushConfig, threshold, adaptive, notify]);

  const onAdaptiveChange = useCallback((value) => {
    setAdaptive(value);
    pushConfig({ autoBlock, threshold, adaptive: value });
    notify({
      severity: 'info',
      title: value ? 'Adaptive DRL policy enabled' : 'Reverted to static rule policy',
      message: value
        ? 'The agent will tune the block threshold from observed reward.'
        : `Threshold pinned at ${threshold} until re-enabled.`,
    });
  }, [setAdaptive, pushConfig, autoBlock, threshold, notify]);

  /**
   * Threshold moves continuously while dragging, so the backend push and the
   * notification are debounced. `value` is captured by the closure rather than
   * read back from state, which keeps the committed value correct.
   */
  const onThresholdChange = useCallback((value) => {
    setThreshold(value);
    if (configTimer.current) clearTimeout(configTimer.current);
    configTimer.current = setTimeout(() => {
      pushConfig({ autoBlock, threshold: value, adaptive });
      notify({
        severity: 'info',
        title: `Auto-block threshold set to ${value}`,
        message: `Malicious verdicts at risk >= ${value} now resolve to BLOCK_IP.`,
      });
    }, 600);
  }, [setThreshold, pushConfig, autoBlock, adaptive, notify]);

  /* ---- blocklist actions ------------------------------------------ */
  /**
   * The shared store already emits a notification event for block/release, so
   * we deliberately do not fire a second `notify` here — that would surface a
   * duplicate toast for a single operator action.
   */
  const release = useCallback((ip) => {
    unblockIp(ip);
    api.unblockIp(ip);
  }, [unblockIp]);

  const submitManualBlock = useCallback((event) => {
    event.preventDefault();
    const ip = form.ip.trim();
    if (!ip) {
      setFormError('Enter an IPv4 address to block.');
      return;
    }
    if (!IPV4_RE.test(ip)) {
      setFormError(`"${ip}" is not a valid IPv4 address (expected four octets, 0-255).`);
      return;
    }
    if (isBlocked(ip)) {
      setFormError('');
      notify({ severity: 'warning', title: `${ip} is already blocked`, message: 'The address is present on the active blocklist.' });
      return;
    }
    const score = Math.max(0, Math.min(100, Number(form.score) || 0));
    setFormError('');
    blockIp({ ip, attackType: form.attackType, score, reason: 'Analyst manual block', mode: 'manual' });
    api.blockIp({ ip, attack_type: form.attackType, risk_score: score, mode: 'manual', reason: 'Analyst manual block' });
    setForm((prev) => ({ ...prev, ip: '' }));
  }, [form, isBlocked, blockIp, notify]);

  const simulate = useCallback((entry) => {
    if (entry.action === 'BLOCK_IP') {
      const candidate = SIM_CANDIDATES.find((ip) => !isBlocked(ip));
      if (!candidate) {
        notify({ severity: 'info', title: 'Every simulation address is already blocked', message: 'Release one to run BLOCK_IP again.' });
        return;
      }
      // Routed through the shared store so the blocklist below updates live.
      blockIp({ ip: candidate, attackType: 'Malware C2', score: 93, reason: 'Playbook simulation', mode: 'auto' });
      return;
    }
    api.simulateBlock(entry.action, entry.target, 'INC-2048');
    notify({
      severity: 'info',
      title: `Simulated ${entry.title.toUpperCase()}`,
      message: `${entry.action} → ${entry.target} — sandboxed, no real network change applied.`,
    });
  }, [isBlocked, blockIp, notify]);

  /* ---- derived values --------------------------------------------- */
  const manualCount = useMemo(() => blocked.filter((b) => b.mode !== 'auto').length, [blocked]);

  const rankedActions = useMemo(() => {
    const list = Array.isArray(policy.actions) && policy.actions.length ? policy.actions : FALLBACK_POLICY.actions;
    return [...list].sort((a, b) => b.q_value - a.q_value);
  }, [policy.actions]);

  const preferredAction = rankedActions[0]?.action;
  const maxQ = Math.max(...rankedActions.map((a) => Math.abs(a.q_value)), 1);
  const rewardSeries = policy.reward_history?.length ? policy.reward_history : FALLBACK_POLICY.reward_history;
  const effectiveThreshold = adaptive ? (policy.effective_threshold ?? threshold) : threshold;

  return (
    <div className="space-y-5 animate-fadeIn">
      {/* ---------------- Header ---------------- */}
      <div className="soc-surface p-5 border border-[#D9E0E8] flex flex-wrap items-start justify-between gap-4 shadow-xs">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-bold text-slate-900">Automated Defense &amp; Response</h1>
            <p className="text-xs text-slate-600 leading-snug">
              Autonomous malicious-IP containment driven by model verdicts, with an adaptive reinforcement-learning
              policy selecting the response action per detection.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {autoBlock ? (
            <LiveDot tone="success" label="AUTO-BLOCK ARMED" />
          ) : (
            <span className="inline-flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-slate-400" />
              <span className="text-[11px] font-mono font-semibold text-slate-600">AUTO-BLOCK DISARMED</span>
            </span>
          )}
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-50 border border-amber-200 text-amber-700 text-[10px] font-mono font-bold uppercase tracking-wide">
            <AlertTriangle className="w-3.5 h-3.5" />
            Sandboxed — no real network changes
          </span>
        </div>
      </div>

      {/* ---------------- KPI row ---------------- */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-5">
        <StatCard
          icon={Ban}
          label="Active Blocks"
          value={blocked.length}
          tone="danger"
          footer="Addresses on the live denylist"
        />
        <StatCard
          icon={Zap}
          label="Auto-Blocked"
          value={autoBlockedCount}
          tone="warning"
          footer="This session, no analyst input"
        />
        <StatCard
          icon={Lock}
          label="Manual Blocks"
          value={manualCount}
          tone="primary"
          footer="Analyst-initiated containment"
        />
        <StatCard
          icon={Timer}
          label="Mean Time To Block"
          value={(policy.mean_time_to_block_s ?? 1.8).toFixed(1)}
          unit="s"
          tone="violet"
          footer="Detection → enforcement"
        />
        <StatCard
          icon={ShieldCheck}
          label="Attacks Mitigated"
          value={(policy.mitigation_rate ?? 97.4).toFixed(1)}
          unit="%"
          tone="success"
          footer="Of malicious verdicts contained"
        />
      </div>

      {/* ---------------- Policy control + blocklist ---------------- */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Policy control panel */}
        <Card className="xl:col-span-4 space-y-5">
          <CardHeader
            icon={SlidersHorizontal}
            title="Defense Policy"
            subtitle="Controls how aggressively Sentinel contains detections."
            right={<Pill tone={autoBlock ? 'success' : 'neutral'}>{autoBlock ? 'ARMED' : 'STANDBY'}</Pill>}
          />

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5">
            <Toggle
              checked={autoBlock}
              onChange={onAutoBlockChange}
              tone="success"
              label="Automatic IP Blocking"
              description="Enforce BLOCK_IP without waiting for analyst confirmation."
            />
          </div>

          {/* Threshold slider */}
          <div className="space-y-2.5">
            <div className="flex items-end justify-between gap-3">
              <label htmlFor="auto-block-threshold" className="text-xs font-semibold text-slate-800">
                Auto-Block Risk Threshold
                <span className="block text-[11px] font-normal text-slate-500 leading-snug">
                  Minimum risk score that triggers containment.
                </span>
              </label>
              <span className="text-2xl font-extrabold font-mono text-slate-900 leading-none shrink-0">{threshold}</span>
            </div>

            <input
              id="auto-block-threshold"
              type="range"
              min={0}
              max={100}
              step={1}
              value={threshold}
              onChange={(e) => onThresholdChange(Number(e.target.value))}
              aria-describedby="auto-block-threshold-hint"
              className="w-full accent-blue-600 cursor-pointer"
            />

            <Meter value={threshold} tone={threshold >= 80 ? 'danger' : threshold >= 60 ? 'warning' : 'success'} />

            <div id="auto-block-threshold-hint" className="flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>0 · block everything</span>
              <span>100 · block nothing</span>
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 space-y-2">
            <Toggle
              checked={adaptive}
              onChange={onAdaptiveChange}
              label="Adaptive DRL Policy"
              description="The agent tunes the threshold from observed reward instead of holding a fixed cutoff."
            />
            <p className="text-[11px] text-slate-500 leading-snug border-t border-slate-200 pt-2">
              Effective threshold in use:{' '}
              <span className="font-mono font-bold text-slate-900">{Math.round(effectiveThreshold)}</span>{' '}
              {adaptive ? '(agent-adjusted)' : '(operator-pinned)'}
            </p>
          </div>

          {/* Decision rule explainer */}
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-3.5 space-y-1.5">
            <p className="text-[10px] font-bold uppercase tracking-wider text-blue-700">Decision Rule</p>
            <p className="text-[11px] font-mono text-slate-800 leading-relaxed">
              verdict == <span className="font-bold text-rose-700">malicious</span>{' '}
              <span className="text-slate-500">AND</span>{' '}
              risk_score &gt;= <span className="font-bold text-slate-900">{Math.round(effectiveThreshold)}</span>
              <span className="block mt-1">
                → <span className="font-bold text-rose-700">BLOCK_IP</span>
                <span className="text-slate-500"> else </span>
                <span className="font-bold text-emerald-700">MONITOR</span>
              </span>
            </p>
            <p className="text-[11px] text-slate-600 leading-snug">
              Benign verdicts never reach enforcement regardless of score.
            </p>
          </div>
        </Card>

        {/* Blocklist */}
        <Card className="xl:col-span-8 space-y-4">
          <CardHeader
            icon={ShieldAlert}
            accent="text-rose-600"
            title="Active Blocklist"
            subtitle="Sandboxed denylist shared with the live monitor. Releasing an entry restores traffic immediately."
            right={<Pill tone="danger">{blocked.length} ACTIVE</Pill>}
          />

          {/* Manual block form */}
          <form onSubmit={submitManualBlock} className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 space-y-2.5">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Block an IP manually</p>
            <div className="flex flex-wrap items-end gap-2.5">
              <div className="flex-1 min-w-[150px]">
                <label htmlFor="manual-ip" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  IPv4 address
                </label>
                <input
                  id="manual-ip"
                  type="text"
                  inputMode="numeric"
                  placeholder="198.51.100.24"
                  value={form.ip}
                  onChange={(e) => { setForm((p) => ({ ...p, ip: e.target.value })); setFormError(''); }}
                  aria-invalid={Boolean(formError)}
                  aria-describedby={formError ? 'manual-ip-error' : undefined}
                  className={cn(
                    'w-full rounded-md border bg-white px-2.5 py-1.5 text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/40',
                    formError ? 'border-rose-400' : 'border-slate-300'
                  )}
                />
              </div>

              <div className="min-w-[150px]">
                <label htmlFor="manual-attack" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  Attack type
                </label>
                <select
                  id="manual-attack"
                  value={form.attackType}
                  onChange={(e) => setForm((p) => ({ ...p, attackType: e.target.value }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                >
                  {ATTACK_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              <div className="w-24">
                <label htmlFor="manual-score" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  Risk
                </label>
                <input
                  id="manual-score"
                  type="number"
                  min={0}
                  max={100}
                  value={form.score}
                  onChange={(e) => setForm((p) => ({ ...p, score: e.target.value }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                />
              </div>

              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
              >
                <Plus className="w-3.5 h-3.5" />
                Block
              </button>
            </div>

            {formError && (
              <p id="manual-ip-error" role="alert" className="flex items-center gap-1.5 text-[11px] font-semibold text-rose-700">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                {formError}
              </p>
            )}

            {serverSnapshot && (
              <p className="text-[10px] font-mono text-slate-500 border-t border-slate-200 pt-2">
                backend snapshot: {nf.format(serverSnapshot.entries?.length ?? 0)} entries · auto_block=
                {String(serverSnapshot.auto_block_enabled ?? false)} · threshold={serverSnapshot.threshold ?? '—'}
              </p>
            )}
          </form>

          {/* Table */}
          {blocked.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-10 text-center">
              <Shield className="w-8 h-8 text-slate-400 mb-2" />
              <p className="text-xs font-semibold text-slate-700">No addresses are currently blocked</p>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Entries appear here the moment auto-block fires or you add one above.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto -mx-1">
              <table className="w-full text-left border-collapse">
                <caption className="sr-only">Active sandboxed IP blocklist</caption>
                <thead>
                  <tr className="border-b border-slate-200">
                    {['Source IP', 'Attack Type', 'Risk', 'Mode', 'Reason', 'Blocked', ''].map((h, i) => (
                      <th
                        key={h || `col-${i}`}
                        scope="col"
                        className="px-2 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 whitespace-nowrap"
                      >
                        {h || <span className="sr-only">Actions</span>}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {blocked.map((entry) => (
                    <tr key={entry.ip} className="border-b border-slate-100 last:border-0 hover:bg-slate-50 transition-colors">
                      <td className="px-2 py-2.5 text-xs font-mono font-bold text-slate-900 whitespace-nowrap">{entry.ip}</td>
                      <td className="px-2 py-2.5 text-xs text-slate-700 whitespace-nowrap">{entry.attackType}</td>
                      <td className="px-2 py-2.5 whitespace-nowrap"><RiskBadge score={entry.score} /></td>
                      <td className="px-2 py-2.5 whitespace-nowrap">
                        <Pill tone={entry.mode === 'auto' ? 'danger' : 'primary'}>
                          {entry.mode === 'auto' ? 'AUTO' : 'MANUAL'}
                        </Pill>
                      </td>
                      <td className="px-2 py-2.5 text-[11px] text-slate-600 max-w-[220px]">{entry.reason}</td>
                      <td className="px-2 py-2.5 text-[11px] font-mono text-slate-500 whitespace-nowrap">{relativeTime(entry.ts)}</td>
                      <td className="px-2 py-2.5 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => release(entry.ip)}
                          aria-label={`Release ${entry.ip} from the blocklist`}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-300 bg-white px-2 py-1 text-[11px] font-bold text-slate-700 transition hover:border-emerald-300 hover:bg-emerald-50 hover:text-emerald-700 focus:outline-none focus:ring-2 focus:ring-emerald-500/30"
                        >
                          <Unlock className="w-3 h-3" />
                          Release
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {/* ---------------- Adaptive DRL panel ---------------- */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <Card className="xl:col-span-7 space-y-4">
          <CardHeader
            icon={Brain}
            accent="text-violet-600"
            title="Adaptive Defense Agent"
            subtitle="Reward curve for the response-selection policy across training episodes."
            right={<Pill tone={policyLive ? 'success' : 'neutral'}>{policyLive ? 'LIVE SNAPSHOT' : 'LOCAL SNAPSHOT'}</Pill>}
          />

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
            {[
              { label: 'Algorithm', value: policy.algorithm ?? FALLBACK_POLICY.algorithm, mono: false },
              { label: 'Episodes', value: nf.format(policy.episodes_trained ?? 0) },
              { label: 'Epsilon', value: (policy.epsilon ?? 0).toFixed(2) },
              { label: 'Avg Reward', value: (policy.avg_reward ?? 0).toFixed(1) },
              { label: 'Eff. Threshold', value: Math.round(effectiveThreshold) },
            ].map((m) => (
              <div key={m.label} className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-2">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{m.label}</p>
                <p className={cn('mt-0.5 text-xs font-bold text-slate-900 leading-snug', m.mono !== false && 'font-mono text-sm')}>
                  {m.value}
                </p>
              </div>
            ))}
          </div>

          <div className="h-[220px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={rewardSeries} margin={{ top: 8, right: 16, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.8} />
                <XAxis dataKey="episode" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload || !payload.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="rounded-xl border border-slate-300 bg-white p-3 shadow-md text-xs space-y-1">
                        <p className="font-bold text-violet-700">Episode {d.episode}</p>
                        <p className="text-slate-800">
                          Cumulative reward:{' '}
                          <strong className="font-mono text-sm text-slate-900">{Number(d.reward).toFixed(1)}</strong>
                        </p>
                      </div>
                    );
                  }}
                />
                <ReferenceLine y={0} stroke="#94a3b8" strokeDasharray="4 4" />
                <Line
                  type="monotone"
                  dataKey="reward"
                  stroke="#7C3AED"
                  strokeWidth={2.5}
                  dot={false}
                  activeDot={{ r: 6, fill: '#6D28D9', stroke: '#ffffff', strokeWidth: 2 }}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <p className="flex items-start gap-1.5 text-[11px] text-slate-500 border-t border-slate-200 pt-3 leading-snug">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-px" />
            This is a simulated policy included for demonstration, not a trained production agent.
          </p>
        </Card>

        {/* Q-values */}
        <Card className="xl:col-span-5 space-y-4">
          <CardHeader
            icon={Network}
            accent="text-violet-600"
            title="Action Q-Values"
            subtitle="Expected return per response action in the current state."
          />

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <caption className="sr-only">Estimated Q-value and selection count per response action</caption>
              <thead>
                <tr className="border-b border-slate-200">
                  <th scope="col" className="px-2 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Action</th>
                  <th scope="col" className="px-2 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Q-Value</th>
                  <th scope="col" className="px-2 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 text-right">Selected</th>
                </tr>
              </thead>
              <tbody>
                {rankedActions.map((a) => {
                  const meta = ACTION_META[a.action] ?? ACTION_META.MONITOR;
                  const Icon = meta.icon;
                  const preferred = a.action === preferredAction;
                  return (
                    <tr
                      key={a.action}
                      className={cn('border-b border-slate-100 last:border-0', preferred && 'bg-violet-50/60')}
                    >
                      <td className="px-2 py-2.5">
                        <span className="flex items-center gap-2 min-w-0">
                          <Icon className={cn('w-3.5 h-3.5 shrink-0', preferred ? 'text-violet-700' : 'text-slate-400')} />
                          <span className="min-w-0">
                            <span className="block text-[11px] font-mono font-bold text-slate-900">{a.action}</span>
                            {preferred && (
                              <span className="block text-[10px] font-bold uppercase tracking-wide text-violet-700">
                                policy preferred
                              </span>
                            )}
                          </span>
                        </span>
                      </td>
                      <td className="px-2 py-2.5 w-[45%]">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold text-slate-900 w-10 shrink-0">{a.q_value.toFixed(2)}</span>
                          <Meter
                            value={Math.abs(a.q_value)}
                            max={maxQ}
                            tone={preferred ? 'violet' : 'primary'}
                            height={6}
                          />
                        </div>
                      </td>
                      <td className="px-2 py-2.5 text-right text-[11px] font-mono text-slate-600">
                        {nf.format(a.selected_count ?? 0)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="text-[11px] text-slate-500 leading-snug border-t border-slate-200 pt-3">
            The argmax action is what the agent would take right now.{' '}
            <span className="font-mono font-semibold text-slate-700">MONITOR</span> carries the highest selection count
            because most observed traffic is benign.
          </p>
        </Card>
      </div>

      {/* ---------------- Response playbook ---------------- */}
      <Card className="space-y-4">
        <CardHeader
          icon={Zap}
          accent="text-amber-600"
          title="Response Playbook"
          subtitle="Containment actions available to the agent. Every simulation is sandboxed."
          right={
            <span className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-wide text-amber-700">
              <AlertTriangle className="w-3.5 h-3.5" />
              Simulation only
            </span>
          }
        />

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {PLAYBOOK.map((entry) => {
            const Icon = entry.icon;
            const meta = ACTION_META[entry.action] ?? ACTION_META.MONITOR;
            return (
              <div
                key={entry.action}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 flex flex-col gap-2 hover-lift"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="rounded-lg bg-white border border-slate-200 p-2">
                    <Icon
                      className={cn(
                        'w-4 h-4',
                        meta.tone === 'danger' ? 'text-rose-600'
                        : meta.tone === 'warning' ? 'text-amber-600'
                        : meta.tone === 'violet' ? 'text-violet-600'
                        : 'text-blue-600'
                      )}
                    />
                  </span>
                  <Pill tone={meta.tone}>{entry.action}</Pill>
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-xs font-bold text-slate-900">{entry.title}</p>
                  <p className="mt-0.5 text-[11px] text-slate-600 leading-snug">{entry.what}</p>
                  <p className="mt-1.5 text-[10px] font-mono text-slate-500">target: {entry.target}</p>
                </div>

                <button
                  type="button"
                  onClick={() => simulate(entry)}
                  className="mt-auto inline-flex items-center justify-center gap-1.5 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-[11px] font-bold text-slate-700 transition hover:border-blue-300 hover:bg-blue-50 hover:text-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                >
                  <Activity className="w-3 h-3" />
                  Simulate
                </button>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
