import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area } from 'recharts';
import { cn, severityStyle } from '../../lib/cn';

/* ------------------------------------------------------------------ */
/* Card                                                                */
/* ------------------------------------------------------------------ */
export function Card({ as: Tag = 'div', className, hover = false, children, ...props }) {
  return (
    <Tag className={cn('soc-surface p-5 border border-[#D9E0E8]', hover && 'hover-lift', className)} {...props}>
      {children}
    </Tag>
  );
}

export function CardHeader({ icon: Icon, title, subtitle, accent = 'text-blue-600', right, className }) {
  return (
    <div className={cn('flex items-start justify-between gap-3', className)}>
      <div className="flex items-start gap-2.5 min-w-0">
        {Icon && (
          <span className="mt-0.5 shrink-0">
            <Icon className={cn('w-5 h-5', accent)} />
          </span>
        )}
        <div className="min-w-0">
          <h3 className="text-sm font-bold text-slate-900 leading-tight">{title}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-0.5 leading-snug">{subtitle}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* StatCard (KPI)                                                      */
/* ------------------------------------------------------------------ */
const TONE = {
  primary: { icon: 'text-blue-600', chip: 'bg-blue-50 text-blue-700', bar: 'bg-blue-600' },
  danger: { icon: 'text-rose-600', chip: 'bg-rose-50 text-rose-700', bar: 'bg-rose-600' },
  warning: { icon: 'text-amber-600', chip: 'bg-amber-50 text-amber-700', bar: 'bg-amber-500' },
  success: { icon: 'text-emerald-600', chip: 'bg-emerald-50 text-emerald-700', bar: 'bg-emerald-600' },
  neutral: { icon: 'text-slate-500', chip: 'bg-slate-100 text-slate-600', bar: 'bg-slate-500' },
  violet: { icon: 'text-violet-600', chip: 'bg-violet-50 text-violet-700', bar: 'bg-violet-600' },
};

export function StatCard({ icon: Icon, label, value, unit, delta, tone = 'primary', spark, footer }) {
  const t = TONE[tone] || TONE.primary;
  return (
    <div className="stat-card animate-countUp">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</p>
          <div className="mt-1 flex items-baseline gap-1">
            <span className="text-2xl font-extrabold font-mono text-slate-900 leading-none">{value}</span>
            {unit && <span className="text-xs font-mono text-slate-500">{unit}</span>}
          </div>
        </div>
        {Icon && (
          <span className={cn('rounded-lg p-2', t.chip)}>
            <Icon className={cn('w-4 h-4', t.icon)} />
          </span>
        )}
      </div>
      {(delta || spark) && (
        <div className="mt-2 flex items-center justify-between gap-2">
          {delta && (
            <span
              className={cn(
                'text-[11px] font-mono font-bold',
                delta.dir === 'up' ? 'text-rose-600' : delta.dir === 'down' ? 'text-emerald-600' : 'text-slate-500'
              )}
            >
              {delta.dir === 'up' ? '▲' : delta.dir === 'down' ? '▼' : '■'} {delta.value}
            </span>
          )}
          {spark && (
            <div className="h-7 w-20 ml-auto">
              <Sparkline data={spark} tone={tone} />
            </div>
          )}
        </div>
      )}
      {footer && <p className="mt-1.5 text-[11px] text-slate-500">{footer}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Toggle switch                                                       */
/* ------------------------------------------------------------------ */
export function Toggle({ checked, onChange, label, description, disabled = false, tone = 'primary' }) {
  const onColor = tone === 'danger' ? 'bg-rose-600' : tone === 'success' ? 'bg-emerald-600' : 'bg-blue-600';
  return (
    <label className={cn('flex items-center justify-between gap-3', disabled && 'opacity-60 cursor-not-allowed')}>
      {(label || description) && (
        <span className="min-w-0">
          {label && <span className="block text-xs font-semibold text-slate-800">{label}</span>}
          {description && <span className="block text-[11px] text-slate-500 leading-snug">{description}</span>}
        </span>
      )}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={cn(
          'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-blue-500/40',
          checked ? onColor : 'bg-slate-300'
        )}
      >
        <span
          className={cn(
            'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform',
            checked ? 'translate-x-4' : 'translate-x-0.5'
          )}
        />
      </button>
    </label>
  );
}

/* ------------------------------------------------------------------ */
/* Meter / progress bar                                                */
/* ------------------------------------------------------------------ */
export function Meter({ value = 0, max = 100, tone = 'primary', className, height = 8 }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const color =
    tone === 'danger' ? '#C43D4B'
    : tone === 'warning' ? '#B7791F'
    : tone === 'success' ? '#16805C'
    : tone === 'violet' ? '#7C3AED'
    : '#2563EB';
  return (
    <div className={cn('meter-track w-full', className)} style={{ height }}>
      <div className="meter-fill" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* RiskBadge                                                           */
/* ------------------------------------------------------------------ */
export function RiskBadge({ score, showScore = true, className }) {
  const s = severityStyle(score);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold border',
        s.bg, s.text, s.border, className
      )}
    >
      {s.label}{showScore ? ` ${Math.round(score)}` : ''}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* LiveDot                                                             */
/* ------------------------------------------------------------------ */
export function LiveDot({ tone = 'success', label, className }) {
  const color =
    tone === 'danger' ? 'bg-rose-500'
    : tone === 'warning' ? 'bg-amber-500'
    : tone === 'primary' ? 'bg-blue-500'
    : 'bg-emerald-500';
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <span className={cn('live-dot', color)} />
      {label && <span className="text-[11px] font-mono font-semibold text-slate-600">{label}</span>}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Sparkline                                                           */
/* ------------------------------------------------------------------ */
export function Sparkline({ data = [], tone = 'primary' }) {
  const color =
    tone === 'danger' ? '#C43D4B'
    : tone === 'warning' ? '#B7791F'
    : tone === 'success' ? '#16805C'
    : tone === 'violet' ? '#7C3AED'
    : '#2563EB';
  const series = data.map((v, i) => (typeof v === 'number' ? { i, v } : { i, ...v }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={series} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`spark-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.75} fill={`url(#spark-${tone})`} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/* ------------------------------------------------------------------ */
/* Donut                                                               */
/* ------------------------------------------------------------------ */
export function Donut({ data = [], size = 160, thickness = 22, centerLabel, centerValue }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={size / 2 - thickness}
            outerRadius={size / 2}
            paddingAngle={2}
            stroke="none"
            startAngle={90}
            endAngle={-270}
          >
            {data.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-2xl font-extrabold font-mono text-slate-900 leading-none">
          {centerValue ?? total}
        </span>
        {centerLabel && <span className="text-[10px] uppercase tracking-wide text-slate-500 mt-0.5">{centerLabel}</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Pill                                                                */
/* ------------------------------------------------------------------ */
export function Pill({ children, tone = 'neutral', className }) {
  const tones = {
    neutral: 'bg-slate-100 text-slate-600 border-slate-200',
    primary: 'bg-blue-50 text-blue-700 border-blue-200',
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    warning: 'bg-amber-50 text-amber-700 border-amber-200',
    danger: 'bg-rose-50 text-rose-700 border-rose-200',
    violet: 'bg-violet-50 text-violet-700 border-violet-200',
  };
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold border', tones[tone], className)}>
      {children}
    </span>
  );
}
