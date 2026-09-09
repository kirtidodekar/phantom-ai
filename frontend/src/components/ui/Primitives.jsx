import React from 'react';
import { ResponsiveContainer, AreaChart, Area } from 'recharts';
import { cn, severityStyle } from '../../lib/cn';

export function Card({ as: Tag = 'div', className, hover = false, children, ...props }) {
  return (
    <Tag className={cn('soc-surface p-5 border border-slate-200/90', hover && 'hover-lift', className)} {...props}>
      {children}
    </Tag>
  );
}

export function CardHeader({ icon: Icon, title, subtitle, accent = 'text-blue-600', right, className }) {
  return (
    <div className={cn('flex items-start justify-between gap-3', className)}>
      <div className="flex items-start gap-2.5 min-w-0">
        {Icon && (
          <span className="mt-0.5 shrink-0 p-1.5 rounded-lg bg-slate-50 border border-slate-200">
            <Icon className={cn('w-4 h-4', accent)} />
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

const TONE = {
  primary: { icon: 'text-blue-600', chip: 'bg-blue-50 text-blue-700 border-blue-200', bar: 'bg-blue-600' },
  danger: { icon: 'text-rose-600', chip: 'bg-rose-50 text-rose-700 border-rose-200', bar: 'bg-rose-600' },
  warning: { icon: 'text-amber-600', chip: 'bg-amber-50 text-amber-700 border-amber-200', bar: 'bg-amber-500' },
  success: { icon: 'text-emerald-600', chip: 'bg-emerald-50 text-emerald-700 border-emerald-200', bar: 'bg-emerald-600' },
  cyan: { icon: 'text-cyan-600', chip: 'bg-cyan-50 text-cyan-700 border-cyan-200', bar: 'bg-cyan-600' },
  violet: { icon: 'text-violet-600', chip: 'bg-violet-50 text-violet-700 border-violet-200', bar: 'bg-violet-600' },
  neutral: { icon: 'text-slate-500', chip: 'bg-slate-100 text-slate-600 border-slate-200', bar: 'bg-slate-500' },
};

export function StatCard({ icon: Icon, label, value, unit, delta, tone = 'primary', spark, footer }) {
  const t = TONE[tone] || TONE.primary;
  return (
    <div className="stat-card animate-fadeIn">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</p>
          <div className="mt-1.5 flex items-baseline gap-1">
            <span className="text-2xl font-extrabold font-mono text-slate-900 leading-none">{value}</span>
            {unit && <span className="text-xs font-mono text-slate-500">{unit}</span>}
          </div>
        </div>
        {Icon && (
          <span className={cn('rounded-xl p-2.5 border shadow-2xs', t.chip)}>
            <Icon className={cn('w-4 h-4', t.icon)} />
          </span>
        )}
      </div>
      {(delta || spark) && (
        <div className="mt-2.5 flex items-center justify-between gap-2">
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
      {footer && <p className="mt-2 text-[11px] font-medium text-slate-500 truncate">{footer}</p>}
    </div>
  );
}

export function RiskBadge({ score, showScore = true, className }) {
  const s = severityStyle(score);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-lg text-[10px] font-mono font-bold border shadow-2xs',
        s.bg, s.text, s.border, className
      )}
    >
      {s.label}{showScore ? ` ${Math.round(score)}` : ''}
    </span>
  );
}

export function LiveDot({ tone = 'success', label, className }) {
  const color =
    tone === 'danger' ? 'bg-rose-500'
    : tone === 'warning' ? 'bg-amber-500'
    : tone === 'cyan' ? 'bg-cyan-500'
    : tone === 'primary' ? 'bg-blue-500'
    : 'bg-emerald-500';
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <span className={cn('live-dot', color)} />
      {label && <span className="text-[11px] font-mono font-semibold text-slate-600">{label}</span>}
    </span>
  );
}

export function Pill({ children, tone = 'neutral', className }) {
  const tones = {
    neutral: 'bg-slate-100 text-slate-600 border-slate-200',
    primary: 'bg-blue-50 text-blue-700 border-blue-200',
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    warning: 'bg-amber-50 text-amber-700 border-amber-200',
    danger: 'bg-rose-50 text-rose-700 border-rose-200',
    violet: 'bg-violet-50 text-violet-700 border-violet-200',
    cyan: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  };
  return (
    <span className={cn('inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[10px] font-mono font-bold border', tones[tone] || tones.neutral, className)}>
      {children}
    </span>
  );
}

export function Sparkline({ data = [], tone = 'primary' }) {
  const color =
    tone === 'danger' ? '#F43F5E'
    : tone === 'warning' ? '#F59E0B'
    : tone === 'success' ? '#10B981'
    : tone === 'violet' ? '#8B5CF6'
    : tone === 'cyan' ? '#06B6D4'
    : '#2563EB';
  const series = data.map((v, i) => (typeof v === 'number' ? { i, v } : { i, ...v }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={series} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`spark-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.4} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={2} fill={`url(#spark-${tone})`} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}