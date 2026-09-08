import React, { useEffect, useRef, useState } from 'react';
import { Bell, Check, Trash2, BellOff } from 'lucide-react';
import { cn } from '../lib/cn';
import { useNotifications, SEVERITY_META, relativeTime } from '../lib/notifications';

export default function NotificationCenter() {
  const { alerts, unreadCount, markAllRead, clearAlerts } = useNotifications();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && unreadCount > 0) markAllRead();
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={toggle}
        title="Admin alerts & notifications"
        className={cn(
          'relative p-1.5 rounded-lg border transition',
          open
            ? 'bg-blue-50 border-blue-300 text-blue-700'
            : 'bg-slate-50 border-slate-300 text-slate-600 hover:bg-slate-100 hover:text-slate-900'
        )}
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-rose-600 text-white text-[9px] font-bold font-mono flex items-center justify-center animate-pulseGlow">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-[360px] max-w-[90vw] soc-elevated overflow-hidden z-50 animate-slideInUp">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 bg-slate-50">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-blue-600" />
              <span className="text-xs font-bold text-slate-900">Alert Center</span>
              <span className="text-[10px] font-mono text-slate-500">{alerts.length}</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={markAllRead}
                className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold text-slate-500 hover:text-blue-700 hover:bg-blue-50 transition"
                title="Mark all read"
              >
                <Check className="w-3 h-3" /> Read
              </button>
              <button
                onClick={clearAlerts}
                className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold text-slate-500 hover:text-rose-700 hover:bg-rose-50 transition"
                title="Clear all"
              >
                <Trash2 className="w-3 h-3" /> Clear
              </button>
            </div>
          </div>

          <div className="max-h-[380px] overflow-y-auto divide-y divide-slate-100">
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-slate-400">
                <BellOff className="w-8 h-8 mb-2" />
                <p className="text-xs font-medium text-slate-500">No alerts yet</p>
                <p className="text-[11px] text-slate-400">Detections and responses appear here.</p>
              </div>
            ) : (
              alerts.map((a) => {
                const meta = SEVERITY_META[a.severity] || SEVERITY_META.info;
                const Icon = meta.icon;
                return (
                  <div key={a.id} className="flex items-start gap-3 px-4 py-2.5 hover:bg-slate-50 transition">
                    <span className={cn('shrink-0 rounded-lg p-1.5 mt-0.5', meta.soft)}>
                      <Icon className="w-3.5 h-3.5" style={{ color: meta.accent }} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-bold text-slate-900 leading-tight">{a.title}</p>
                      {a.message && <p className="text-[11px] text-slate-600 mt-0.5 leading-snug">{a.message}</p>}
                      <p className="text-[10px] font-mono text-slate-400 mt-1">{relativeTime(a.ts)}</p>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
