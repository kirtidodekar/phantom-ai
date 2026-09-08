import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { api } from './api';

/**
 * Defense store — shared, modular state for the automatic malicious-IP
 * blocking subsystem and the adaptive (DRL) defense policy.
 *
 * Both the Live Monitor and the Auto-Defense console read/write this store,
 * so a block issued in one place is instantly reflected in the other. All
 * enforcement is sandboxed and routed through the backend action endpoint.
 */

const DefenseContext = createContext(null);

const SEED_BLOCKS = [
  { ip: '198.51.100.99', attackType: 'SQL Injection', score: 96, mode: 'auto', reason: 'C2 exfiltration endpoint', ts: Date.now() - 1000 * 60 * 4 },
  { ip: '203.0.113.44', attackType: 'Brute Force', score: 88, mode: 'auto', reason: '412 failed auths in 60s', ts: Date.now() - 1000 * 60 * 12 },
  { ip: '45.83.192.7', attackType: 'DDoS', score: 91, mode: 'manual', reason: 'SYN flood 25k pps', ts: Date.now() - 1000 * 60 * 33 },
];

export function DefenseProvider({ children, onEvent }) {
  const [autoBlock, setAutoBlock] = useState(true);
  const [threshold, setThreshold] = useState(80);
  const [adaptive, setAdaptive] = useState(true);
  const [blocked, setBlocked] = useState(SEED_BLOCKS);

  const isBlocked = useCallback((ip) => blocked.some((b) => b.ip === ip), [blocked]);

  const blockIp = useCallback(
    ({ ip, attackType = 'Malicious', score = 90, reason = 'Analyst action', mode = 'manual', incidentId = 'INC-2048' }) => {
      setBlocked((prev) => {
        if (prev.some((b) => b.ip === ip)) return prev;
        return [{ ip, attackType, score, reason, mode, ts: Date.now() }, ...prev].slice(0, 40);
      });
      api.simulateBlock('BLOCK_IP', ip, incidentId);
      onEvent?.({
        severity: mode === 'auto' ? 'warning' : 'info',
        title: mode === 'auto' ? `Auto-blocked ${ip}` : `Blocked ${ip}`,
        message: `${attackType} - risk ${Math.round(score)} - sandboxed enforcement applied`,
      });
      return true;
    },
    [onEvent]
  );

  const unblockIp = useCallback((ip) => {
    setBlocked((prev) => prev.filter((b) => b.ip !== ip));
    onEvent?.({ severity: 'success', title: `Released ${ip}`, message: 'Removed from active blocklist.' });
  }, [onEvent]);

  const maybeAutoBlock = useCallback(
    (detection) => {
      if (!autoBlock) return false;
      if (!detection || detection.verdict === 'benign') return false;
      if (detection.score < threshold) return false;
      if (isBlocked(detection.ip)) return false;
      blockIp({
        ip: detection.ip,
        attackType: detection.attackType,
        score: detection.score,
        reason: `Auto-mitigated by ${adaptive ? 'DRL policy' : 'static rule'}`,
        mode: 'auto',
      });
      return true;
    },
    [autoBlock, threshold, adaptive, isBlocked, blockIp]
  );

  const value = useMemo(
    () => ({
      autoBlock, setAutoBlock,
      threshold, setThreshold,
      adaptive, setAdaptive,
      blocked, blockIp, unblockIp, isBlocked, maybeAutoBlock,
      autoBlockedCount: blocked.filter((b) => b.mode === 'auto').length,
    }),
    [autoBlock, threshold, adaptive, blocked, blockIp, unblockIp, isBlocked, maybeAutoBlock]
  );

  return <DefenseContext.Provider value={value}>{children}</DefenseContext.Provider>;
}

export function useDefense() {
  const ctx = useContext(DefenseContext);
  if (!ctx) throw new Error('useDefense must be used within DefenseProvider');
  return ctx;
}
