import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * cn — merge conditional class names and de-duplicate conflicting Tailwind
 * utilities. This is the single class-composition helper used across the
 * Sentinel AI UI so components stay declarative and modular.
 *
 * @param {...any} inputs clsx-compatible class values
 * @returns {string} merged className string
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

/**
 * severityOf — map a 0-100 threat score to a canonical severity key.
 * Keeps the score→severity thresholds in one place instead of the ternary
 * that was previously duplicated across App, Navbar and OverviewPage.
 */
export function severityOf(score = 0) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/** Tailwind text/border/bg tokens per severity, for consistent theming. */
export const SEVERITY_STYLES = {
  critical: {
    label: 'CRITICAL',
    text: 'text-rose-700',
    bg: 'bg-rose-50',
    border: 'border-rose-200',
    dot: 'bg-rose-600',
    solid: 'bg-rose-600',
    ring: 'ring-rose-500/30',
  },
  high: {
    label: 'HIGH',
    text: 'text-amber-700',
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    dot: 'bg-amber-500',
    solid: 'bg-amber-500',
    ring: 'ring-amber-500/30',
  },
  medium: {
    label: 'MEDIUM',
    text: 'text-yellow-700',
    bg: 'bg-yellow-50',
    border: 'border-yellow-200',
    dot: 'bg-yellow-500',
    solid: 'bg-yellow-500',
    ring: 'ring-yellow-500/30',
  },
  low: {
    label: 'LOW',
    text: 'text-emerald-700',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    dot: 'bg-emerald-500',
    solid: 'bg-emerald-500',
    ring: 'ring-emerald-500/30',
  },
};

export function severityStyle(score) {
  return SEVERITY_STYLES[severityOf(score)];
}
