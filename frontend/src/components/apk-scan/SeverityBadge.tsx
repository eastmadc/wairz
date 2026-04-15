/**
 * SeverityBadge — a compact, colored badge for security finding severity levels.
 *
 * Supports the standard Wairz severity levels (critical/high/medium/low/info)
 * plus "warning" which some APK scan tools emit. Unknown levels fall back
 * to a neutral gray style.
 *
 * Variants:
 *   - "filled" (default): solid background, white/black text
 *   - "outline": colored border + text, transparent background
 *   - "subtle": light tinted background with colored text
 */

import * as React from 'react'
import {
  ShieldX,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// ── Severity level type (superset: includes "warning" for APK scan contexts) ──

export type SeverityLevel =
  | 'critical'
  | 'high'
  | 'medium'
  | 'warning'
  | 'low'
  | 'info'

// ── Color configuration per severity ──

export interface SeverityStyle {
  icon: React.ElementType
  label: string
  /** Solid badge: bg + text color */
  filled: string
  /** Outline badge: border + text color */
  outline: string
  /** Subtle badge: light bg tint + text color */
  subtle: string
  /** Text-only color (for inline use) */
  text: string
  /** Dot / indicator color */
  dot: string
  /** Sort order: 0 = most severe */
  order: number
}

export const SEVERITY_STYLES: Record<SeverityLevel, SeverityStyle> = {
  critical: {
    icon: ShieldX,
    label: 'Critical',
    filled: 'bg-red-600 text-white',
    outline: 'border border-red-500/50 text-red-600 dark:text-red-400',
    subtle: 'bg-red-500/10 text-red-600 dark:text-red-400',
    text: 'text-red-600 dark:text-red-400',
    dot: 'bg-red-600',
    order: 0,
  },
  high: {
    icon: ShieldAlert,
    label: 'High',
    filled: 'bg-orange-500 text-white',
    outline: 'border border-orange-500/50 text-orange-600 dark:text-orange-400',
    subtle: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
    text: 'text-orange-500',
    dot: 'bg-orange-500',
    order: 1,
  },
  medium: {
    icon: AlertTriangle,
    label: 'Medium',
    filled: 'bg-yellow-500 text-black',
    outline: 'border border-yellow-500/50 text-yellow-600 dark:text-yellow-400',
    subtle: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400',
    text: 'text-yellow-500',
    dot: 'bg-yellow-500',
    order: 2,
  },
  warning: {
    icon: AlertTriangle,
    label: 'Warning',
    filled: 'bg-amber-500 text-black',
    outline: 'border border-amber-500/50 text-amber-600 dark:text-amber-400',
    subtle: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    text: 'text-amber-500',
    dot: 'bg-amber-500',
    order: 2,
  },
  low: {
    icon: AlertCircle,
    label: 'Low',
    filled: 'bg-blue-500 text-white',
    outline: 'border border-blue-500/50 text-blue-600 dark:text-blue-400',
    subtle: 'bg-blue-500/10 text-blue-600 dark:text-blue-400',
    text: 'text-blue-500',
    dot: 'bg-blue-500',
    order: 3,
  },
  info: {
    icon: Info,
    label: 'Info',
    filled: 'bg-gray-500 text-white',
    outline: 'border border-gray-500/50 text-gray-500 dark:text-gray-400',
    subtle: 'bg-gray-500/10 text-gray-500 dark:text-gray-400',
    text: 'text-gray-500',
    dot: 'bg-gray-500',
    order: 4,
  },
}

/** Fallback for unknown severity strings */
const FALLBACK_STYLE: SeverityStyle = {
  icon: Info,
  label: 'Unknown',
  filled: 'bg-gray-400 text-white',
  outline: 'border border-gray-400/50 text-gray-400',
  subtle: 'bg-gray-400/10 text-gray-400',
  text: 'text-gray-400',
  dot: 'bg-gray-400',
  order: 99,
}

/** Resolve a severity string to its style, with safe fallback */
export function getSeverityStyle(severity: string): SeverityStyle {
  const key = severity.toLowerCase() as SeverityLevel
  return SEVERITY_STYLES[key] ?? FALLBACK_STYLE
}

// ── Component ──

export type SeverityBadgeVariant = 'filled' | 'outline' | 'subtle'

export interface SeverityBadgeProps {
  /** Severity level string (case-insensitive) */
  severity: string
  /** Visual variant */
  variant?: SeverityBadgeVariant
  /** Show the icon before the label */
  showIcon?: boolean
  /** Override the displayed label */
  label?: string
  /** Size preset */
  size?: 'sm' | 'md'
  /** Additional CSS classes */
  className?: string
}

export function SeverityBadge({
  severity,
  variant = 'filled',
  showIcon = false,
  label,
  size = 'sm',
  className,
}: SeverityBadgeProps) {
  const style = getSeverityStyle(severity)
  const Icon = style.icon
  const displayLabel = label ?? style.label

  const sizeClasses =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-xs gap-1'
      : 'px-2.5 py-1 text-sm gap-1.5'

  return (
    <span
      data-slot="severity-badge"
      data-severity={severity.toLowerCase()}
      className={cn(
        'inline-flex items-center justify-center rounded-full font-medium whitespace-nowrap shrink-0',
        sizeClasses,
        style[variant],
        className,
      )}
    >
      {showIcon && <Icon className={size === 'sm' ? 'size-3' : 'size-3.5'} />}
      {displayLabel}
    </span>
  )
}

// ── Utility: Severity dot indicator ──

export interface SeverityDotProps {
  severity: string
  className?: string
}

/** A small colored circle indicator for severity */
export function SeverityDot({ severity, className }: SeverityDotProps) {
  const style = getSeverityStyle(severity)
  return (
    <span
      data-slot="severity-dot"
      className={cn('inline-block size-2 rounded-full shrink-0', style.dot, className)}
    />
  )
}
