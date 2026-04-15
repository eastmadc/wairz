/**
 * CategoryTag — a compact tag for APK scan finding categories.
 *
 * Used to label findings from bytecode analysis and SAST scans with their
 * functional category (crypto, network, storage, etc.). Each category gets
 * a distinct color for quick visual scanning in result lists.
 *
 * Variants:
 *   - "filled" (default): solid colored background
 *   - "outline": colored border + text, transparent background
 *   - "subtle": light tinted background with colored text
 */

import * as React from 'react'
import {
  Lock,
  Globe,
  HardDrive,
  Cpu,
  FileText,
  MonitorSmartphone,
  Database,
  Clipboard,
  MessageSquare,
  Tag,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// ── Category type (covers bytecode + SAST categories) ──

export type ScanCategory =
  | 'crypto'
  | 'network'
  | 'storage'
  | 'runtime'
  | 'logging'
  | 'webview'
  | 'sql'
  | 'clipboard'
  | 'ipc'
  | 'manifest'
  | 'code'
  | 'general'

// ── Color configuration per category ──

export interface CategoryStyle {
  icon: React.ElementType
  label: string
  /** Solid tag: bg + text color */
  filled: string
  /** Outline tag: border + text color */
  outline: string
  /** Subtle tag: light bg tint + text color */
  subtle: string
}

export const CATEGORY_STYLES: Record<ScanCategory, CategoryStyle> = {
  crypto: {
    icon: Lock,
    label: 'Crypto',
    filled: 'bg-purple-600 text-white',
    outline: 'border border-purple-500/50 text-purple-600 dark:text-purple-400',
    subtle: 'bg-purple-500/10 text-purple-600 dark:text-purple-400',
  },
  network: {
    icon: Globe,
    label: 'Network',
    filled: 'bg-cyan-600 text-white',
    outline: 'border border-cyan-500/50 text-cyan-600 dark:text-cyan-400',
    subtle: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400',
  },
  storage: {
    icon: HardDrive,
    label: 'Storage',
    filled: 'bg-emerald-600 text-white',
    outline: 'border border-emerald-500/50 text-emerald-600 dark:text-emerald-400',
    subtle: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  },
  runtime: {
    icon: Cpu,
    label: 'Runtime',
    filled: 'bg-rose-600 text-white',
    outline: 'border border-rose-500/50 text-rose-600 dark:text-rose-400',
    subtle: 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
  },
  logging: {
    icon: FileText,
    label: 'Logging',
    filled: 'bg-amber-600 text-white',
    outline: 'border border-amber-500/50 text-amber-600 dark:text-amber-400',
    subtle: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
  },
  webview: {
    icon: MonitorSmartphone,
    label: 'WebView',
    filled: 'bg-sky-600 text-white',
    outline: 'border border-sky-500/50 text-sky-600 dark:text-sky-400',
    subtle: 'bg-sky-500/10 text-sky-600 dark:text-sky-400',
  },
  sql: {
    icon: Database,
    label: 'SQL',
    filled: 'bg-indigo-600 text-white',
    outline: 'border border-indigo-500/50 text-indigo-600 dark:text-indigo-400',
    subtle: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400',
  },
  clipboard: {
    icon: Clipboard,
    label: 'Clipboard',
    filled: 'bg-teal-600 text-white',
    outline: 'border border-teal-500/50 text-teal-600 dark:text-teal-400',
    subtle: 'bg-teal-500/10 text-teal-600 dark:text-teal-400',
  },
  ipc: {
    icon: MessageSquare,
    label: 'IPC',
    filled: 'bg-violet-600 text-white',
    outline: 'border border-violet-500/50 text-violet-600 dark:text-violet-400',
    subtle: 'bg-violet-500/10 text-violet-600 dark:text-violet-400',
  },
  manifest: {
    icon: FileText,
    label: 'Manifest',
    filled: 'bg-orange-600 text-white',
    outline: 'border border-orange-500/50 text-orange-600 dark:text-orange-400',
    subtle: 'bg-orange-500/10 text-orange-600 dark:text-orange-400',
  },
  code: {
    icon: Tag,
    label: 'Code',
    filled: 'bg-zinc-600 text-white',
    outline: 'border border-zinc-500/50 text-zinc-500 dark:text-zinc-400',
    subtle: 'bg-zinc-500/10 text-zinc-500 dark:text-zinc-400',
  },
  general: {
    icon: Tag,
    label: 'General',
    filled: 'bg-gray-500 text-white',
    outline: 'border border-gray-500/50 text-gray-500 dark:text-gray-400',
    subtle: 'bg-gray-500/10 text-gray-500 dark:text-gray-400',
  },
}

/** Fallback for unknown category strings */
const FALLBACK_STYLE: CategoryStyle = {
  icon: Tag,
  label: 'Other',
  filled: 'bg-gray-400 text-white',
  outline: 'border border-gray-400/50 text-gray-400',
  subtle: 'bg-gray-400/10 text-gray-400',
}

/** Resolve a category string to its style, with safe fallback */
export function getCategoryStyle(category: string): CategoryStyle {
  const key = category.toLowerCase() as ScanCategory
  return CATEGORY_STYLES[key] ?? FALLBACK_STYLE
}

// ── Component ──

export type CategoryTagVariant = 'filled' | 'outline' | 'subtle'

export interface CategoryTagProps {
  /** Category string (case-insensitive) */
  category: string
  /** Visual variant */
  variant?: CategoryTagVariant
  /** Show the icon before the label */
  showIcon?: boolean
  /** Override the displayed label */
  label?: string
  /** Size preset */
  size?: 'sm' | 'md'
  /** Additional CSS classes */
  className?: string
}

export function CategoryTag({
  category,
  variant = 'subtle',
  showIcon = true,
  label,
  size = 'sm',
  className,
}: CategoryTagProps) {
  const style = getCategoryStyle(category)
  const Icon = style.icon
  const displayLabel = label ?? style.label

  const sizeClasses =
    size === 'sm'
      ? 'px-1.5 py-0.5 text-xs gap-1'
      : 'px-2.5 py-1 text-sm gap-1.5'

  return (
    <span
      data-slot="category-tag"
      data-category={category.toLowerCase()}
      className={cn(
        'inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap shrink-0',
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
