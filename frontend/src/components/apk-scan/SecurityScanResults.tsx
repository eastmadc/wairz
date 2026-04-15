/**
 * SecurityScanResults — container component for displaying multi-phase APK
 * security scan results with category grouping, collapsible detail expansion,
 * and severity badges.
 *
 * Accepts results from all three scan phases (manifest, bytecode, SAST) and
 * normalizes them into a unified finding model grouped by category. Each group
 * is collapsible. Individual findings within each group are also expandable
 * to reveal full detail (description, evidence, CWE links, code locations).
 *
 * Uses the existing SeverityBadge and CategoryTag components for consistent
 * visual styling across the APK scan UI.
 */

import React, { useMemo, useState, useCallback } from 'react'
import {
  ChevronDown,
  ChevronRight,
  Shield,
  ShieldCheck,
  Clock,
  Database,
  AlertTriangle,
  FileCode,
  Code,
  ExternalLink,
  Filter,
  SortAsc,
  SortDesc,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { SeverityBadge } from './SeverityBadge'
import { CategoryTag } from './CategoryTag'
import type {
  ManifestScanResponse,
  ManifestFindingResponse,
  BytecodeScanResponse,
  BytecodeFindingResponse,
  SastScanResponse,
  SastFindingResponse,
  FirmwareContextResponse,
} from '@/api/apkScan'

// ── Unified finding type ──

export type ScanPhase = 'manifest' | 'bytecode' | 'sast'

export interface UnifiedFinding {
  /** Unique key for React rendering */
  id: string
  /** Originating scan phase */
  phase: ScanPhase
  /** Display title */
  title: string
  /** Severity level (critical/high/medium/low/info/warning) */
  severity: string
  /** Full description text */
  description: string
  /** Category for grouping */
  category: string
  /** Evidence or proof text */
  evidence?: string
  /** CWE identifiers */
  cweIds: string[]
  /** Check/pattern/rule identifier from the scanner */
  ruleId: string
  /** Confidence level (manifest and bytecode) */
  confidence?: string
  /** Source file path (SAST only) */
  filePath?: string | null
  /** Source line number (SAST only) */
  lineNumber?: number | null
  /** OWASP Mobile reference (SAST only) */
  owaspMobile?: string
  /** MASVS reference (SAST only) */
  masvs?: string
  /** Bytecode locations (bytecode only) */
  locations?: Record<string, unknown>[]
  /** Total occurrences (bytecode only) */
  totalOccurrences?: number
}

// ── Severity ordering for sort ──

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  warning: 3,
  low: 4,
  info: 5,
}

function severityRank(severity: string): number {
  return SEVERITY_ORDER[severity.toLowerCase()] ?? 99
}

// ── Phase display labels ──

const PHASE_CONFIG: Record<ScanPhase, { label: string; icon: React.ElementType; color: string }> = {
  manifest: { label: 'Manifest', icon: FileCode, color: 'text-orange-500' },
  bytecode: { label: 'Bytecode', icon: Database, color: 'text-purple-500' },
  sast: { label: 'SAST', icon: Shield, color: 'text-cyan-500' },
}

// ── Sort modes ──

export type SortMode = 'severity' | 'category' | 'phase'
export type SortDirection = 'asc' | 'desc'

// ── Normalization helpers ──

function normalizeManifestFindings(
  response: ManifestScanResponse,
): UnifiedFinding[] {
  return response.findings.map((f: ManifestFindingResponse) => ({
    id: `manifest-${f.check_id}`,
    phase: 'manifest' as ScanPhase,
    title: f.title,
    severity: f.severity,
    description: f.description,
    category: 'manifest',
    evidence: f.evidence || undefined,
    cweIds: f.cwe_ids,
    ruleId: f.check_id,
    confidence: f.confidence,
  }))
}

function normalizeBytecodeFinding(
  f: BytecodeFindingResponse,
): UnifiedFinding {
  return {
    id: `bytecode-${f.pattern_id}`,
    phase: 'bytecode',
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    description: f.description,
    category: f.category || 'general',
    cweIds: f.cwe_ids,
    ruleId: f.pattern_id,
    locations: f.locations,
    totalOccurrences: f.total_occurrences,
  }
}

function normalizeSastFinding(
  f: SastFindingResponse,
  idx: number,
): UnifiedFinding {
  // Derive category from rule_id prefix when possible
  const category = deriveSastCategory(f.rule_id)
  return {
    id: `sast-${f.rule_id}-${idx}`,
    phase: 'sast',
    title: f.title,
    severity: f.severity,
    description: f.description,
    category,
    cweIds: f.cwe_ids,
    ruleId: f.rule_id,
    filePath: f.source_file || f.file_path,
    lineNumber: f.line_number,
    owaspMobile: f.owasp_mobile || undefined,
    masvs: f.masvs || undefined,
  }
}

function deriveSastCategory(ruleId: string): string {
  const lower = ruleId.toLowerCase()
  if (lower.includes('crypto') || lower.includes('cipher') || lower.includes('hash')) return 'crypto'
  if (lower.includes('network') || lower.includes('http') || lower.includes('ssl') || lower.includes('tls')) return 'network'
  if (lower.includes('storage') || lower.includes('file') || lower.includes('shared_pref')) return 'storage'
  if (lower.includes('log')) return 'logging'
  if (lower.includes('webview')) return 'webview'
  if (lower.includes('sql') || lower.includes('database')) return 'sql'
  if (lower.includes('clipboard')) return 'clipboard'
  if (lower.includes('ipc') || lower.includes('intent') || lower.includes('broadcast')) return 'ipc'
  return 'code'
}

// ── Component Props ──

export interface SecurityScanResultsProps {
  /** Phase 1: Manifest scan results */
  manifest?: ManifestScanResponse | null
  /** Phase 2a: Bytecode scan results */
  bytecode?: BytecodeScanResponse | null
  /** Phase 2b: SAST scan results */
  sast?: SastScanResponse | null
  /** Firmware context for display (taken from any non-null response) */
  firmwareContext?: FirmwareContextResponse | null
  /** APK package name */
  packageName?: string
  /** Whether any scan is currently running */
  isScanning?: boolean
  /** Callback to view decompiled source at a file:line */
  onViewSource?: (filePath: string, line?: number) => void
  /** Additional CSS classes on the root container */
  className?: string
}

// ── Main Component ──

export default function SecurityScanResults({
  manifest,
  bytecode,
  sast,
  firmwareContext,
  packageName,
  isScanning = false,
  onViewSource,
  className,
}: SecurityScanResultsProps) {
  // ── State ──
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [sortMode, setSortMode] = useState<SortMode>('severity')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set())
  const [phaseFilter, setPhaseFilter] = useState<Set<ScanPhase>>(new Set())

  // ── Normalize all findings ──
  const allFindings = useMemo<UnifiedFinding[]>(() => {
    const findings: UnifiedFinding[] = []
    if (manifest && !manifest.error) {
      findings.push(...normalizeManifestFindings(manifest))
    }
    if (bytecode && !bytecode.error) {
      bytecode.findings.forEach((f) => findings.push(normalizeBytecodeFinding(f)))
    }
    if (sast && !sast.error) {
      sast.findings.forEach((f, i) => findings.push(normalizeSastFinding(f, i)))
    }
    return findings
  }, [manifest, bytecode, sast])

  // ── Filtered findings ──
  const filteredFindings = useMemo(() => {
    let result = allFindings
    if (severityFilter.size > 0) {
      result = result.filter((f) => severityFilter.has(f.severity.toLowerCase()))
    }
    if (phaseFilter.size > 0) {
      result = result.filter((f) => phaseFilter.has(f.phase))
    }
    return result
  }, [allFindings, severityFilter, phaseFilter])

  // ── Group findings by the current sort mode key ──
  const groupedFindings = useMemo(() => {
    const groups = new Map<string, UnifiedFinding[]>()

    for (const f of filteredFindings) {
      let groupKey: string
      switch (sortMode) {
        case 'category':
          groupKey = f.category
          break
        case 'phase':
          groupKey = f.phase
          break
        case 'severity':
        default:
          groupKey = f.severity.toLowerCase()
          break
      }
      const existing = groups.get(groupKey) || []
      existing.push(f)
      groups.set(groupKey, existing)
    }

    // Sort groups
    const sortedGroups = Array.from(groups.entries()).sort(([a], [b]) => {
      let cmp: number
      if (sortMode === 'severity') {
        cmp = severityRank(a) - severityRank(b)
      } else {
        cmp = a.localeCompare(b)
      }
      return sortDirection === 'desc' ? -cmp : cmp
    })

    // Sort findings within each group by severity
    for (const [, findings] of sortedGroups) {
      findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    }

    return sortedGroups
  }, [filteredFindings, sortMode, sortDirection])

  // ── Severity summary counts ──
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const f of allFindings) {
      const key = f.severity.toLowerCase()
      counts[key] = (counts[key] || 0) + 1
    }
    return counts
  }, [allFindings])

  // ── Toggle helpers ──
  const toggleGroup = useCallback((key: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
      } else {
        next.add(key)
      }
      return next
    })
  }, [])

  const toggleFinding = useCallback((id: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const expandAll = useCallback(() => {
    const allGroupKeys = groupedFindings.map(([key]) => key)
    setExpandedGroups(new Set(allGroupKeys))
  }, [groupedFindings])

  const collapseAll = useCallback(() => {
    setExpandedGroups(new Set())
    setExpandedFindings(new Set())
  }, [])

  const toggleSeverityFilter = useCallback((sev: string) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev)
      if (next.has(sev)) {
        next.delete(sev)
      } else {
        next.add(sev)
      }
      return next
    })
  }, [])

  const clearAllFilters = useCallback(() => {
    setSeverityFilter(new Set())
    setPhaseFilter(new Set())
  }, [])

  const togglePhaseFilter = useCallback((phase: ScanPhase) => {
    setPhaseFilter((prev) => {
      const next = new Set(prev)
      if (next.has(phase)) {
        next.delete(phase)
      } else {
        next.add(phase)
      }
      return next
    })
  }, [])

  // ── Has data ──
  const hasResults = allFindings.length > 0
  const hasAnyResponse = manifest != null || bytecode != null || sast != null

  if (!hasAnyResponse && !isScanning) {
    return null
  }

  // ── Render ──
  return (
    <div className={cn('space-y-4', className)} data-slot="security-scan-results">
      {/* ── Header summary bar ── */}
      <ScanSummaryBar
        manifest={manifest}
        bytecode={bytecode}
        sast={sast}
        packageName={packageName}
        firmwareContext={firmwareContext}
        severityCounts={severityCounts}
        totalFindings={allFindings.length}
      />

      {/* ── Toolbar: filters, sort, expand/collapse ── */}
      {hasResults && (
        <ResultsToolbar
          sortMode={sortMode}
          sortDirection={sortDirection}
          onSortModeChange={setSortMode}
          onSortDirectionToggle={() =>
            setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'))
          }
          severityFilter={severityFilter}
          onToggleSeverity={toggleSeverityFilter}
          phaseFilter={phaseFilter}
          onTogglePhase={togglePhaseFilter}
          onClearFilters={clearAllFilters}
          availableSeverities={Object.keys(severityCounts)}
          availablePhases={[
            ...(manifest ? (['manifest'] as ScanPhase[]) : []),
            ...(bytecode ? (['bytecode'] as ScanPhase[]) : []),
            ...(sast ? (['sast'] as ScanPhase[]) : []),
          ]}
          onExpandAll={expandAll}
          onCollapseAll={collapseAll}
        />
      )}

      {/* ── Grouped findings ── */}
      {hasResults ? (
        <div className="space-y-2">
          {groupedFindings.map(([groupKey, findings]) => (
            <FindingGroup
              key={groupKey}
              groupKey={groupKey}
              groupMode={sortMode}
              findings={findings}
              isExpanded={expandedGroups.has(groupKey)}
              expandedFindings={expandedFindings}
              onToggleGroup={() => toggleGroup(groupKey)}
              onToggleFinding={toggleFinding}
              onViewSource={onViewSource}
            />
          ))}
        </div>
      ) : hasAnyResponse && !isScanning ? (
        <div className="text-center py-8 text-muted-foreground">
          <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">No security findings detected.</p>
          {(manifest?.error || bytecode?.error || sast?.error) && (
            <p className="text-xs mt-1 text-destructive">
              Some scans encountered errors — check individual scan results.
            </p>
          )}
        </div>
      ) : null}

      {/* ── Errors ── */}
      {hasAnyResponse && (
        <ScanErrors manifest={manifest} bytecode={bytecode} sast={sast} />
      )}
    </div>
  )
}

// ── Scan Summary Bar ──

interface ScanSummaryBarProps {
  manifest?: ManifestScanResponse | null
  bytecode?: BytecodeScanResponse | null
  sast?: SastScanResponse | null
  packageName?: string
  firmwareContext?: FirmwareContextResponse | null
  severityCounts: Record<string, number>
  totalFindings: number
}

function ScanSummaryBar({
  manifest,
  bytecode,
  sast,
  packageName,
  firmwareContext,
  severityCounts,
  totalFindings,
}: ScanSummaryBarProps) {
  const resolvedPackage = packageName || manifest?.package || bytecode?.package || ''
  const ctx = firmwareContext || manifest?.firmware_context || bytecode?.firmware_context || sast?.firmware_context

  return (
    <div className="rounded-lg border bg-card p-4 space-y-3">
      {/* Top row: package name + phase badges */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Shield className="h-5 w-5 text-primary shrink-0" />
          <div className="min-w-0">
            <h3 className="text-sm font-semibold truncate">
              {resolvedPackage || 'APK Security Scan'}
            </h3>
            {ctx && (
              <p className="text-xs text-muted-foreground truncate">
                {[ctx.manufacturer, ctx.device_model, ctx.android_version && `Android ${ctx.android_version}`]
                  .filter(Boolean)
                  .join(' · ') || 'Unknown device context'}
                {ctx.is_priv_app && (
                  <span className="ml-1.5 text-amber-500 font-medium">priv-app</span>
                )}
              </p>
            )}
          </div>
        </div>

        {/* Phase status indicators */}
        <div className="flex items-center gap-2">
          {manifest && (
            <PhaseIndicator
              phase="manifest"
              count={manifest.findings.length}
              cached={manifest.from_cache}
              elapsed={manifest.elapsed_ms != null ? `${Math.round(manifest.elapsed_ms)}ms` : undefined}
              error={manifest.error}
            />
          )}
          {bytecode && (
            <PhaseIndicator
              phase="bytecode"
              count={bytecode.findings.length}
              cached={bytecode.from_cache}
              elapsed={`${bytecode.elapsed_seconds.toFixed(1)}s`}
              error={bytecode.error}
            />
          )}
          {sast && (
            <PhaseIndicator
              phase="sast"
              count={sast.findings.length}
              cached={sast.cached}
              elapsed={sast.timing ? `${(sast.timing.total_elapsed_ms / 1000).toFixed(1)}s` : undefined}
              error={sast.error}
            />
          )}
        </div>
      </div>

      {/* Severity summary row */}
      {totalFindings > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          {(['critical', 'high', 'medium', 'warning', 'low', 'info'] as const).map((sev) => {
            const count = severityCounts[sev]
            if (!count) return null
            return (
              <SeverityBadge
                key={sev}
                severity={sev}
                variant="filled"
                showIcon
                size="sm"
                label={`${count} ${sev}`}
              />
            )
          })}
          <span className="text-xs text-muted-foreground ml-1">
            {totalFindings} total finding{totalFindings !== 1 ? 's' : ''}
          </span>
        </div>
      )}
    </div>
  )
}

// ── Phase Indicator ──

interface PhaseIndicatorProps {
  phase: ScanPhase
  count: number
  cached: boolean
  elapsed?: string
  error?: string | null
}

function PhaseIndicator({ phase, count, cached, elapsed, error }: PhaseIndicatorProps) {
  const config = PHASE_CONFIG[phase]
  const Icon = config.icon
  const hasError = !!error

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium border',
        hasError
          ? 'border-destructive/50 text-destructive bg-destructive/5'
          : 'border-border bg-muted/50 text-foreground',
      )}
      title={error || `${config.label}: ${count} findings${cached ? ' (cached)' : ''}${elapsed ? ` in ${elapsed}` : ''}`}
    >
      <Icon className={cn('size-3', hasError ? 'text-destructive' : config.color)} />
      <span>{config.label}</span>
      <span className="font-mono">{count}</span>
      {cached && <Database className="size-3 text-muted-foreground" />}
      {elapsed && (
        <span className="text-muted-foreground flex items-center gap-0.5">
          <Clock className="size-2.5" />
          {elapsed}
        </span>
      )}
    </div>
  )
}

// ── Results Toolbar ──

interface ResultsToolbarProps {
  sortMode: SortMode
  sortDirection: SortDirection
  onSortModeChange: (mode: SortMode) => void
  onSortDirectionToggle: () => void
  severityFilter: Set<string>
  onToggleSeverity: (sev: string) => void
  phaseFilter: Set<ScanPhase>
  onTogglePhase: (phase: ScanPhase) => void
  onClearFilters: () => void
  availableSeverities: string[]
  availablePhases: ScanPhase[]
  onExpandAll: () => void
  onCollapseAll: () => void
}

function ResultsToolbar({
  sortMode,
  sortDirection,
  onSortModeChange,
  onSortDirectionToggle,
  severityFilter,
  onToggleSeverity,
  phaseFilter,
  onTogglePhase,
  onClearFilters,
  availableSeverities,
  availablePhases,
  onExpandAll,
  onCollapseAll,
}: ResultsToolbarProps) {
  const [showFilters, setShowFilters] = useState(false)

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        {/* Left: group-by pills */}
        <div className="flex items-center gap-1">
          <span className="text-xs text-muted-foreground mr-1">Group by:</span>
          {(['severity', 'category', 'phase'] as SortMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => onSortModeChange(mode)}
              className={cn(
                'px-2 py-0.5 text-xs rounded-md border transition-colors',
                sortMode === mode
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'bg-muted/50 text-muted-foreground border-border hover:bg-muted',
              )}
            >
              {mode.charAt(0).toUpperCase() + mode.slice(1)}
            </button>
          ))}
          <button
            type="button"
            onClick={onSortDirectionToggle}
            className="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            title={sortDirection === 'asc' ? 'Sort ascending (most severe first)' : 'Sort descending (least severe first)'}
          >
            {sortDirection === 'asc' ? (
              <SortAsc className="size-3.5" />
            ) : (
              <SortDesc className="size-3.5" />
            )}
          </button>
        </div>

        {/* Right: filter toggle + expand/collapse */}
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-md border transition-colors',
              (severityFilter.size > 0 || phaseFilter.size > 0)
                ? 'bg-primary/10 text-primary border-primary/30'
                : 'bg-muted/50 text-muted-foreground border-border hover:bg-muted',
            )}
          >
            <Filter className="size-3" />
            Filter
            {(severityFilter.size > 0 || phaseFilter.size > 0) && (
              <span className="font-mono">({severityFilter.size + phaseFilter.size})</span>
            )}
          </button>
          <button
            type="button"
            onClick={onExpandAll}
            className="px-2 py-0.5 text-xs rounded-md border bg-muted/50 text-muted-foreground border-border hover:bg-muted transition-colors"
          >
            Expand all
          </button>
          <button
            type="button"
            onClick={onCollapseAll}
            className="px-2 py-0.5 text-xs rounded-md border bg-muted/50 text-muted-foreground border-border hover:bg-muted transition-colors"
          >
            Collapse all
          </button>
        </div>
      </div>

      {/* Filter row (conditionally shown) */}
      {showFilters && (
        <div className="flex items-center gap-3 flex-wrap px-1">
          {/* Severity filters */}
          <div className="flex items-center gap-1">
            <span className="text-xs text-muted-foreground mr-0.5">Severity:</span>
            {availableSeverities
              .sort((a, b) => severityRank(a) - severityRank(b))
              .map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => onToggleSeverity(sev)}
                  className="transition-opacity"
                  style={{ opacity: severityFilter.size === 0 || severityFilter.has(sev) ? 1 : 0.4 }}
                >
                  <SeverityBadge
                    severity={sev}
                    variant={severityFilter.has(sev) ? 'filled' : 'outline'}
                    size="sm"
                  />
                </button>
              ))}
          </div>

          {/* Phase filters */}
          {availablePhases.length > 1 && (
            <div className="flex items-center gap-1">
              <span className="text-xs text-muted-foreground mr-0.5">Phase:</span>
              {availablePhases.map((phase) => {
                const config = PHASE_CONFIG[phase]
                const active = phaseFilter.has(phase)
                return (
                  <button
                    key={phase}
                    type="button"
                    onClick={() => onTogglePhase(phase)}
                    className={cn(
                      'inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded-md border transition-all',
                      active
                        ? 'bg-primary/10 text-primary border-primary/30'
                        : 'text-muted-foreground border-border hover:bg-muted',
                      phaseFilter.size > 0 && !active && 'opacity-40',
                    )}
                  >
                    <config.icon className="size-3" />
                    {config.label}
                  </button>
                )
              })}
            </div>
          )}

          {/* Clear filters */}
          {(severityFilter.size > 0 || phaseFilter.size > 0) && (
            <button
              type="button"
              onClick={onClearFilters}
              className="text-xs text-destructive hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ── Finding Group ──

interface FindingGroupProps {
  groupKey: string
  groupMode: SortMode
  findings: UnifiedFinding[]
  isExpanded: boolean
  expandedFindings: Set<string>
  onToggleGroup: () => void
  onToggleFinding: (id: string) => void
  onViewSource?: (filePath: string, line?: number) => void
}

function FindingGroup({
  groupKey,
  groupMode,
  findings,
  isExpanded,
  expandedFindings,
  onToggleGroup,
  onToggleFinding,
  onViewSource,
}: FindingGroupProps) {
  const groupSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const f of findings) {
      const key = f.severity.toLowerCase()
      counts[key] = (counts[key] || 0) + 1
    }
    return counts
  }, [findings])

  return (
    <div className="rounded-lg border bg-card overflow-hidden">
      {/* Group header */}
      <button
        type="button"
        onClick={onToggleGroup}
        className="w-full flex items-center gap-2 px-3 py-2.5 hover:bg-accent/50 transition-colors text-left"
      >
        {isExpanded ? (
          <ChevronDown className="size-4 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="size-4 text-muted-foreground shrink-0" />
        )}

        {/* Group label */}
        {groupMode === 'severity' && (
          <SeverityBadge severity={groupKey} variant="filled" showIcon size="sm" />
        )}
        {groupMode === 'category' && (
          <CategoryTag category={groupKey} variant="subtle" showIcon size="sm" />
        )}
        {groupMode === 'phase' && (() => {
          const config = PHASE_CONFIG[groupKey as ScanPhase]
          if (!config) return <span className="text-sm font-medium">{groupKey}</span>
          const PhaseIcon = config.icon
          return (
            <span className={cn('inline-flex items-center gap-1 text-sm font-medium', config.color)}>
              <PhaseIcon className="size-3.5" />
              {config.label}
            </span>
          )
        })()}

        {/* Finding count */}
        <span className="text-xs text-muted-foreground">
          {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>

        {/* Severity mini-badges (when not grouped by severity) */}
        {groupMode !== 'severity' && (
          <div className="flex items-center gap-1 ml-auto">
            {(['critical', 'high', 'medium', 'warning', 'low', 'info'] as const).map((sev) => {
              const count = groupSeverityCounts[sev]
              if (!count) return null
              return (
                <SeverityBadge
                  key={sev}
                  severity={sev}
                  variant="subtle"
                  size="sm"
                  label={String(count)}
                />
              )
            })}
          </div>
        )}
      </button>

      {/* Finding rows */}
      {isExpanded && (
        <div className="border-t divide-y divide-border/50">
          {findings.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              groupMode={groupMode}
              isExpanded={expandedFindings.has(finding.id)}
              onToggle={() => onToggleFinding(finding.id)}
              onViewSource={onViewSource}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Finding Row ──

interface FindingRowProps {
  finding: UnifiedFinding
  groupMode: SortMode
  isExpanded: boolean
  onToggle: () => void
  onViewSource?: (filePath: string, line?: number) => void
}

function FindingRow({ finding, groupMode, isExpanded, onToggle, onViewSource }: FindingRowProps) {
  const phaseConfig = PHASE_CONFIG[finding.phase]

  return (
    <div className="bg-card">
      {/* Row header */}
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-4 py-2 hover:bg-accent/30 transition-colors text-left"
      >
        {isExpanded ? (
          <ChevronDown className="size-3.5 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="size-3.5 text-muted-foreground shrink-0" />
        )}

        {/* Severity badge (show when not grouped by severity) */}
        {groupMode !== 'severity' && (
          <SeverityBadge severity={finding.severity} variant="outline" size="sm" />
        )}

        {/* Title */}
        <span className="text-sm truncate min-w-0 flex-1">{finding.title}</span>

        {/* Right-side metadata */}
        <div className="flex items-center gap-1.5 shrink-0">
          {/* Category (show when not grouped by category) */}
          {groupMode !== 'category' && finding.category !== 'manifest' && (
            <CategoryTag category={finding.category} variant="outline" size="sm" showIcon={false} />
          )}

          {/* Phase indicator (show when not grouped by phase) */}
          {groupMode !== 'phase' && (
            <span
              className={cn(
                'inline-flex items-center gap-0.5 text-xs',
                phaseConfig.color,
              )}
              title={`${phaseConfig.label} scan`}
            >
              <phaseConfig.icon className="size-3" />
            </span>
          )}

          {/* CWE badges */}
          {finding.cweIds.length > 0 && (
            <span className="text-xs text-muted-foreground font-mono">
              {finding.cweIds[0]}
              {finding.cweIds.length > 1 && ` +${finding.cweIds.length - 1}`}
            </span>
          )}

          {/* Confidence (manifest) */}
          {finding.confidence && (
            <ConfidenceBadge confidence={finding.confidence} />
          )}
        </div>
      </button>

      {/* Expanded detail */}
      {isExpanded && (
        <FindingDetail finding={finding} onViewSource={onViewSource} />
      )}
    </div>
  )
}

// ── Confidence Badge ──

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const colors: Record<string, string> = {
    high: 'text-green-600 dark:text-green-400 bg-green-500/10',
    medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-500/10',
    low: 'text-gray-500 dark:text-gray-400 bg-gray-500/10',
  }

  return (
    <span
      className={cn(
        'px-1.5 py-0.5 text-[10px] rounded font-medium uppercase',
        colors[confidence.toLowerCase()] || colors.medium,
      )}
    >
      {confidence}
    </span>
  )
}

// ── Finding Detail Panel ──

function FindingDetail({ finding, onViewSource }: { finding: UnifiedFinding; onViewSource?: (filePath: string, line?: number) => void }) {
  return (
    <div className="px-4 py-3 bg-muted/30 border-t space-y-3 text-sm">
      {/* Description */}
      <div>
        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
          Description
        </h4>
        <p className="text-sm text-foreground whitespace-pre-wrap">{finding.description}</p>
      </div>

      {/* Evidence (manifest findings) */}
      {finding.evidence && (
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
            Evidence
          </h4>
          <pre className="text-xs bg-muted rounded-md p-2 overflow-x-auto font-mono whitespace-pre-wrap">
            {finding.evidence}
          </pre>
        </div>
      )}

      {/* File location (SAST) + View Source button */}
      {finding.filePath && (
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
            Location
          </h4>
          <div className="flex items-center gap-2">
            <p className="font-mono text-xs text-foreground">
              {finding.filePath}
              {finding.lineNumber != null && (
                <span className="text-muted-foreground">:{finding.lineNumber}</span>
              )}
            </p>
            {finding.phase === 'sast' && onViewSource && (
              <button
                type="button"
                className="text-xs text-primary hover:underline flex items-center gap-1"
                onClick={() => onViewSource(finding.filePath!, finding.lineNumber ?? undefined)}
              >
                <Code className="size-3" />
                View Source
              </button>
            )}
          </div>
        </div>
      )}

      {/* Bytecode locations */}
      {finding.locations && finding.locations.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
            Occurrences
            {finding.totalOccurrences != null && finding.totalOccurrences > finding.locations.length && (
              <span className="font-normal ml-1">
                (showing {finding.locations.length} of {finding.totalOccurrences})
              </span>
            )}
          </h4>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {finding.locations.map((loc, i) => (
              <BytecodeLocationRow key={i} location={loc} />
            ))}
          </div>
        </div>
      )}

      {/* Metadata row */}
      <div className="flex items-center gap-3 flex-wrap text-xs text-muted-foreground pt-1 border-t border-border/50">
        {/* Rule ID */}
        <span className="font-mono">{finding.ruleId}</span>

        {/* CWE links */}
        {finding.cweIds.length > 0 && (
          <div className="flex items-center gap-1">
            {finding.cweIds.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 text-primary hover:underline"
              >
                {cwe}
                <ExternalLink className="size-2.5" />
              </a>
            ))}
          </div>
        )}

        {/* OWASP / MASVS */}
        {finding.owaspMobile && (
          <span>OWASP: {finding.owaspMobile}</span>
        )}
        {finding.masvs && (
          <span>MASVS: {finding.masvs}</span>
        )}

        {/* Phase */}
        <span className={PHASE_CONFIG[finding.phase].color}>
          {PHASE_CONFIG[finding.phase].label} scan
        </span>
      </div>
    </div>
  )
}

// ── Bytecode Location Row ──

function BytecodeLocationRow({ location }: { location: Record<string, unknown> }) {
  const cls = (location.caller_class || location.using_class || '') as string
  const method = (location.caller_method || location.using_method || '') as string
  const target = (location.target || location.string_value || location.dangerous_class || '') as string

  if (!cls && !method && !target) return null

  return (
    <div className="flex items-center gap-2 font-mono text-xs py-0.5">
      {cls && (
        <span className="text-purple-500 dark:text-purple-400 truncate max-w-[250px]" title={cls}>
          {cls.split('.').pop() || cls}
        </span>
      )}
      {method && (
        <>
          <span className="text-muted-foreground">.</span>
          <span className="text-blue-500 dark:text-blue-400">{method}</span>
        </>
      )}
      {target && (
        <>
          <span className="text-muted-foreground">→</span>
          <span className="text-foreground truncate max-w-[300px]" title={target}>
            {target}
          </span>
        </>
      )}
    </div>
  )
}

// ── Scan Errors ──

function ScanErrors({
  manifest,
  bytecode,
  sast,
}: {
  manifest?: ManifestScanResponse | null
  bytecode?: BytecodeScanResponse | null
  sast?: SastScanResponse | null
}) {
  const errors: { phase: ScanPhase; message: string }[] = []
  if (manifest?.error) errors.push({ phase: 'manifest', message: manifest.error })
  if (bytecode?.error) errors.push({ phase: 'bytecode', message: bytecode.error })
  if (sast?.error) errors.push({ phase: 'sast', message: sast.error })

  if (errors.length === 0) return null

  return (
    <div className="space-y-2">
      {errors.map(({ phase, message }) => {
        const config = PHASE_CONFIG[phase]
        return (
          <div
            key={phase}
            className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm"
          >
            <AlertTriangle className="size-4 text-destructive shrink-0 mt-0.5" />
            <div>
              <span className="font-medium text-destructive">{config.label} scan error:</span>{' '}
              <span className="text-foreground">{message}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
