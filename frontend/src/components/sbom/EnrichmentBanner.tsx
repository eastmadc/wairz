import { ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from 'lucide-react'
import type { NvdEnrichmentStatus } from '@/types'
import { isEnrichmentSubstantiated } from '@/types'

/**
 * Renders the CVE-enrichment verdict ABOVE the vulnerability counts it
 * qualifies.
 *
 * A vulnerability scan run against a missing or half-populated pinned NVD
 * cache (Rule #37) persists `status='completed'` with ZERO rows — byte
 * identical to a genuinely clean firmware. Showing "0 vulnerabilities" with
 * no marker is therefore a false clean verdict, not a neutral one. The
 * backend records which CVE source answered each lookup; this component is
 * how the operator actually sees it.
 *
 * Placement contract: the banner must PRECEDE or ACCOMPANY the number it
 * invalidates. Never render it below the counts.
 */

interface EnrichmentConfigEntry {
  label: string
  /** Short line shown when the backend supplied no warning text. */
  detail: string
  className: string
  Icon: typeof ShieldAlert
  /** true = counts below are trustworthy; no banner rendered. */
  clean: boolean
}

// Rule #9: EXHAUSTIVE over NvdEnrichmentStatus. Mirrors ENRICHMENT_STATUSES in
// backend/app/services/nvd_provenance_surface.py — adding a backend value
// without extending this map yields `undefined` and blanks the page. The
// lookup below still applies `?? UNKNOWN_ENTRY` as defence in depth.
const ENRICHMENT_CONFIG: Record<NvdEnrichmentStatus, EnrichmentConfigEntry> = {
  complete: {
    label: 'CVE enrichment complete',
    detail: 'Every component lookup was answered by the pinned NVD cache.',
    className: 'border-green-500/40 bg-green-500/5 text-green-700 dark:text-green-400',
    Icon: ShieldCheck,
    clean: true,
  },
  live: {
    label: 'CVE enrichment used the live NVD API',
    detail: 'Enriched, but not reproducible against the pinned manifest.',
    className: 'border-blue-500/40 bg-blue-500/5 text-blue-700 dark:text-blue-400',
    Icon: ShieldCheck,
    clean: true,
  },
  partial: {
    label: 'CVE enrichment INCOMPLETE — counts under-report',
    detail:
      'Some component lookups hit an unavailable or degraded pinned NVD cache. '
      + 'Absence of a CVE below is not evidence it does not apply.',
    className: 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-400',
    Icon: ShieldAlert,
    clean: false,
  },
  none: {
    label: 'CVE enrichment DID NOT RUN',
    detail:
      'The pinned NVD cache was unavailable for every lookup. A result of 0 '
      + 'here means "not looked up", NOT "no known CVEs".',
    className: 'border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-400',
    Icon: ShieldX,
    clean: false,
  },
  not_applicable: {
    label: 'No components were checked for CVEs',
    detail:
      'No component carried a CPE identifier, so nothing was looked up. '
      + 'This is not evidence the firmware is free of known CVEs.',
    className: 'border-yellow-500/50 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400',
    Icon: ShieldQuestion,
    clean: false,
  },
  unknown: {
    label: 'CVE enrichment provenance NOT RECORDED',
    detail:
      'This scan predates provenance stamping (or was written by another '
      + 'path). Counts cannot be attributed to a pinned NVD cache generation; '
      + 're-run the scan for a reproducible result.',
    className: 'border-yellow-500/50 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400',
    Icon: ShieldQuestion,
    clean: false,
  },
}

const UNKNOWN_ENTRY = ENRICHMENT_CONFIG.unknown

export interface EnrichmentBannerProps {
  status: NvdEnrichmentStatus | null | undefined
  warning?: string | null
  provenance?: Record<string, unknown> | null
  /** Render the reassuring green/blue line too. Default: only warn. */
  showWhenClean?: boolean
  className?: string
}

export function EnrichmentBanner({
  status,
  warning,
  provenance,
  showWhenClean = false,
  className = '',
}: EnrichmentBannerProps) {
  if (!status) return null

  const cfg = ENRICHMENT_CONFIG[status] ?? UNKNOWN_ENTRY
  if (cfg.clean && !showWhenClean) return null

  const { Icon } = cfg
  const manifestSha = typeof provenance?.manifest_sha === 'string'
    ? provenance.manifest_sha
    : null
  const engine = typeof provenance?.engine === 'string' ? provenance.engine : null

  return (
    <div
      role={cfg.clean ? 'status' : 'alert'}
      className={`flex items-start gap-2.5 rounded-md border px-3 py-2.5 text-xs ${cfg.className} ${className}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0 space-y-1">
        <p className="font-medium leading-snug">{cfg.label}</p>
        {/* Backend warning wins — it carries the live lookup counts. */}
        <p className="leading-snug opacity-90">{warning || cfg.detail}</p>
        {(manifestSha || engine) && (
          <p className="font-mono text-[10px] leading-snug opacity-70">
            CVE source: {engine ?? 'unknown'}
            {manifestSha ? ` · manifest ${manifestSha.slice(0, 12)}` : ''}
          </p>
        )}
      </div>
    </div>
  )
}

/**
 * Inline one-liner for tight spots (next to a count, in a toolbar row).
 * Same substantiation rule as the banner: silent only on positive evidence.
 */
export function EnrichmentInlineNote({
  status,
}: {
  status: NvdEnrichmentStatus | null | undefined
}) {
  if (!status || isEnrichmentSubstantiated(status)) return null
  const cfg = ENRICHMENT_CONFIG[status] ?? UNKNOWN_ENTRY
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-orange-600 dark:text-orange-400">
      <ShieldAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
      {cfg.label} — this is not a clean result
    </span>
  )
}

export default EnrichmentBanner
