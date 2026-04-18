import { Fragment, type ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import type { HardwareFirmwareBlob } from '@/api/hardwareFirmware'

interface BlobTableProps {
  blobs: HardwareFirmwareBlob[]
  selectedId: string | null
  onSelect: (id: string) => void
  searchQuery?: string
}

// Exhaustive Record fallback per CLAUDE.md rule 9.
const SIGNED_STYLE: Record<string, string> = {
  signed: 'border-green-500/50 text-green-600 dark:text-green-400',
  unsigned: 'border-red-500/50 text-red-600 dark:text-red-400',
  unknown: 'border-gray-500/50 text-gray-500',
  weakly_signed: 'border-orange-500/50 text-orange-600 dark:text-orange-400',
}

function cveBadgeClass(severity: string | null | undefined): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-700'
    case 'high':
      return 'bg-red-600'
    case 'medium':
      return 'bg-amber-600'
    case 'low':
      return 'bg-yellow-600'
    default:
      return 'bg-red-600'
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Strip storage prefix so paths display as "partition_4_erofs/lib/modules/foo.ko"
// instead of the full container storage path.  Matches any path containing
// "/extracted/rootfs/", "/extracted/", or "/firmware/<uuid>/extracted".
export function displayPath(abs: string): string {
  const markers = ['/extracted/rootfs/', '/extracted/']
  for (const m of markers) {
    const idx = abs.indexOf(m)
    if (idx >= 0) return abs.slice(idx + m.length)
  }
  return abs
}

/**
 * Render ``text`` with every case-insensitive occurrence of ``query``
 * wrapped in a <mark> element so search hits are visually obvious.
 * Empty / whitespace queries short-circuit to the raw string.  Query
 * characters are escaped before being compiled as a regex literal so
 * paths with dots / dashes don't turn into surprise regex operators.
 */
export function highlightMatches(text: string, query: string | undefined): ReactNode {
  const q = (query ?? '').trim()
  if (!q) return text
  const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Split with a capture group returns alternating non-match / match
  // segments, so odd indices are the hits — no need to re-test, which
  // would be unreliable with the global flag's stateful lastIndex.
  const re = new RegExp(`(${safe})`, 'gi')
  const parts = text.split(re)
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <mark
        key={i}
        className="rounded-sm bg-amber-300/50 px-0.5 text-foreground dark:bg-amber-400/30"
      >
        {part}
      </mark>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  )
}

export default function BlobTable({
  blobs,
  selectedId,
  onSelect,
  searchQuery,
}: BlobTableProps) {
  if (blobs.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware firmware blobs match the current filters.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border bg-muted/30 text-left text-muted-foreground">
            <th className="py-2 pl-3 pr-3 font-medium">Path</th>
            <th className="py-2 pr-3 font-medium">Category</th>
            <th className="py-2 pr-3 font-medium">Vendor</th>
            <th className="py-2 pr-3 font-medium">Format</th>
            <th className="py-2 pr-3 font-medium text-right">Size</th>
            <th className="py-2 pr-3 font-medium">CVEs</th>
            <th className="py-2 pr-3 font-medium">Signed</th>
          </tr>
        </thead>
        <tbody>
          {blobs.map((b) => {
            const isSelected = selectedId === b.id
            const signedStyle =
              SIGNED_STYLE[b.signed] ?? 'border-border text-muted-foreground'
            return (
              <tr
                key={b.id}
                onClick={() => onSelect(b.id)}
                className={`cursor-pointer border-b border-border/50 transition-colors ${
                  isSelected ? 'bg-accent/60' : 'hover:bg-accent/30'
                }`}
              >
                <td className="py-1.5 pl-3 pr-3 font-mono text-[11px]" title={b.blob_path}>
                  <div className="max-w-[340px] truncate">
                    {highlightMatches(displayPath(b.blob_path), searchQuery)}
                  </div>
                </td>
                <td className="py-1.5 pr-3 text-muted-foreground">{b.category}</td>
                <td className="py-1.5 pr-3">{b.vendor ?? '—'}</td>
                <td className="py-1.5 pr-3 font-mono text-[11px]">{b.format}</td>
                <td className="py-1.5 pr-3 text-right tabular-nums">
                  {formatBytes(b.file_size)}
                </td>
                <td className="py-1.5 pr-3">
                  {b.cve_count > 0 ? (
                    <Badge
                      className={`text-[10px] text-white ${cveBadgeClass(b.max_severity)}`}
                      title={`max severity: ${b.max_severity ?? 'unknown'}`}
                    >
                      {b.cve_count}
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground/60">—</span>
                  )}
                  {b.advisory_count > 0 && (
                    <Badge
                      className="ml-1 text-[10px] bg-amber-600 text-white"
                      title={`${b.advisory_count} advisory flag(s)`}
                    >
                      ADV
                    </Badge>
                  )}
                </td>
                <td className="py-1.5 pr-3">
                  <Badge variant="outline" className={`text-[10px] ${signedStyle}`}>
                    {b.signed}
                  </Badge>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
