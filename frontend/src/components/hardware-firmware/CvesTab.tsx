import { Fragment, useMemo, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import type { CveRow, HardwareFirmwareBlob } from '@/api/hardwareFirmware'
import { displayPath, highlightMatches } from './BlobTable'

interface CvesTabProps {
  cves: CveRow[]
  blobs: HardwareFirmwareBlob[]
  loading: boolean
  searchQuery?: string
  onSelectBlob: (blobId: string) => void
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-700 text-white',
  high: 'bg-red-600 text-white',
  medium: 'bg-amber-600 text-white',
  low: 'bg-yellow-600 text-black',
  unknown: 'bg-gray-500 text-white',
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
}

type SortKey = 'severity' | 'affected' | 'tier' | 'cve_id'

function filterCves(cves: CveRow[], query: string): CveRow[] {
  if (!query) return cves
  const q = query.toLowerCase()
  return cves.filter((c) =>
    [
      c.cve_id,
      c.severity,
      c.match_tier ?? '',
      c.description ?? '',
      c.affected_formats.join(' '),
    ]
      .join(' ')
      .toLowerCase()
      .includes(q),
  )
}

function sortCves(cves: CveRow[], key: SortKey): CveRow[] {
  const out = [...cves]
  out.sort((a, b) => {
    switch (key) {
      case 'severity': {
        const diff =
          (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
        if (diff !== 0) return diff
        return b.affected_blob_count - a.affected_blob_count
      }
      case 'affected':
        return b.affected_blob_count - a.affected_blob_count
      case 'tier':
        return (a.match_tier ?? '').localeCompare(b.match_tier ?? '')
      case 'cve_id':
        return a.cve_id.localeCompare(b.cve_id)
    }
  })
  return out
}

export default function CvesTab({
  cves,
  blobs,
  loading,
  searchQuery,
  onSelectBlob,
}: CvesTabProps) {
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const blobsById = useMemo(() => {
    const m = new Map<string, HardwareFirmwareBlob>()
    for (const b of blobs) m.set(b.id, b)
    return m
  }, [blobs])

  const rows = useMemo(
    () => sortCves(filterCves(cves, (searchQuery ?? '').trim()), sortKey),
    [cves, searchQuery, sortKey],
  )

  if (loading) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        Loading CVEs…
      </div>
    )
  }
  if (rows.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware-firmware CVEs detected. Run the matcher from the
        header to populate findings.
      </div>
    )
  }

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>Sort by:</span>
        {(
          [
            ['severity', 'Severity'],
            ['affected', 'Affected blobs'],
            ['tier', 'Match tier'],
            ['cve_id', 'CVE ID'],
          ] as const
        ).map(([k, label]) => (
          <button
            key={k}
            type="button"
            onClick={() => setSortKey(k)}
            className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
              sortKey === k
                ? 'border-primary/60 bg-primary/10 text-foreground'
                : 'border-border hover:bg-accent/30'
            }`}
          >
            {label}
          </button>
        ))}
        <span className="ml-auto">{rows.length} CVE{rows.length === 1 ? '' : 's'}</span>
      </div>

      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/30 text-left text-muted-foreground">
              <th className="py-2 pl-3 pr-3 font-medium">Severity</th>
              <th className="py-2 pr-3 font-medium">CVE</th>
              <th className="py-2 pr-3 font-medium">Tier</th>
              <th className="py-2 pr-3 font-medium text-right">Blobs</th>
              <th className="py-2 pr-3 font-medium">Formats</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const isOpen = expanded.has(c.cve_id)
              return (
                <Fragment key={c.cve_id}>
                  <tr
                    onClick={() => toggle(c.cve_id)}
                    className="cursor-pointer border-b border-border/50 transition-colors hover:bg-accent/30"
                  >
                    <td className="py-1.5 pl-3 pr-3">
                      <Badge
                        className={`text-[10px] ${
                          SEVERITY_STYLE[c.severity] ?? SEVERITY_STYLE.unknown
                        }`}
                      >
                        {c.severity}
                      </Badge>
                      {c.cvss_score != null && (
                        <span className="ml-1 text-[10px] tabular-nums text-muted-foreground">
                          {c.cvss_score}
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] font-semibold">
                      {highlightMatches(c.cve_id, searchQuery)}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[10px] text-muted-foreground">
                      {c.match_tier ?? '—'}
                    </td>
                    <td className="py-1.5 pr-3 text-right font-mono tabular-nums">
                      {c.affected_blob_count}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[10px] text-muted-foreground">
                      {c.affected_formats.join(', ')}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="border-b border-border/50 bg-muted/20">
                      <td colSpan={5} className="px-4 py-3 text-[11px]">
                        {c.description && (
                          <p className="mb-2 text-muted-foreground">
                            {c.description}
                          </p>
                        )}
                        <p className="mb-1 text-xs font-medium text-muted-foreground">
                          Affected blobs ({c.affected_blob_count})
                        </p>
                        <ul className="space-y-0.5">
                          {c.affected_blob_ids.map((bid) => {
                            const blob = blobsById.get(bid)
                            if (!blob) {
                              return (
                                <li
                                  key={bid}
                                  className="break-all font-mono text-[10px] text-muted-foreground"
                                >
                                  {bid}
                                </li>
                              )
                            }
                            return (
                              <li key={bid}>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    onSelectBlob(bid)
                                  }}
                                  className="break-all text-left font-mono text-[11px] text-blue-500 hover:underline"
                                >
                                  {displayPath(blob.blob_path)}
                                </button>
                                <span className="ml-2 font-mono text-[10px] text-muted-foreground">
                                  {blob.format}
                                </span>
                              </li>
                            )
                          })}
                        </ul>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
