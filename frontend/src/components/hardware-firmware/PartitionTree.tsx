import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, Cpu } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import type { HardwareFirmwareBlob } from '@/api/hardwareFirmware'
import VendorRollup from './VendorRollup'
import { displayPath, highlightMatches } from './BlobTable'

interface PartitionTreeProps {
  blobs: HardwareFirmwareBlob[]
  selectedId: string | null
  onSelect: (id: string) => void
  // Text-search query applied in-place; when non-empty, only blobs
  // whose path, format, version, or chipset contains the query (case-
  // insensitive) survive, and their containing partition + vendor
  // auto-expand so matches are visible without a click.
  searchQuery?: string
  // Sort order for partition headers: "blobs" (default, largest first)
  // or "cves" (partitions with the most CVE findings first).
  sortMode?: 'blobs' | 'cves'
}

// Exhaustive signed-badge style map (CLAUDE.md rule 9).  The `?? fallback`
// at the call site covers any future signed status not in this map.
const SIGNED_STYLE: Record<string, string> = {
  signed: 'border-green-500/50 text-green-600 dark:text-green-400',
  unsigned: 'border-red-500/50 text-red-600 dark:text-red-400',
  unknown: 'border-gray-500/50 text-gray-500',
  weakly_signed: 'border-orange-500/50 text-orange-600 dark:text-orange-400',
}

// Severity → CVE badge background color.  Critical/high stand out (red),
// medium gets warning amber, low/unknown stay neutral so the eye is
// drawn to the worst risk first.
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
      return 'bg-red-600'  // CVEs without severity rank still flag red
  }
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

function worstSeverity(blobs: HardwareFirmwareBlob[]): string | null {
  let best = 0
  let label: string | null = null
  for (const b of blobs) {
    const rank = b.max_severity ? SEVERITY_RANK[b.max_severity] ?? 0 : 0
    if (rank > best) {
      best = rank
      label = b.max_severity
    }
  }
  return label
}

const UNKNOWN_PARTITION = '(unknown partition)'
const UNKNOWN_VENDOR = 'unknown'

// Derive the partition name for a blob.  Prefers `blob.partition`; falls
// back to the top-level dir of the extracted path (vendor, system, odm,
// system_ext, product, ...).
function partitionOf(blob: HardwareFirmwareBlob): string {
  if (blob.partition) return blob.partition
  const rel = displayPath(blob.blob_path)
  const top = rel.split('/').filter(Boolean)[0]
  return top ?? UNKNOWN_PARTITION
}

function vendorOf(blob: HardwareFirmwareBlob): string {
  return blob.vendor ?? UNKNOWN_VENDOR
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

interface Grouped {
  partitions: {
    key: string
    blobs: HardwareFirmwareBlob[]
    vendors: { key: string; blobs: HardwareFirmwareBlob[] }[]
    cveCount: number
    maxSeverity: string | null
  }[]
}

/**
 * Decide which partitions should be open on first render / after a
 * filter change.  Priority:
 *   1. Partitions containing any CVE-bearing blob (security researcher
 *      lands on "where are the 26 CVEs?" — show them without clicks).
 *   2. Fallback to the single largest partition when nothing has CVEs
 *      (existing behaviour, preserved).
 *
 * Exported for unit testing — pure function, no React state.
 */
export function pickDefaultOpenPartitions(
  partitions: Grouped['partitions'],
): Set<string> {
  const s = new Set<string>()
  for (const p of partitions) {
    if (p.cveCount > 0) s.add(p.key)
  }
  if (s.size === 0 && partitions.length > 0) {
    s.add(partitions[0].key)
  }
  return s
}

/**
 * Mirror of ``pickDefaultOpenPartitions`` for the vendor tier.  Opens
 * any vendor group that holds a CVE-bearing blob, so after the
 * CVE-auto-expansion the user sees the actual blob rows rather than a
 * second layer of "click to expand" buttons.  Keys are
 * ``${partitionKey}::${vendorKey}`` to match the tree's open-state
 * convention.
 *
 * Exported for unit testing.
 */
export function pickDefaultOpenVendors(
  partitions: Grouped['partitions'],
): Set<string> {
  const s = new Set<string>()
  for (const p of partitions) {
    for (const v of p.vendors) {
      if (v.blobs.some((b) => b.cve_count > 0)) {
        s.add(`${p.key}::${v.key}`)
      }
    }
  }
  return s
}

/**
 * Build "every partition" and "every vendor" key sets for the
 * Expand-all affordance.  Works on the already-grouped tree so the
 * keys match the tree's open-state convention exactly.
 */
export function buildAllOpenKeys(
  partitions: Grouped['partitions'],
): { partitions: Set<string>; vendors: Set<string> } {
  const p = new Set<string>()
  const v = new Set<string>()
  for (const part of partitions) {
    p.add(part.key)
    for (const ven of part.vendors) {
      v.add(`${part.key}::${ven.key}`)
    }
  }
  return { partitions: p, vendors: v }
}

function groupBlobs(
  blobs: HardwareFirmwareBlob[],
  sortMode: 'blobs' | 'cves',
): Grouped {
  const byPartition = new Map<string, HardwareFirmwareBlob[]>()
  for (const b of blobs) {
    const p = partitionOf(b)
    const list = byPartition.get(p)
    if (list) list.push(b)
    else byPartition.set(p, [b])
  }

  const partitions = [...byPartition.entries()]
    .map(([key, items]) => {
      const byVendor = new Map<string, HardwareFirmwareBlob[]>()
      for (const b of items) {
        const v = vendorOf(b)
        const list = byVendor.get(v)
        if (list) list.push(b)
        else byVendor.set(v, [b])
      }
      const vendors = [...byVendor.entries()]
        .sort((a, b) => b[1].length - a[1].length)
        .map(([vKey, vItems]) => ({
          key: vKey,
          blobs: vItems.sort((a, b) =>
            displayPath(a.blob_path).localeCompare(displayPath(b.blob_path)),
          ),
        }))
      return {
        key,
        blobs: items,
        vendors,
        cveCount: items.reduce((acc, b) => acc + (b.cve_count || 0), 0),
        maxSeverity: worstSeverity(items),
      }
    })
    .sort((a, b) => {
      if (sortMode === 'cves') {
        if (b.cveCount !== a.cveCount) return b.cveCount - a.cveCount
      }
      return b.blobs.length - a.blobs.length
    })

  return { partitions }
}

/**
 * Hierarchical tree view of hardware firmware blobs: partition → vendor
 * → blob.  Reuses `onSelect`/`selectedId` so `BlobDetail` continues to
 * work unchanged.
 *
 * Keyboard accessible: partition / vendor / blob rows are <button>
 * elements, so Enter and Space toggle or select them natively.
 */
export default function PartitionTree({
  blobs,
  selectedId,
  onSelect,
  searchQuery,
  sortMode = 'blobs',
}: PartitionTreeProps) {
  const grouped = useMemo(
    () => groupBlobs(blobs, sortMode),
    [blobs, sortMode],
  )

  // Default: expand every partition with CVEs; fall back to the largest
  // partition when nothing qualifies (keeps the pre-fix behaviour when
  // a firmware has zero findings).
  const defaultOpenPartitions = useMemo(
    () => pickDefaultOpenPartitions(grouped.partitions),
    [grouped.partitions],
  )
  // Also expand any vendor groups that hold CVE-bearing blobs so the
  // auto-expanded partitions show the actual blob rows, not a second
  // layer of collapsed vendor headers.
  const defaultOpenVendors = useMemo(
    () => pickDefaultOpenVendors(grouped.partitions),
    [grouped.partitions],
  )

  const [openPartitions, setOpenPartitions] = useState<Set<string>>(
    defaultOpenPartitions,
  )
  const [openVendors, setOpenVendors] = useState<Set<string>>(
    defaultOpenVendors,
  )

  // If the set of partitions changes (filters toggled, firmware
  // switched), re-apply the default so CVE-bearing partitions AND
  // their vendors are visible without extra clicks.
  useEffect(() => {
    setOpenPartitions(defaultOpenPartitions)
    setOpenVendors(defaultOpenVendors)
  }, [defaultOpenPartitions, defaultOpenVendors])

  // Text-search auto-expansion: when the query is non-empty, open every
  // partition + vendor whose descendant blobs match, so the filtered
  // tree isn't hiding the hit behind a collapsed row.
  const query = (searchQuery ?? '').trim().toLowerCase()
  useEffect(() => {
    if (!query) return
    const newPartitions = new Set<string>()
    const newVendors = new Set<string>()
    for (const p of grouped.partitions) {
      for (const v of p.vendors) {
        for (const b of v.blobs) {
          if (matchesQuery(b, query)) {
            newPartitions.add(p.key)
            newVendors.add(`${p.key}::${v.key}`)
          }
        }
      }
    }
    setOpenPartitions(newPartitions.size ? newPartitions : defaultOpenPartitions)
    setOpenVendors(newVendors.size ? newVendors : defaultOpenVendors)
  }, [query, grouped.partitions, defaultOpenPartitions, defaultOpenVendors])

  const allPartitionsOpen = useMemo(() => {
    if (grouped.partitions.length === 0) return false
    return grouped.partitions.every((p) => openPartitions.has(p.key))
  }, [grouped.partitions, openPartitions])

  const expandAll = () => {
    const all = buildAllOpenKeys(grouped.partitions)
    setOpenPartitions(all.partitions)
    setOpenVendors(all.vendors)
  }

  const collapseAll = () => {
    setOpenPartitions(new Set())
    setOpenVendors(new Set())
  }

  const togglePartition = (key: string) => {
    setOpenPartitions((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const toggleVendor = (key: string) => {
    setOpenVendors((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  if (blobs.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware firmware blobs match the current filters.
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[11px] text-muted-foreground">
          {grouped.partitions.length} partition
          {grouped.partitions.length === 1 ? '' : 's'} ·{' '}
          {grouped.partitions.reduce((a, p) => a + p.blobs.length, 0)} blobs
        </span>
        <button
          type="button"
          onClick={allPartitionsOpen ? collapseAll : expandAll}
          className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] transition-colors hover:bg-accent/30"
          title={
            allPartitionsOpen
              ? 'Collapse every partition + vendor group'
              : 'Expand every partition + vendor group to show all blobs'
          }
        >
          {allPartitionsOpen ? (
            <>
              <ChevronsDownUp className="h-3.5 w-3.5" />
              Collapse all
            </>
          ) : (
            <>
              <ChevronsUpDown className="h-3.5 w-3.5" />
              Expand all
            </>
          )}
        </button>
      </div>
      {grouped.partitions.map((partition) => {
        const isOpen = openPartitions.has(partition.key)
        return (
          <div
            key={partition.key}
            className="overflow-hidden rounded-md border border-border"
          >
            <button
              type="button"
              onClick={() => togglePartition(partition.key)}
              aria-expanded={isOpen}
              className="flex w-full items-center gap-2 bg-muted/30 px-3 py-2 text-left text-xs transition-colors hover:bg-muted/50"
            >
              {isOpen ? (
                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
              )}
              <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="font-mono font-medium">{partition.key}</span>
              <Badge variant="outline" className="text-[10px]">
                {partition.blobs.length} blob
                {partition.blobs.length === 1 ? '' : 's'}
              </Badge>
              {partition.cveCount > 0 && (
                <Badge
                  className={`text-[10px] text-white ${cveBadgeClass(partition.maxSeverity)}`}
                  title={`${partition.cveCount} CVE finding${
                    partition.cveCount === 1 ? '' : 's'
                  } across this partition (max severity: ${partition.maxSeverity ?? 'unknown'})`}
                >
                  {partition.cveCount} CVE · {partition.maxSeverity ?? 'unknown'}
                </Badge>
              )}
              <div className="ml-auto">
                <VendorRollup blobs={partition.blobs} max={6} />
              </div>
            </button>

            {isOpen && (
              <div className="border-t border-border bg-background">
                {partition.vendors.map((vendor) => {
                  const vendorKey = `${partition.key}::${vendor.key}`
                  const vendorOpen = openVendors.has(vendorKey)
                  return (
                    <div
                      key={vendorKey}
                      className="border-b border-border/50 last:border-b-0"
                    >
                      <button
                        type="button"
                        onClick={() => toggleVendor(vendorKey)}
                        aria-expanded={vendorOpen}
                        className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition-colors hover:bg-accent/30"
                      >
                        {vendorOpen ? (
                          <ChevronDown className="h-3 w-3 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-3 w-3 text-muted-foreground" />
                        )}
                        <span className="font-medium">{vendor.key}</span>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${
                            vendor.key === UNKNOWN_VENDOR
                              ? 'border-gray-500/40 text-muted-foreground'
                              : ''
                          }`}
                        >
                          {vendor.blobs.length}
                        </Badge>
                      </button>

                      {vendorOpen && (
                        <ul className="divide-y divide-border/50">
                          {vendor.blobs
                            .filter((b) => !query || matchesQuery(b, query))
                            .map((b) => {
                              const isSelected = selectedId === b.id
                              const signedStyle =
                                SIGNED_STYLE[b.signed] ??
                                'border-border text-muted-foreground'
                              return (
                                <li key={b.id}>
                                  <button
                                    type="button"
                                    onClick={() => onSelect(b.id)}
                                    aria-pressed={isSelected}
                                    className={`flex w-full items-center gap-2 px-6 py-1 text-left text-[11px] transition-colors ${
                                      isSelected
                                        ? 'bg-accent/60'
                                        : 'hover:bg-accent/30'
                                    }`}
                                    title={b.blob_path}
                                  >
                                    <span className="flex-1 truncate font-mono">
                                      {highlightMatches(
                                        displayPath(b.blob_path),
                                        query,
                                      )}
                                    </span>
                                    <span className="font-mono text-[10px] text-muted-foreground">
                                      {b.category}
                                    </span>
                                    <span className="font-mono text-[10px] text-muted-foreground">
                                      {b.format}
                                    </span>
                                    {b.version && (
                                      <Badge
                                        variant="outline"
                                        className="font-mono text-[10px] border-blue-500/40 text-blue-700 dark:text-blue-400"
                                        title={`Parser-extracted version: ${b.version}`}
                                      >
                                        v{b.version}
                                      </Badge>
                                    )}
                                    {b.cve_count > 0 && (
                                      <Badge
                                        className={`text-[10px] text-white ${cveBadgeClass(b.max_severity)}`}
                                        title={`${b.cve_count} CVE${b.cve_count === 1 ? '' : 's'} matched (max severity: ${b.max_severity ?? 'unknown'})`}
                                      >
                                        {b.cve_count} CVE
                                      </Badge>
                                    )}
                                    {b.advisory_count > 0 && (
                                      <Badge
                                        className="text-[10px] bg-amber-600 text-white"
                                        title={`${b.advisory_count} advisory presence flag(s)`}
                                      >
                                        ADV
                                      </Badge>
                                    )}
                                    <span className="w-16 text-right font-mono tabular-nums text-[10px] text-muted-foreground">
                                      {formatBytes(b.file_size)}
                                    </span>
                                    <Badge
                                      variant="outline"
                                      className={`w-24 justify-center text-[10px] ${signedStyle}`}
                                    >
                                      {b.signed}
                                    </Badge>
                                  </button>
                                </li>
                              )
                            })}
                        </ul>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

/**
 * Case-insensitive substring match across the blob's searchable text
 * fields.  Exported so the page-level filtered count stays consistent
 * with the in-tree filter.
 */
export function matchesQuery(blob: HardwareFirmwareBlob, query: string): boolean {
  if (!query) return true
  const q = query.toLowerCase()
  const haystack = [
    blob.blob_path,
    blob.format,
    blob.category,
    blob.vendor ?? '',
    blob.version ?? '',
    blob.chipset_target ?? '',
    blob.partition ?? '',
  ]
    .join(' ')
    .toLowerCase()
  return haystack.includes(q)
}
