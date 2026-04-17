import { useMemo } from 'react'
import { Badge } from '@/components/ui/badge'
import type { HardwareFirmwareBlob } from '@/api/hardwareFirmware'

interface VendorRollupProps {
  blobs: HardwareFirmwareBlob[]
  onVendorClick?: (vendor: string | null) => void
  max?: number
}

// Display label for a vendor, with a fallback for null/unknown.
function displayVendor(vendor: string | null): string {
  if (!vendor) return 'unknown'
  return vendor
}

/**
 * Horizontal pill row summarising vendor counts, e.g.
 *   [MediaTek 47] [ARM 3] [AWINIC 1] [Unknown 12]
 *
 * Sorted by count desc and capped at `max` visible pills (default 10).
 * Click a pill → filters the page to that vendor (if callback is supplied).
 */
export default function VendorRollup({
  blobs,
  onVendorClick,
  max = 10,
}: VendorRollupProps) {
  const entries = useMemo(() => {
    const counts = new Map<string, number>()
    for (const b of blobs) {
      const key = displayVendor(b.vendor)
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1])
  }, [blobs])

  if (entries.length === 0) return null

  const visible = entries.slice(0, max)
  const overflow = entries.length - visible.length

  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map(([vendor, count]) => {
        const isUnknown = vendor === 'unknown'
        const clickable = !!onVendorClick && !isUnknown
        return (
          <Badge
            key={vendor}
            variant="outline"
            className={`text-[10px] ${
              clickable ? 'cursor-pointer hover:bg-accent' : ''
            } ${isUnknown ? 'border-gray-500/40 text-muted-foreground' : ''}`}
            onClick={() => {
              if (onVendorClick && !isUnknown) onVendorClick(vendor)
            }}
          >
            <span className="font-medium">{vendor}</span>
            <span className="ml-1 tabular-nums opacity-70">{count}</span>
          </Badge>
        )
      })}
      {overflow > 0 && (
        <Badge
          variant="outline"
          className="border-border text-[10px] text-muted-foreground"
          title={entries
            .slice(max)
            .map(([v, c]) => `${v}: ${c}`)
            .join(' · ')}
        >
          +{overflow} more
        </Badge>
      )}
    </div>
  )
}
