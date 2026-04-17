import { Badge } from '@/components/ui/badge'
import type { HardwareFirmwareBlob } from '@/api/hardwareFirmware'

interface BlobTableProps {
  blobs: HardwareFirmwareBlob[]
  selectedId: string | null
  onSelect: (id: string) => void
}

// Exhaustive Record fallback per CLAUDE.md rule 9 — new backend "signed"
// values must be added here OR the lookup falls back via `??`.
const SIGNED_STYLE: Record<string, string> = {
  signed: 'border-green-500/50 text-green-600 dark:text-green-400',
  unsigned: 'border-red-500/50 text-red-600 dark:text-red-400',
  unknown: 'border-gray-500/50 text-gray-500',
  weakly_signed: 'border-orange-500/50 text-orange-600 dark:text-orange-400',
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function BlobTable({ blobs, selectedId, onSelect }: BlobTableProps) {
  if (blobs.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware firmware blobs match the current filters.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground">
            <th className="py-2 pr-3 font-medium">Path</th>
            <th className="py-2 pr-3 font-medium">Vendor</th>
            <th className="py-2 pr-3 font-medium">Format</th>
            <th className="py-2 pr-3 font-medium">Version</th>
            <th className="py-2 pr-3 font-medium text-right">Size</th>
            <th className="py-2 pr-3 font-medium">Signed</th>
          </tr>
        </thead>
        <tbody>
          {blobs.map((b) => {
            const isSelected = selectedId === b.id
            const signedStyle = SIGNED_STYLE[b.signed] ?? 'border-border text-muted-foreground'
            return (
              <tr
                key={b.id}
                onClick={() => onSelect(b.id)}
                className={`cursor-pointer border-b border-border/50 transition-colors ${
                  isSelected ? 'bg-accent/60' : 'hover:bg-accent/30'
                }`}
              >
                <td className="py-1.5 pr-3 font-mono text-[11px]" title={b.blob_path}>
                  <div className="max-w-[260px] truncate">{b.blob_path}</div>
                </td>
                <td className="py-1.5 pr-3">{b.vendor ?? '-'}</td>
                <td className="py-1.5 pr-3 font-mono text-[11px]">{b.format}</td>
                <td className="py-1.5 pr-3 font-mono text-[11px]">{b.version ?? '-'}</td>
                <td className="py-1.5 pr-3 text-right tabular-nums">
                  {formatBytes(b.file_size)}
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
