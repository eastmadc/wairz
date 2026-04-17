import { Badge } from '@/components/ui/badge'
import { Loader2 } from 'lucide-react'
import type { HardwareFirmwareBlob, FirmwareCveMatch } from '@/api/hardwareFirmware'
import { displayPath } from './BlobTable'

interface BlobDetailProps {
  blob: HardwareFirmwareBlob | null
  cves: FirmwareCveMatch[]
  loading: boolean
}

// Exhaustive severity -> color map per CLAUDE.md rule 9.
const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

export default function BlobDetail({ blob, cves, loading }: BlobDetailProps) {
  if (!blob) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
        Select a blob to see details.
      </div>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-border p-4">
      <div>
        <p
          className="break-all font-mono text-xs text-foreground"
          title={blob.blob_path}
        >
          {displayPath(blob.blob_path)}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Badge variant="outline" className="text-[10px]">{blob.category}</Badge>
          <Badge variant="outline" className="text-[10px]">{blob.vendor ?? 'unknown'}</Badge>
          <Badge variant="outline" className="text-[10px] font-mono">{blob.format}</Badge>
          {blob.version && (
            <Badge variant="outline" className="text-[10px] font-mono">v{blob.version}</Badge>
          )}
          <Badge
            variant="outline"
            className={`text-[10px] ${
              blob.signed === 'signed'
                ? 'border-green-500/50 text-green-600 dark:text-green-400'
                : blob.signed === 'unsigned'
                  ? 'border-red-500/50 text-red-600 dark:text-red-400'
                  : blob.signed === 'weakly_signed'
                    ? 'border-orange-500/50 text-orange-600 dark:text-orange-400'
                    : 'border-gray-500/50 text-gray-500'
            }`}
          >
            {blob.signed}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        <span className="text-muted-foreground">SHA-256:</span>
        <span className="break-all font-mono text-[10px]">{blob.blob_sha256}</span>
        <span className="text-muted-foreground">Size:</span>
        <span className="font-mono tabular-nums">{blob.file_size.toLocaleString()} bytes</span>
        {blob.partition && (
          <>
            <span className="text-muted-foreground">Partition:</span>
            <span className="font-mono">{blob.partition}</span>
          </>
        )}
        {blob.chipset_target && (
          <>
            <span className="text-muted-foreground">Chipset:</span>
            <span className="font-mono">{blob.chipset_target}</span>
          </>
        )}
        {blob.signature_algorithm && (
          <>
            <span className="text-muted-foreground">Sig. algorithm:</span>
            <span className="font-mono">{blob.signature_algorithm}</span>
          </>
        )}
        {blob.cert_subject && (
          <>
            <span className="text-muted-foreground">Cert subject:</span>
            <span className="break-all font-mono text-[10px]">{blob.cert_subject}</span>
          </>
        )}
        <span className="text-muted-foreground">Detection source:</span>
        <span className="font-mono">{blob.detection_source}</span>
        <span className="text-muted-foreground">Confidence:</span>
        <span>{blob.detection_confidence}</span>
      </div>

      {blob.driver_references && blob.driver_references.length > 0 && (
        <div className="border-t border-border/50 pt-3">
          <p className="mb-1 text-xs font-medium text-muted-foreground">Driver references</p>
          <ul className="space-y-0.5">
            {blob.driver_references.slice(0, 20).map((ref) => (
              <li key={ref} className="break-all font-mono text-[11px]">
                {ref}
              </li>
            ))}
            {blob.driver_references.length > 20 && (
              <li className="text-[10px] italic text-muted-foreground">
                +{blob.driver_references.length - 20} more
              </li>
            )}
          </ul>
        </div>
      )}

      {blob.metadata && Object.keys(blob.metadata).length > 0 && (
        <div className="border-t border-border/50 pt-3">
          <p className="mb-1 text-xs font-medium text-muted-foreground">Parser metadata</p>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-2 text-[10px] leading-tight font-mono">
            {JSON.stringify(blob.metadata, null, 2)}
          </pre>
        </div>
      )}

      <div className="border-t border-border/50 pt-3">
        <div className="mb-1 flex items-center justify-between">
          <p className="text-xs font-medium text-muted-foreground">CVE matches</p>
          {loading && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
        </div>
        {!loading && cves.length === 0 && (
          <p className="text-[11px] italic text-muted-foreground">
            No CVE matches for this blob. Run the Tier 3 matcher from the header.
          </p>
        )}
        {cves.length > 0 && (
          <ul className="space-y-2">
            {cves.map((v) => (
              <li
                key={v.id}
                className="rounded-md border border-border bg-muted/40 p-2 text-[11px]"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono font-semibold">{v.cve_id}</span>
                  <Badge
                    className={`text-[10px] ${
                      SEVERITY_STYLE[v.severity] ?? 'bg-gray-500 text-white'
                    }`}
                  >
                    {v.severity}
                  </Badge>
                  {v.cvss_score != null && (
                    <Badge variant="outline" className="text-[10px]">
                      CVSS {v.cvss_score}
                    </Badge>
                  )}
                  {v.match_tier && (
                    <Badge variant="outline" className="text-[10px]">
                      {v.match_tier}
                    </Badge>
                  )}
                  {v.match_confidence && (
                    <Badge variant="outline" className="text-[10px]">
                      {v.match_confidence}
                    </Badge>
                  )}
                </div>
                {v.description && (
                  <p className="mt-1 text-muted-foreground">{v.description}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
