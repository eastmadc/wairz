import { Download, Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  buildBlobDownloadUrl,
  type FirmwareCveMatch,
  type HardwareFirmwareBlob,
} from '@/api/hardwareFirmware'
import { displayPath } from './BlobTable'

interface BlobDetailProps {
  blob: HardwareFirmwareBlob | null
  cves: FirmwareCveMatch[]
  loading: boolean
  projectId: string
  firmwareId: string | null
  onDriverClick?: (driverPath: string) => void
}

// Exhaustive severity -> color map per CLAUDE.md rule 9.
const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

// Keys promoted to structured fields above the JSON escape hatch.  If
// the parser populated any of these we render them inline so the user
// doesn't have to expand the raw JSON to read common values.
const PROMOTED_METADATA_KEYS = [
  'build_date',
  'built_on',
  'release',
  'git_hash',
  'commit',
  'toolchain',
  'architecture',
] as const

function promotedEntries(meta: Record<string, unknown>): [string, unknown][] {
  const out: [string, unknown][] = []
  for (const k of PROMOTED_METADATA_KEYS) {
    if (k in meta && meta[k] !== null && meta[k] !== undefined && meta[k] !== '') {
      out.push([k, meta[k]])
    }
  }
  return out
}

function scalarDisplay(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return JSON.stringify(v)
}

export default function BlobDetail({
  blob,
  cves,
  loading,
  projectId,
  firmwareId,
  onDriverClick,
}: BlobDetailProps) {
  if (!blob) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
        Select a blob to see details.
      </div>
    )
  }

  const downloadUrl = buildBlobDownloadUrl(projectId, blob.id, firmwareId)
  const filename = displayPath(blob.blob_path).split('/').pop() || 'blob.bin'
  const metaEntries = blob.metadata ? Object.entries(blob.metadata) : []
  const promoted = blob.metadata ? promotedEntries(blob.metadata) : []

  return (
    <div className="space-y-3 rounded-lg border border-border p-4">
      <div>
        <div className="flex items-start justify-between gap-2">
          <p
            className="flex-1 break-all font-mono text-xs text-foreground"
            title={blob.blob_path}
          >
            {displayPath(blob.blob_path)}
          </p>
          <Button
            variant="outline"
            size="sm"
            asChild
            title={`Download ${filename} (${blob.file_size.toLocaleString()} bytes)`}
          >
            <a href={downloadUrl} download={filename}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Download
            </a>
          </Button>
        </div>
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
        {promoted.map(([k, v]) => (
          <div key={k} className="contents">
            <span className="text-muted-foreground">{k.replace(/_/g, ' ')}:</span>
            <span className="break-all font-mono text-[10px]">{scalarDisplay(v)}</span>
          </div>
        ))}
      </div>

      {blob.driver_references && blob.driver_references.length > 0 && (
        <div className="border-t border-border/50 pt-3">
          <p className="mb-1 text-xs font-medium text-muted-foreground">Driver references</p>
          <ul className="space-y-0.5">
            {blob.driver_references.slice(0, 20).map((ref) =>
              onDriverClick ? (
                <li key={ref}>
                  <button
                    type="button"
                    onClick={() => onDriverClick(ref)}
                    className="break-all font-mono text-[11px] text-blue-500 hover:underline"
                    title="Click to see blobs referenced by this driver"
                  >
                    {ref}
                  </button>
                </li>
              ) : (
                <li key={ref} className="break-all font-mono text-[11px]">
                  {ref}
                </li>
              ),
            )}
            {blob.driver_references.length > 20 && (
              <li className="text-[10px] italic text-muted-foreground">
                +{blob.driver_references.length - 20} more
              </li>
            )}
          </ul>
        </div>
      )}

      {(() => {
        const kv = (blob.metadata as { known_vulnerabilities?: Array<{
          cve_id: string
          severity: string
          subcomponent?: string
          confidence?: string
          rationale?: string
          reference?: string
          cwe?: string
          source?: string
        }> } | null)?.known_vulnerabilities
        if (!kv || kv.length === 0) return null
        return (
          <div className="border-t border-border/50 pt-3">
            <p className="mb-1 text-xs font-medium text-red-600 dark:text-red-400">
              Known vulnerabilities ({kv.length}) — parser-detected
            </p>
            <ul className="space-y-2">
              {kv.map((v) => (
                <li
                  key={v.cve_id}
                  className="rounded-md border border-red-500/40 bg-red-500/5 p-2 text-[11px]"
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
                    {v.cwe && (
                      <Badge variant="outline" className="text-[10px]">{v.cwe}</Badge>
                    )}
                    {v.subcomponent && (
                      <Badge variant="outline" className="text-[10px]">{v.subcomponent}</Badge>
                    )}
                    {v.confidence && (
                      <Badge variant="outline" className="text-[10px]">
                        confidence: {v.confidence}
                      </Badge>
                    )}
                  </div>
                  {v.rationale && (
                    <p className="mt-1 text-muted-foreground">{v.rationale}</p>
                  )}
                  {v.reference && (
                    <a
                      href={v.reference}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-1 inline-block break-all text-[10px] text-blue-500 hover:underline"
                    >
                      {v.reference}
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )
      })()}

      {metaEntries.length > 0 && (
        <details className="border-t border-border/50 pt-3">
          <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
            Parser metadata ({metaEntries.length} {metaEntries.length === 1 ? 'key' : 'keys'})
          </summary>
          <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-muted p-2 text-[10px] leading-tight font-mono">
            {JSON.stringify(blob.metadata, null, 2)}
          </pre>
        </details>
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
