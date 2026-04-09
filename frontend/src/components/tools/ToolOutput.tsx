import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Loader2, CheckCircle2, XCircle, Copy, Check, ChevronDown, ChevronUp, Terminal, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { exportSbom } from '@/api/sbom'
import { useProjectStore } from '@/stores/projectStore'
import type { ToolRunResponse } from '@/api/tools'

interface ToolOutputProps {
  result: ToolRunResponse | null
  loading: boolean
  error: string | null
  /** The input parameters that were passed to the tool */
  toolInput?: Record<string, unknown>
}

function tryFormatJson(text: string): string {
  const trimmed = text.trim()
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      // not valid JSON, return as-is
    }
  }
  return text
}

export default function ToolOutput({ result, loading, error, toolInput }: ToolOutputProps) {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const [copied, setCopied] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [downloading, setDownloading] = useState(false)

  // Download handler for export tools
  const handleDownload = async (format: string) => {
    if (!projectId) return
    setDownloading(true)
    try {
      const fwId = selectedFirmwareId || undefined
      const blob = await exportSbom(projectId, format, fwId)
      const filenames: Record<string, string> = {
        'cyclonedx-json': `sbom-${projectId}.cdx.json`,
        'spdx-json': `sbom-${projectId}.spdx.json`,
        'cyclonedx-vex-json': `vex-${projectId}.cdx.json`,
      }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filenames[format] || `sbom-${projectId}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silently fail — user can copy the output instead
    } finally {
      setDownloading(false)
    }
  }

  const handleCopy = (text: string) => {
    const fallback = () => {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.focus()
      ta.select()
      try { document.execCommand('copy') } catch { /* ignore */ }
      document.body.removeChild(ta)
    }

    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).catch(fallback)
    } else {
      fallback()
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Loading state
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin mb-3" />
        <p className="text-sm">Running tool...</p>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4">
        <div className="flex items-center gap-2 mb-2">
          <XCircle className="h-4 w-4 text-destructive" />
          <span className="text-sm font-medium text-destructive">Error</span>
        </div>
        <p className="text-sm text-destructive/90">{error}</p>
        <p className="text-xs text-muted-foreground mt-2">
          Check that the backend is running and try again.
        </p>
      </div>
    )
  }

  // No result yet
  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <Terminal className="h-8 w-8 mb-3 opacity-30" />
        <p className="text-sm">Select a tool and run it to see results</p>
      </div>
    )
  }

  const formattedOutput = tryFormatJson(result.output)
  const lineCount = formattedOutput.split('\n').length
  const isLong = lineCount > 50

  // Determine if this is an export tool that supports direct download
  const isExportTool = result.tool === 'export_sbom'
  const exportFormat = isExportTool
    ? (toolInput?.format as string) || 'cyclonedx-json'
    : null

  return (
    <div className="space-y-3">
      {/* Status header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {result.success ? (
            <>
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              <span className="text-sm font-medium text-green-500">Success</span>
            </>
          ) : (
            <>
              <XCircle className="h-4 w-4 text-destructive" />
              <span className="text-sm font-medium text-destructive">Failed</span>
            </>
          )}
          <span className="text-xs text-muted-foreground">
            {result.tool}
          </span>
        </div>
        <div className="flex items-center gap-1">
          {isExportTool && exportFormat && result.success && (
            <Button
              variant="ghost"
              size="xs"
              onClick={() => handleDownload(exportFormat)}
              disabled={downloading}
              className="text-muted-foreground"
            >
              {downloading ? (
                <Loader2 className="mr-1 h-3 w-3 animate-spin" />
              ) : (
                <Download className="mr-1 h-3 w-3" />
              )}
              Download
            </Button>
          )}
          {isLong && (
            <Button
              variant="ghost"
              size="xs"
              onClick={() => setCollapsed((prev) => !prev)}
              className="text-muted-foreground"
            >
              {collapsed ? (
                <ChevronDown className="mr-1 h-3 w-3" />
              ) : (
                <ChevronUp className="mr-1 h-3 w-3" />
              )}
              {collapsed ? 'Expand' : 'Collapse'}
            </Button>
          )}
          <Button
            variant="ghost"
            size="xs"
            onClick={() => handleCopy(result.output)}
            className="text-muted-foreground"
          >
            {copied ? (
              <Check className="mr-1 h-3 w-3" />
            ) : (
              <Copy className="mr-1 h-3 w-3" />
            )}
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      {/* Output */}
      <div className="rounded-md border bg-muted/30 overflow-hidden">
        <pre
          className={`p-4 text-xs font-mono whitespace-pre-wrap overflow-auto ${
            collapsed ? 'max-h-24' : ''
          }`}
        >
          {formattedOutput}
        </pre>
      </div>

      {isLong && (
        <p className="text-xs text-muted-foreground text-right">
          {lineCount} lines
        </p>
      )}
    </div>
  )
}
