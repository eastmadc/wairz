import { useState } from 'react'
import { Loader2, CheckCircle2, XCircle, Copy, Check, ChevronDown, ChevronUp, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { ToolRunResponse } from '@/api/tools'

interface ToolOutputProps {
  result: ToolRunResponse | null
  loading: boolean
  error: string | null
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

export default function ToolOutput({ result, loading, error }: ToolOutputProps) {
  const [copied, setCopied] = useState(false)
  const [collapsed, setCollapsed] = useState(false)

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text)
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
            collapsed ? 'max-h-24' : 'max-h-[600px]'
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
