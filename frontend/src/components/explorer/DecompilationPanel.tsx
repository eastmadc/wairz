import { useState, useEffect, useCallback } from 'react'
import { Loader2, Copy, Check } from 'lucide-react'
import Editor from '@monaco-editor/react'

export default function DecompilationPanel({
  functionName,
  binaryPath,
  decompilation,
  loading,
  cleanedCode,
  cleanedCodeChecked,
}: {
  functionName: string
  binaryPath: string
  decompilation: string | null
  loading: boolean
  cleanedCode: string | null
  cleanedCodeChecked: boolean
}) {
  const [decompileView, setDecompileView] = useState<'raw' | 'cleaned'>('raw')
  const [copied, setCopied] = useState(false)

  // Reset view to raw when function changes
  useEffect(() => {
    setDecompileView('raw')
  }, [functionName])

  const promptText = `Please clean up the decompiled code for function ${functionName} in ${binaryPath} — rename variables, add comments, and annotate security-relevant patterns. Then save it using the save_code_cleanup tool.`

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(promptText).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [promptText])

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Decompiling {functionName}... (this may take 30-120s on first call)</span>
        </div>
      </div>
    )
  }

  if (!decompilation) {
    return (
      <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
        Decompilation unavailable.
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border px-4 py-1.5">
        <span className="text-xs text-muted-foreground">
          Decompilation of <span className="font-mono text-foreground">{functionName}</span>
        </span>
        <div className="ml-auto flex items-center rounded-md border border-border text-xs">
          <button
            onClick={() => setDecompileView('raw')}
            className={`px-2.5 py-1 rounded-l-md transition-colors ${
              decompileView === 'raw'
                ? 'bg-accent text-accent-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Raw
          </button>
          <button
            onClick={() => setDecompileView('cleaned')}
            className={`px-2.5 py-1 rounded-r-md border-l border-border transition-colors ${
              decompileView === 'cleaned'
                ? 'bg-accent text-accent-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Cleaned
          </button>
        </div>
      </div>

      <div className="flex-1">
        {decompileView === 'raw' ? (
          <Editor
            language="c"
            value={decompilation}
            theme="vs-dark"
            options={{
              readOnly: true,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              fontSize: 13,
              lineNumbers: 'on',
              wordWrap: 'off',
              renderLineHighlight: 'none',
              contextmenu: false,
              automaticLayout: true,
            }}
          />
        ) : cleanedCode ? (
          <Editor
            language="c"
            value={cleanedCode}
            theme="vs-dark"
            options={{
              readOnly: true,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              fontSize: 13,
              lineNumbers: 'on',
              wordWrap: 'off',
              renderLineHighlight: 'none',
              contextmenu: false,
              automaticLayout: true,
            }}
          />
        ) : !cleanedCodeChecked ? (
          <div className="flex flex-1 items-center justify-center h-full">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center h-full">
            <div className="max-w-lg space-y-4 text-center px-4">
              <p className="text-sm text-muted-foreground">
                No AI-cleaned version available yet.
              </p>
              <div className="rounded-md border border-border bg-muted/30 p-4 text-left">
                <p className="mb-2 text-xs text-muted-foreground">
                  Ask your AI assistant to clean up this function. Copy the prompt below:
                </p>
                <div className="relative">
                  <pre className="whitespace-pre-wrap rounded bg-background p-3 text-xs font-mono text-foreground">
                    {promptText}
                  </pre>
                  <button
                    onClick={handleCopy}
                    className="absolute right-2 top-2 rounded p-1 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                    title="Copy to clipboard"
                  >
                    {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
