import { Loader2 } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { registerAssemblyLanguage } from '@/utils/monacoAssembly'

export default function DisassemblyPanel({
  functionName,
  disassembly,
  loading,
}: {
  functionName: string
  disassembly: string | null
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Disassembling {functionName}…</span>
        </div>
      </div>
    )
  }

  if (!disassembly) {
    return (
      <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
        No disassembly available.
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-border px-4 py-1.5 text-xs text-muted-foreground">
        Disassembly of <span className="font-mono text-foreground">{functionName}</span>
      </div>
      <div className="flex-1">
        <Editor
          language="assembly"
          value={disassembly}
          theme="vs-dark"
          beforeMount={(monaco) => {
            registerAssemblyLanguage(monaco)
          }}
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
      </div>
    </div>
  )
}
