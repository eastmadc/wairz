import { AlertTriangle } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useExplorerStore } from '@/stores/explorerStore'
import type { TreeNode } from '@/stores/explorerStore'
import { getMonacoLanguage } from '@/utils/fileIcons'
import { registerAssemblyLanguage } from '@/utils/monacoAssembly'
import { registerShellLanguage } from '@/utils/monacoShell'
import type { FileContent, FileInfo } from '@/types'
import FileInfoPanel from './FileInfoPanel'

export default function TextTabs({
  selectedNode,
  fileContent,
  fileInfo,
  infoLoading,
}: {
  selectedNode: TreeNode | null
  selectedPath: string
  fileContent: FileContent
  fileInfo: FileInfo | null
  infoLoading: boolean
}) {
  const pendingLine = useExplorerStore((s) => s.pendingLine)
  const clearPendingLine = useExplorerStore((s) => s.clearPendingLine)

  return (
    <Tabs defaultValue="content" className="flex flex-1 flex-col overflow-hidden">
      <TabsList className="mx-4 mt-2 w-fit">
        <TabsTrigger value="content">Content</TabsTrigger>
        <TabsTrigger value="info">Info</TabsTrigger>
      </TabsList>

      <TabsContent value="content" className="flex-1 overflow-hidden mt-0 p-0">
        <div className="flex h-full flex-col">
          {fileContent.truncated && (
            <div className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              File content truncated. Only a portion of the file is shown.
            </div>
          )}
          <div className="flex-1">
            <Editor
              language={getMonacoLanguage(selectedNode?.name ?? '', fileContent.content)}
              value={fileContent.content}
              theme="vs-dark"
              beforeMount={(monaco) => {
                registerAssemblyLanguage(monaco)
                registerShellLanguage(monaco)
              }}
              onMount={(editor) => {
                if (pendingLine && pendingLine > 0) {
                  setTimeout(() => {
                    editor.revealLineInCenter(pendingLine)
                    editor.setPosition({ lineNumber: pendingLine, column: 1 })
                    editor.deltaDecorations([], [{
                      range: { startLineNumber: pendingLine, startColumn: 1, endLineNumber: pendingLine, endColumn: 1 },
                      options: {
                        isWholeLine: true,
                        className: 'bg-yellow-500/20',
                        glyphMarginClassName: 'bg-yellow-500',
                      },
                    }])
                    clearPendingLine()
                  }, 100)
                }
              }}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 13,
                lineNumbers: 'on',
                wordWrap: 'on',
                renderLineHighlight: 'none',
                contextmenu: false,
                automaticLayout: true,
              }}
            />
          </div>
        </div>
      </TabsContent>

      <TabsContent value="info" className="flex-1 overflow-auto mt-0 p-4">
        <FileInfoPanel fileInfo={fileInfo} infoLoading={infoLoading} />
      </TabsContent>
    </Tabs>
  )
}
