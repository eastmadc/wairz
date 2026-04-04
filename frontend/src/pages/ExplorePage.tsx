import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { FolderTree, PanelLeftClose, PanelLeftOpen, TerminalSquare, Cpu } from 'lucide-react'
import { useExplorerStore } from '@/stores/explorerStore'
import { useProjectStore } from '@/stores/projectStore'
import { listFirmware } from '@/api/firmware'
import type { FirmwareDetail } from '@/types'
import FileTree from '@/components/explorer/FileTree'
import FileViewer from '@/components/explorer/FileViewer'
import UefiModules from '@/components/explorer/UefiModules'
import TerminalPanel from '@/components/explorer/TerminalPanel'
import FirmwareSelector from '@/components/projects/FirmwareSelector'

export default function ExplorePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const resetExplorer = useExplorerStore((s) => s.reset)
  const loadRootDirectory = useExplorerStore((s) => s.loadRootDirectory)
  const loadDocuments = useExplorerStore((s) => s.loadDocuments)
  const navigateToPath = useExplorerStore((s) => s.navigateToPath)
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [treeOpen, setTreeOpen] = useState(true)
  const [viewMode, setViewMode] = useState<'files' | 'uefi'>('files')
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [terminalHeight, setTerminalHeight] = useState(250)
  const draggingRef = useRef(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (projectId) {
      loadDocuments(projectId)
      listFirmware(projectId).then(setFirmwareList)
    }
    return () => {
      resetExplorer()
    }
  }, [projectId, loadDocuments, resetExplorer])

  // Reload file tree when firmware version changes
  useEffect(() => {
    if (projectId && selectedFirmwareId) {
      loadRootDirectory(projectId)
    }
  }, [projectId, selectedFirmwareId, loadRootDirectory])

  // Handle ?path= and ?line= query parameters: expand tree, select file, scroll to line
  const setPendingLine = useExplorerStore((s) => s.setPendingLine)
  useEffect(() => {
    const pathParam = searchParams.get('path')
    const lineParam = searchParams.get('line')
    if (!projectId) return
    if (pathParam) {
      navigateToPath(projectId, pathParam)
      if (lineParam) {
        setPendingLine(parseInt(lineParam, 10) || null)
      }
      // Clear query params so they don't re-trigger on re-renders
      setSearchParams({}, { replace: true })
    }
  }, [projectId, searchParams, setSearchParams, navigateToPath, setPendingLine])

  // Vertical resize drag handler for terminal panel
  const handleDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    draggingRef.current = true

    const startY = e.clientY
    const startHeight = terminalHeight

    const onMouseMove = (moveEvent: MouseEvent) => {
      if (!draggingRef.current) return
      const delta = startY - moveEvent.clientY
      const newHeight = Math.min(600, Math.max(100, startHeight + delta))
      setTerminalHeight(newHeight)
    }

    const onMouseUp = () => {
      draggingRef.current = false
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [terminalHeight])

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Left panel: file tree */}
      {treeOpen && (
        <div className="flex w-72 shrink-0 flex-col border-r border-border">
          <div className="flex flex-col border-b border-border">
            <div className="flex items-center gap-2 px-4 py-2">
              <FolderTree className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Files</span>
              <button
                onClick={() => setTreeOpen(false)}
                className="ml-auto rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                title="Collapse panel"
              >
                <PanelLeftClose className="h-4 w-4" />
              </button>
            </div>
            {projectId && firmwareList.filter((fw) => fw.extracted_path).length > 1 && (
              <div className="px-4 pb-2">
                <FirmwareSelector projectId={projectId} firmwareList={firmwareList} />
              </div>
            )}
          </div>
          <FileTree />
        </div>
      )}

      {/* Center panel: file viewer + terminal */}
      <div ref={containerRef} className="relative flex min-w-0 flex-1 flex-col">
        {!treeOpen && (
          <button
            onClick={() => setTreeOpen(true)}
            className="absolute left-2 top-2 z-10 rounded border border-border bg-background p-1 text-muted-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            title="Show file tree"
          >
            <PanelLeftOpen className="h-4 w-4" />
          </button>
        )}

        {/* View mode tabs */}
        <div className="flex items-center gap-1 border-b border-border px-2">
          <button
            onClick={() => setViewMode('files')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'files'
                ? 'border-b-2 border-primary text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <FolderTree className="h-3.5 w-3.5" />
            Files
          </button>
          <button
            onClick={() => setViewMode('uefi')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'uefi'
                ? 'border-b-2 border-primary text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            UEFI Modules
          </button>
        </div>

        {/* Content area (takes remaining space) */}
        <div className="min-h-0 flex-1">
          {viewMode === 'files' ? (
            <FileViewer />
          ) : projectId ? (
            <UefiModules projectId={projectId} />
          ) : null}
        </div>

        {/* Drag handle + terminal panel */}
        {terminalOpen && (
          <>
            <div
              onMouseDown={handleDragStart}
              className="h-1 shrink-0 cursor-row-resize border-t border-border bg-background hover:bg-accent"
            />
            <div style={{ height: terminalHeight }} className="shrink-0">
              <TerminalPanel
                projectId={projectId}
                isOpen={terminalOpen}
                onClose={() => setTerminalOpen(false)}
              />
            </div>
          </>
        )}

        {/* Terminal toggle — bottom-left */}
        {!terminalOpen && (
          <button
            onClick={() => setTerminalOpen(true)}
            className="absolute bottom-4 left-4 z-10 flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium text-muted-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            title="Open terminal"
          >
            <TerminalSquare className="h-4 w-4" />
            Terminal
          </button>
        )}
      </div>
    </div>
  )
}
