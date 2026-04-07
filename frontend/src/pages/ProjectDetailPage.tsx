import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Trash2,
  FolderSearch,
  ShieldAlert,
  Cpu,
  HardDrive,
  Hash,
  FileText,
  Loader2,
  AlertCircle,
  GitCompareArrows,
  Plus,
  Tag,
  Download,
  Upload,
  Pencil,
  Check,
  X,
  Shield,
  ChevronDown,
  Terminal,
  Microchip,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { listFirmware, deleteFirmware, updateFirmware, uploadRootfs } from '@/api/firmware'
import { runSecurityAudit, runYaraScan, type SecurityAuditResult, type YaraScanResult } from '@/api/findings'
import type { FirmwareDetail } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatFileSize, formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import FirmwareMetadataCard from '@/components/projects/FirmwareMetadataCard'
import DocumentsCard from '@/components/projects/DocumentsCard'
import McpConnectionCard from '@/components/projects/McpConnectionCard'
import { exportProject } from '@/api/exportImport'
import { useEventStream } from '@/hooks/useEventStream'

const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  ready: 'default',
  unpacking: 'secondary',
  error: 'destructive',
  created: 'outline',
}

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const {
    currentProject: project,
    loading,
    unpacking,
    fetchProject,
    removeProject,
    unpackFirmware,
    clearCurrentProject,
  } = useProjectStore()

  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [showUpload, setShowUpload] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [editingVersionLabel, setEditingVersionLabel] = useState<string | null>(null)
  const [versionLabelDraft, setVersionLabelDraft] = useState('')
  const [uploadingRootfs, setUploadingRootfs] = useState<string | null>(null)
  const [rootfsError, setRootfsError] = useState<string | null>(null)
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null)
  const [yaraScanning, setYaraScanning] = useState(false)
  const [yaraResult, setYaraResult] = useState<YaraScanResult | null>(null)
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set())
  const versionInputRef = useRef<HTMLInputElement>(null)
  const rootfsInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (projectId) fetchProject(projectId)
    return () => clearCurrentProject()
  }, [projectId, fetchProject, clearCurrentProject])

  // Fetch full firmware list for details (includes unpack_log, extracted_path)
  // Depend on project.id + status (not full object) to avoid redundant fetches on every poll
  useEffect(() => {
    if (projectId && project) {
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    }
  }, [projectId, project?.id, project?.status])

  // SSE: listen for unpacking events and refresh on status changes
  const isUnpacking = project?.status === 'unpacking'
  const { lastEvent: unpackEvent } = useEventStream<{ type: string; status: string }>(
    projectId,
    { types: ['unpacking'], enabled: isUnpacking },
  )

  const refreshProject = useCallback(() => {
    if (!projectId) return
    fetchProject(projectId)
    listFirmware(projectId).then(setFirmwareList).catch(() => {})
  }, [projectId, fetchProject])

  // When an SSE event arrives, refresh data
  useEffect(() => {
    if (unpackEvent) refreshProject()
  }, [unpackEvent, refreshProject])

  // Fallback poll while unpacking (in case SSE is unavailable)
  useEffect(() => {
    if (!projectId || !isUnpacking) return
    const interval = setInterval(refreshProject, 5000)
    return () => clearInterval(interval)
  }, [projectId, isUnpacking, refreshProject])

  if (loading || !project) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading project...</span>
      </div>
    )
  }

  const firmware = project.firmware ?? []
  const status = project.status
  const hasUnpacked = firmwareList.some((fw) => fw.extracted_path)
  const unpackedCount = firmwareList.filter((fw) => fw.extracted_path).length

  const handleDelete = async () => {
    if (window.confirm('Delete this project and all its data? This cannot be undone.')) {
      await removeProject(project.id)
      navigate('/projects')
    }
  }

  const handleUnpack = async (firmwareId: string) => {
    if (projectId) {
      try {
        await unpackFirmware(projectId, firmwareId)
        // Refresh firmware list
        listFirmware(projectId).then(setFirmwareList).catch(() => {})
      } catch {
        // error shown via store
      }
    }
  }

  const handleDeleteFirmware = async (firmwareId: string) => {
    if (!projectId) return
    if (!window.confirm('Delete this firmware version? This cannot be undone.')) return
    try {
      await deleteFirmware(projectId, firmwareId)
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    } catch {
      // error handled by caller
    }
  }

  const handleExport = async () => {
    if (!projectId) return
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportProject(projectId)
      const safeName = project.name.replace(/\s+/g, '_').replace(/\//g, '_')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeName}.wairz`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      const msg = err instanceof Error
        ? err.message
        : 'Export failed'
      setExportError(msg)
    } finally {
      setExporting(false)
    }
  }

  const startEditingVersionLabel = (fwId: string, current: string | null) => {
    setEditingVersionLabel(fwId)
    setVersionLabelDraft(current ?? '')
    setTimeout(() => versionInputRef.current?.focus(), 0)
  }

  const saveVersionLabel = async (fwId: string) => {
    if (!projectId) return
    const label = versionLabelDraft.trim() || null
    try {
      await updateFirmware(projectId, fwId, { version_label: label })
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    } catch {
      // error handled by caller
    }
    setEditingVersionLabel(null)
  }

  const handleRootfsUpload = async (firmwareId: string, file: File) => {
    if (!projectId) return
    setUploadingRootfs(firmwareId)
    setRootfsError(null)
    try {
      await uploadRootfs(projectId, firmwareId, file)
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    } catch (e) {
      setRootfsError(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setUploadingRootfs(null)
    }
  }

  const handleUploadComplete = () => {
    setShowUpload(false)
    if (projectId) {
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{project.name}</h1>
            <Badge
              variant={STATUS_VARIANT[status] ?? 'outline'}
              className={status === 'unpacking' ? 'animate-pulse' : ''}
            >
              {status}
            </Badge>
          </div>
          {project.description && (
            <p className="text-sm text-muted-foreground">{project.description}</p>
          )}
          <p className="text-xs text-muted-foreground">Created {formatDate(project.created_at)}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/projects">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Link>
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
            {exporting ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Download className="mr-2 h-4 w-4" />
            )}
            Export
          </Button>
          <Button variant="destructive" size="sm" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      {exportError && (
        <div className="rounded bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
          Export failed: {exportError}
        </div>
      )}

      {/* Firmware cards */}
      {firmware.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Firmware ({firmware.length})
            </h2>
            <Button size="sm" variant="outline" onClick={() => setShowUpload(!showUpload)}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Upload Version
            </Button>
          </div>

          {firmware.map((fw) => {
            const fwDetail = firmwareList.find((f) => f.id === fw.id)
            const isUnpacked = fwDetail?.extracted_path
            const hasError = fwDetail?.unpack_log && !isUnpacked && (status as string) === 'error'

            return (
              <Card key={fw.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      {fw.original_filename}
                      {editingVersionLabel === fw.id ? (
                        <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                          <Input
                            ref={versionInputRef}
                            value={versionLabelDraft}
                            onChange={(e) => setVersionLabelDraft(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') saveVersionLabel(fw.id)
                              if (e.key === 'Escape') setEditingVersionLabel(null)
                            }}
                            placeholder="e.g. v1.0.3"
                            className="h-6 w-32 text-xs"
                          />
                          <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => saveVersionLabel(fw.id)}>
                            <Check className="h-3 w-3" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => setEditingVersionLabel(null)}>
                            <X className="h-3 w-3" />
                          </Button>
                        </span>
                      ) : fw.version_label ? (
                        <Badge
                          variant="secondary"
                          className="text-xs cursor-pointer hover:bg-secondary/80"
                          onClick={() => startEditingVersionLabel(fw.id, fw.version_label ?? null)}
                        >
                          <Tag className="mr-1 h-3 w-3" />
                          {fw.version_label}
                          <Pencil className="ml-1 h-2.5 w-2.5 opacity-50" />
                        </Badge>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-5 px-1.5 text-xs text-muted-foreground"
                          onClick={() => startEditingVersionLabel(fw.id, null)}
                        >
                          <Tag className="mr-1 h-3 w-3" />
                          Add version
                        </Button>
                      )}
                      {isUnpacked && (
                        <Badge variant="default" className="text-xs">unpacked</Badge>
                      )}
                      {fwDetail?.binary_info && (
                        <Badge variant="outline" className="text-xs">standalone binary</Badge>
                      )}
                    </CardTitle>
                    <div className="flex gap-1">
                      {!isUnpacked && !hasError && !unpacking && !fwDetail?.unpack_stage && status !== 'unpacking' && (
                        <Button size="sm" onClick={() => handleUnpack(fw.id)}>
                          Unpack
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => handleDeleteFirmware(fw.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">Size:</dt>
                      <dd className="font-medium">
                        {fw.file_size != null ? formatFileSize(fw.file_size) : 'N/A'}
                      </dd>
                    </div>
                    {fw.architecture && (
                      <div className="flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-muted-foreground" />
                        <dt className="text-muted-foreground">Architecture:</dt>
                        <dd className="font-medium">
                          {fw.architecture}
                          {fw.endianness ? ` (${fw.endianness})` : ''}
                        </dd>
                      </div>
                    )}
                    {(() => {
                      const osInfo = fw.os_info ? (() => { try { return JSON.parse(fw.os_info) } catch { return null } })() : null
                      const rtos = osInfo?.rtos
                      const hexMeta = osInfo?.hex_metadata
                      return (
                        <>
                          {rtos && (
                            <div className="flex items-center gap-2">
                              <Microchip className="h-4 w-4 text-muted-foreground" />
                              <dt className="text-muted-foreground">OS/RTOS:</dt>
                              <dd className="font-medium">
                                {rtos.name}
                                {rtos.version ? ` v${rtos.version}` : ''}
                                <Badge variant="outline" className="ml-2 text-[10px]">{rtos.confidence}</Badge>
                              </dd>
                            </div>
                          )}
                          {osInfo?.format === 'intel_hex' && hexMeta && (
                            <div className="flex items-center gap-2">
                              <Cpu className="h-4 w-4 text-muted-foreground" />
                              <dt className="text-muted-foreground">Memory:</dt>
                              <dd className="font-mono text-xs">
                                {hexMeta.regions?.map((r: { start: number; size: number }, i: number) => (
                                  <span key={i} className="mr-2">
                                    0x{r.start.toString(16).toUpperCase().padStart(8, '0')} ({(r.size / 1024).toFixed(0)} KB)
                                  </span>
                                ))}
                                {hexMeta.entry_point != null && (
                                  <span className="text-muted-foreground ml-1">entry: 0x{hexMeta.entry_point.toString(16).toUpperCase().padStart(8, '0')}</span>
                                )}
                              </dd>
                            </div>
                          )}
                          {osInfo?.companion_components?.length > 0 && (
                            <div className="flex items-center gap-2 col-span-2">
                              <Microchip className="h-4 w-4 text-muted-foreground" />
                              <dt className="text-muted-foreground">Components:</dt>
                              <dd className="text-xs">
                                {osInfo.companion_components.map((c: { name: string; version?: string }, i: number) => (
                                  <Badge key={i} variant="outline" className="mr-1 text-[10px]">
                                    {c.name}{c.version ? ` v${c.version}` : ''}
                                  </Badge>
                                ))}
                              </dd>
                            </div>
                          )}
                        </>
                      )
                    })()}
                    {fwDetail?.binary_info && (
                      <div className="flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-muted-foreground" />
                        <dt className="text-muted-foreground">Binary:</dt>
                        <dd className="font-medium">
                          {fwDetail.binary_info.format?.toUpperCase() ?? 'Unknown'}
                          {fwDetail.binary_info.bits ? ` ${fwDetail.binary_info.bits}-bit` : ''}
                          {' '}
                          {fwDetail.binary_info.is_static ? 'static' : 'dynamic'}
                          {fwDetail.binary_info.is_pie ? ', PIE' : ''}
                        </dd>
                      </div>
                    )}
                    {fwDetail?.binary_info && fwDetail.binary_info.dependencies.length > 0 && (
                      <div className="flex items-start gap-2 col-span-2">
                        <Cpu className="h-4 w-4 text-muted-foreground mt-0.5" />
                        <dt className="text-muted-foreground">Dependencies:</dt>
                        <dd className="font-mono text-xs">
                          {fwDetail.binary_info.dependencies.join(', ')}
                        </dd>
                      </div>
                    )}
                    <div className="flex items-center gap-2 col-span-2">
                      <Hash className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">SHA256:</dt>
                      <dd className="font-mono text-xs truncate">{fw.sha256}</dd>
                    </div>
                  </dl>

                  {status === 'unpacking' && fwDetail && !isUnpacked && fwDetail.unpack_stage && (
                    <div className="mt-3 rounded bg-muted/50 border p-3 space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          {fwDetail.unpack_stage}
                        </span>
                        {fwDetail.unpack_progress != null && (
                          <span className="text-muted-foreground text-xs">{fwDetail.unpack_progress}%</span>
                        )}
                      </div>
                      {fwDetail.unpack_progress != null && (
                        <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                          <div
                            className="h-full rounded-full bg-primary transition-all duration-500"
                            style={{ width: `${Math.min(fwDetail.unpack_progress, 100)}%` }}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {hasError && fwDetail?.unpack_log && (
                    <div className="mt-3 rounded bg-destructive/5 border border-destructive/20 p-3">
                      <div className="flex items-center gap-2 text-sm text-destructive mb-2">
                        <AlertCircle className="h-4 w-4" />
                        Unpacking Failed
                      </div>
                      <pre className="max-h-40 overflow-auto text-xs">{fwDetail.unpack_log}</pre>
                      <div className="flex gap-2 mt-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleUnpack(fw.id)}
                          disabled={unpacking}
                        >
                          {unpacking && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                          Retry
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => rootfsInputRef.current?.click()}
                          disabled={uploadingRootfs === fw.id}
                        >
                          {uploadingRootfs === fw.id ? (
                            <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Upload className="mr-2 h-3.5 w-3.5" />
                          )}
                          Upload Rootfs
                        </Button>
                        <input
                          ref={rootfsInputRef}
                          type="file"
                          accept=".tar,.tar.gz,.tgz,.zip"
                          className="hidden"
                          onChange={(e) => {
                            const file = e.target.files?.[0]
                            if (file) handleRootfsUpload(fw.id, file)
                            e.target.value = ''
                          }}
                        />
                      </div>
                      {rootfsError && uploadingRootfs === null && (
                        <p className="text-xs text-destructive mt-1">{rootfsError}</p>
                      )}
                    </div>
                  )}

                  {isUnpacked && fwDetail?.unpack_log && (
                    <div className="mt-3">
                      <button
                        type="button"
                        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                        onClick={() => setExpandedLogs((prev) => {
                          const next = new Set(prev)
                          if (next.has(fw.id)) next.delete(fw.id)
                          else next.add(fw.id)
                          return next
                        })}
                      >
                        <ChevronDown className={`h-3.5 w-3.5 transition-transform ${expandedLogs.has(fw.id) ? '' : '-rotate-90'}`} />
                        <Terminal className="h-3.5 w-3.5" />
                        Unpack Log
                      </button>
                      {expandedLogs.has(fw.id) && (
                        <pre className="mt-2 max-h-48 overflow-auto rounded bg-muted/50 border p-3 text-xs">
                          {fwDetail.unpack_log}
                        </pre>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Upload section */}
      {(showUpload || firmware.length === 0) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Upload Firmware</CardTitle>
          </CardHeader>
          <CardContent>
            <FirmwareUpload
              projectId={project.id}
              onComplete={handleUploadComplete}
              showVersionLabel
            />
          </CardContent>
        </Card>
      )}

      {/* Project documents */}
      <DocumentsCard projectId={project.id} />

      {/* Firmware metadata cards for unpacked firmware */}
      {firmwareList
        .filter((fw) => fw.extracted_path)
        .map((fw) => (
          <FirmwareMetadataCard key={fw.id} projectId={project.id} firmwareId={fw.id} />
        ))}

      {/* Action buttons when ready */}
      {hasUnpacked && (
        <>
          <div className="flex gap-3 flex-wrap">
            <Button asChild>
              <Link to={`/projects/${project.id}/explore`}>
                <FolderSearch className="mr-2 h-4 w-4" />
                Explore Files
              </Link>
            </Button>
            <Button variant="outline" asChild>
              <Link to={`/projects/${project.id}/findings`}>
                <ShieldAlert className="mr-2 h-4 w-4" />
                Findings
              </Link>
            </Button>
            <Button
              variant="outline"
              disabled={auditing}
              onClick={async () => {
                if (!project) return
                setAuditing(true)
                setAuditResult(null)
                try {
                  const result = await runSecurityAudit(project.id)
                  setAuditResult(result)
                } catch {
                  setAuditResult({ status: 'error', checks_run: 0, findings_created: 0, total_findings: 0, errors: ['Scan failed'] })
                } finally {
                  setAuditing(false)
                }
              }}
            >
              {auditing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Shield className="mr-2 h-4 w-4" />}
              {auditing ? 'Auditing...' : 'Security Audit'}
            </Button>
            <Button
              variant="outline"
              disabled={yaraScanning}
              onClick={async () => {
                if (!project) return
                setYaraScanning(true)
                setYaraResult(null)
                try {
                  const result = await runYaraScan(project.id)
                  setYaraResult(result)
                } catch {
                  setYaraResult({ status: 'error', rules_loaded: 0, files_scanned: 0, files_matched: 0, findings_created: 0, errors: ['YARA scan failed'] })
                } finally {
                  setYaraScanning(false)
                }
              }}
            >
              {yaraScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Shield className="mr-2 h-4 w-4" />}
              {yaraScanning ? 'Scanning...' : 'YARA Scan'}
            </Button>
            {unpackedCount >= 2 && (
              <Button variant="outline" asChild>
                <Link to={`/projects/${project.id}/compare`}>
                  <GitCompareArrows className="mr-2 h-4 w-4" />
                  Compare Versions
                </Link>
              </Button>
            )}
          </div>

          {auditResult && !auditing && (
            <Card>
              <CardContent className="py-3 px-4">
                <div className="flex items-center gap-3">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">
                    Security audit complete: <strong>{auditResult.findings_created}</strong> finding{auditResult.findings_created !== 1 ? 's' : ''} from {auditResult.checks_run} checks
                  </span>
                  {auditResult.findings_created > 0 && (
                    <Button variant="link" size="sm" className="h-auto p-0" asChild>
                      <Link to={`/projects/${project.id}/findings?source=security_audit`}>
                        View in Findings
                      </Link>
                    </Button>
                  )}
                  {auditResult.errors.length > 0 && (
                    <span className="text-xs text-destructive">
                      {auditResult.errors.length} error(s)
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {yaraResult && !yaraScanning && (
            <Card>
              <CardContent className="py-3 px-4">
                <div className="flex items-center gap-3">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">
                    YARA scan complete: <strong>{yaraResult.findings_created}</strong> finding{yaraResult.findings_created !== 1 ? 's' : ''} from {yaraResult.files_scanned} files ({yaraResult.rules_loaded} rules)
                  </span>
                  {yaraResult.findings_created > 0 && (
                    <Button variant="link" size="sm" className="h-auto p-0" asChild>
                      <Link to={`/projects/${project.id}/findings?source=yara_scan`}>
                        View in Findings
                      </Link>
                    </Button>
                  )}
                  {yaraResult.errors.length > 0 && (
                    <span className="text-xs text-destructive">
                      {yaraResult.errors.length} error(s)
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          <McpConnectionCard projectId={project.id} />
        </>
      )}
    </div>
  )
}
