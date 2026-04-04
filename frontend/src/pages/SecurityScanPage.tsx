import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Shield, Loader2, RefreshCw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  runSecurityAudit,
  runYaraScan,
  listFindings,
  type SecurityAuditResult,
  type YaraScanResult,
} from '@/api/findings'
import { runTool } from '@/api/tools'
import { listFirmware } from '@/api/firmware'
import { useProjectStore } from '@/stores/projectStore'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import type { Finding, FirmwareDetail, Severity } from '@/types'

type Tab = 'audit' | 'yara' | 'vulhunt'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

export default function SecurityScanPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const [tab, setTab] = useState<Tab>('audit')
  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null)
  const [yaraScanning, setYaraScanning] = useState(false)
  const [yaraResult, setYaraResult] = useState<YaraScanResult | null>(null)
  const [vulhuntScanning, setVulhuntScanning] = useState(false)
  const [vulhuntResult, setVulhuntResult] = useState<{ output: string; success: boolean } | null>(null)
  const [vulhuntProgress, setVulhuntProgress] = useState<{
    scanned: number; total: number; findings: number; message: string
    current_binary?: string; results_text?: string
  } | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)

  useEffect(() => {
    if (projectId) {
      listFirmware(projectId).then(setFirmwareList)
    }
  }, [projectId])

  const source = tab === 'audit' ? 'security_audit' : tab === 'yara' ? 'yara_scan' : 'vulhunt_scan'

  const loadFindings = useCallback(async () => {
    if (!projectId) return
    setLoadingFindings(true)
    try {
      const params: Record<string, string> = { source }
      if (selectedFirmwareId) params.firmware_id = selectedFirmwareId
      const results = await listFindings(projectId, params)
      setFindings(results)
    } catch {
      setFindings([])
    } finally {
      setLoadingFindings(false)
    }
  }, [projectId, source, selectedFirmwareId])

  useEffect(() => {
    loadFindings()
  }, [loadFindings])

  const handleAudit = async () => {
    if (!projectId) return
    setAuditing(true)
    setAuditResult(null)
    try {
      const result = await runSecurityAudit(projectId)
      setAuditResult(result)
      await loadFindings()
    } catch {
      setAuditResult({ status: 'error', checks_run: 0, findings_created: 0, total_findings: 0, errors: ['Scan failed'] })
    } finally {
      setAuditing(false)
    }
  }

  const handleYara = async () => {
    if (!projectId) return
    setYaraScanning(true)
    setYaraResult(null)
    try {
      const result = await runYaraScan(projectId)
      setYaraResult(result)
      await loadFindings()
    } catch {
      setYaraResult({ status: 'error', rules_loaded: 0, files_scanned: 0, files_matched: 0, findings_created: 0, errors: ['Scan failed'] })
    } finally {
      setYaraScanning(false)
    }
  }

  const handleVulhunt = async () => {
    if (!projectId) return
    setVulhuntScanning(true)
    setVulhuntResult(null)
    setVulhuntProgress(null)

    // Subscribe to SSE for progress updates
    const evtSource = new EventSource(`/api/v1/projects/${projectId}/events?types=vulhunt`)
    evtSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'vulhunt') {
          setVulhuntProgress({
            scanned: data.scanned ?? 0,
            total: data.total ?? 0,
            findings: data.findings ?? 0,
            message: data.message ?? '',
            current_binary: data.current_binary,
            results_text: data.results_text,
          })
        }
      } catch { /* ignore parse errors */ }
    }

    try {
      const result = await runTool(
        projectId,
        'vulhunt_scan_firmware',
        {},
        selectedFirmwareId || undefined,
      )
      setVulhuntResult(result)
    } catch {
      setVulhuntResult({ output: 'VulHunt scan failed. Is the vulhunt container running?', success: false })
    } finally {
      evtSource.close()
      setVulhuntScanning(false)
    }
  }

  // Group findings by severity
  const bySeverity = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    acc[f.severity] = acc[f.severity] || []
    acc[f.severity].push(f)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-lg font-semibold">Security Scanning</h1>
            <p className="text-sm text-muted-foreground">
              Automated security audit and YARA malware scanning
            </p>
          </div>
        </div>
      </div>

      {/* Firmware Selector */}
      {projectId && <FirmwareSelector projectId={projectId} firmwareList={firmwareList} />}

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'audit'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('audit')}
        >
          Security Audit
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'yara'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('yara')}
        >
          YARA Scan
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'vulhunt'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('vulhunt')}
        >
          VulHunt
        </button>
      </div>

      {/* Action buttons + results */}
      {tab === 'audit' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleAudit} disabled={auditing}>
              {auditing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {auditing ? 'Scanning...' : 'Run Security Audit'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Scans for hardcoded credentials, API keys, weak passwords, setuid binaries, insecure services, kernel hardening
            </p>
          </div>

          {auditResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <span className="text-sm">
                  Audit complete: <strong>{auditResult.findings_created}</strong> finding{auditResult.findings_created !== 1 ? 's' : ''} from {auditResult.checks_run} checks
                  {auditResult.errors.length > 0 && (
                    <span className="text-xs text-destructive ml-2">({auditResult.errors.length} error{auditResult.errors.length !== 1 ? 's' : ''})</span>
                  )}
                </span>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {tab === 'yara' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleYara} disabled={yaraScanning}>
              {yaraScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {yaraScanning ? 'Scanning...' : 'Run YARA Scan'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Scans with 26 rules: IoT botnets, backdoors, crypto miners, web shells, private keys, weak crypto
            </p>
          </div>

          {yaraResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <span className="text-sm">
                  YARA scan complete: <strong>{yaraResult.findings_created}</strong> finding{yaraResult.findings_created !== 1 ? 's' : ''} from {yaraResult.files_scanned} files ({yaraResult.rules_loaded} rules)
                  {yaraResult.errors.length > 0 && (
                    <span className="text-xs text-destructive ml-2">({yaraResult.errors.length} error{yaraResult.errors.length !== 1 ? 's' : ''})</span>
                  )}
                </span>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {tab === 'vulhunt' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleVulhunt} disabled={vulhuntScanning}>
              {vulhuntScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {vulhuntScanning ? 'Scanning...' : 'Run VulHunt Scan'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Deep binary vulnerability analysis on all ELF and UEFI PE32+ modules — dataflow tracking, pattern matching
            </p>
          </div>

          {vulhuntScanning && vulhuntProgress && vulhuntProgress.total > 0 && (
            <Card>
              <CardContent className="py-3 px-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{vulhuntProgress.message}</span>
                  <span className="font-mono">
                    {vulhuntProgress.scanned}/{vulhuntProgress.total}
                  </span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full transition-all duration-300"
                    style={{ width: `${(vulhuntProgress.scanned / vulhuntProgress.total) * 100}%` }}
                  />
                </div>
                {vulhuntProgress.findings > 0 && (
                  <p className="text-xs text-orange-500">
                    {vulhuntProgress.findings} vulnerability finding{vulhuntProgress.findings !== 1 ? 's' : ''} so far
                  </p>
                )}
                {vulhuntProgress.current_binary && (
                  <p className="text-xs text-muted-foreground font-mono truncate">
                    Scanning: {vulhuntProgress.current_binary}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {vulhuntScanning && vulhuntProgress?.results_text && (
            <Card>
              <CardContent className="py-3 px-4">
                <pre className="text-xs whitespace-pre-wrap font-mono max-h-64 overflow-y-auto">
                  {vulhuntProgress.results_text}
                </pre>
              </CardContent>
            </Card>
          )}

          {vulhuntResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <pre className="text-xs whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                  {vulhuntResult.output}
                </pre>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Findings list */}
      {loadingFindings ? (
        <div className="flex items-center gap-2 py-8 justify-center text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            {tab === 'audit'
              ? 'No security audit findings. Click "Run Security Audit" to scan.'
              : tab === 'yara'
              ? 'No YARA findings. Click "Run YARA Scan" to scan.'
              : 'No VulHunt findings yet. Click "Run VulHunt Scan" to analyze binaries.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Severity summary */}
          <div className="flex gap-3 flex-wrap">
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
              const count = bySeverity[sev]?.length || 0
              if (count === 0) return null
              return (
                <Badge key={sev} className={SEVERITY_COLORS[sev]}>
                  {sev}: {count}
                </Badge>
              )
            })}
            <span className="text-sm text-muted-foreground self-center">
              {findings.length} total
            </span>
            <Button variant="link" size="sm" className="h-auto p-0" asChild>
              <Link to={`/projects/${projectId}/findings?source=${source}`}>
                View in Findings page
              </Link>
            </Button>
          </div>

          {/* Findings table */}
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-3 font-medium w-20">Severity</th>
                  <th className="pb-2 pr-3 font-medium">Title</th>
                  <th className="pb-2 pr-3 font-medium">File</th>
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 200).map((f) => (
                  <tr key={f.id} className="border-b border-border/30 hover:bg-muted/50">
                    <td className="py-1.5 pr-3">
                      <Badge variant="outline" className={`text-xs ${SEVERITY_COLORS[f.severity as Severity] || ''}`}>
                        {f.severity}
                      </Badge>
                    </td>
                    <td className="py-1.5 pr-3 truncate max-w-[400px]">
                      <Link
                        to={`/projects/${projectId}/findings`}
                        state={{ findingId: f.id }}
                        className="hover:underline hover:text-primary"
                      >
                        {f.title}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-muted-foreground truncate max-w-[200px]">
                      {f.file_path ? (
                        <Link
                          to={`/projects/${projectId}/explore?path=${encodeURIComponent(f.file_path)}`}
                          className="hover:underline hover:text-primary"
                        >
                          {f.file_path}
                        </Link>
                      ) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {findings.length > 200 && (
              <p className="text-xs text-muted-foreground mt-2">
                Showing first 200 of {findings.length} findings.{' '}
                <Link to={`/projects/${projectId}/findings?source=${source}`} className="underline">
                  View all in Findings page
                </Link>
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
