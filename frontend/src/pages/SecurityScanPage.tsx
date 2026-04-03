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
import { listFirmware } from '@/api/firmware'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import type { Finding, FirmwareDetail, Severity } from '@/types'

type Tab = 'audit' | 'yara'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

export default function SecurityScanPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [tab, setTab] = useState<Tab>('audit')
  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null)
  const [yaraScanning, setYaraScanning] = useState(false)
  const [yaraResult, setYaraResult] = useState<YaraScanResult | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)

  useEffect(() => {
    if (projectId) {
      listFirmware(projectId).then(setFirmwareList)
    }
  }, [projectId])

  const source = tab === 'audit' ? 'security_audit' : 'yara_scan'

  const loadFindings = useCallback(async () => {
    if (!projectId) return
    setLoadingFindings(true)
    try {
      const results = await listFindings(projectId, { source })
      setFindings(results)
    } catch {
      setFindings([])
    } finally {
      setLoadingFindings(false)
    }
  }, [projectId, source])

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
              : 'No YARA findings. Click "Run YARA Scan" to scan.'}
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
                    <td className="py-1.5 pr-3 truncate max-w-[400px]">{f.title}</td>
                    <td className="py-1.5 pr-3 font-mono text-muted-foreground truncate max-w-[200px]">
                      {f.file_path || '-'}
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
