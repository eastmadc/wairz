import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  FolderSearch,
  ShieldAlert,
  Loader2,
  GitCompareArrows,
  Shield,
} from 'lucide-react'
import { runSecurityAudit, runYaraScan } from '@/api/findings'
import type { SecurityAuditResult, YaraScanResult } from '@/api/findings'
import type { ProjectDetail } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import McpConnectionCard from '@/components/projects/McpConnectionCard'

interface ProjectActionButtonsProps {
  project: ProjectDetail
  unpackedCount: number
}

export default function ProjectActionButtons({
  project,
  unpackedCount,
}: ProjectActionButtonsProps) {
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null)
  const [yaraScanning, setYaraScanning] = useState(false)
  const [yaraResult, setYaraResult] = useState<YaraScanResult | null>(null)

  return (
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
  )
}
