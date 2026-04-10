import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertCircle, CheckCircle2, Loader2, Shield, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  runAbusechScan,
  runKnownGoodScan,
  listFindings,
  type AbusechScanResult,
  type KnownGoodScanResult,
  type KnownGoodFile,
} from '@/api/findings'
import type { Finding, Severity } from '@/types'

interface ThreatIntelTabProps {
  projectId: string
  selectedFirmwareId: string | null
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

export default function ThreatIntelTab({ projectId, selectedFirmwareId }: ThreatIntelTabProps) {
  const [abusechScanning, setAbusechScanning] = useState(false)
  const [abusechResult, setAbusechResult] = useState<AbusechScanResult | null>(null)
  const [knownGoodScanning, setKnownGoodScanning] = useState(false)
  const [knownGoodResult, setKnownGoodResult] = useState<KnownGoodScanResult | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)
  const [showAllKnownGood, setShowAllKnownGood] = useState(false)

  const loadFindings = useCallback(async () => {
    setLoadingFindings(true)
    try {
      const params: Record<string, string> = { source: 'abusech_scan' }
      if (selectedFirmwareId) params.firmware_id = selectedFirmwareId
      const results = await listFindings(projectId, params)
      setFindings(results)
    } catch {
      setFindings([])
    } finally {
      setLoadingFindings(false)
    }
  }, [projectId, selectedFirmwareId])

  useEffect(() => {
    loadFindings()
  }, [loadFindings])

  const handleAbusechScan = async () => {
    setAbusechScanning(true)
    setAbusechResult(null)
    try {
      const result = await runAbusechScan(projectId)
      setAbusechResult(result)
      await loadFindings()
    } catch {
      setAbusechResult({
        status: 'error', binaries_checked: 0, malwarebazaar_hits: 0,
        threatfox_hits: 0, yaraify_hits: 0, findings_created: 0,
        details: {}, errors: ['Scan failed'],
      })
    } finally {
      setAbusechScanning(false)
    }
  }

  const handleKnownGoodScan = async () => {
    setKnownGoodScanning(true)
    setKnownGoodResult(null)
    try {
      const result = await runKnownGoodScan(projectId)
      setKnownGoodResult(result)
    } catch {
      setKnownGoodResult({
        status: 'error', binaries_checked: 0, known_good_count: 0,
        unknown_count: 0, known_good_files: [], errors: ['Scan failed'],
      })
    } finally {
      setKnownGoodScanning(false)
    }
  }

  const bySeverity = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    acc[f.severity] = acc[f.severity] || []
    acc[f.severity].push(f)
    return acc
  }, {})

  const knownGoodToShow: KnownGoodFile[] = knownGoodResult
    ? (showAllKnownGood ? knownGoodResult.known_good_files : knownGoodResult.known_good_files.slice(0, 20))
    : []

  return (
    <div className="space-y-6">
      {/* abuse.ch Scan Section */}
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Button onClick={handleAbusechScan} disabled={abusechScanning || knownGoodScanning}>
            {abusechScanning
              ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              : <ShieldAlert className="mr-2 h-4 w-4" />}
            {abusechScanning ? 'Scanning...' : 'Run abuse.ch Scan'}
          </Button>
          <p className="text-xs text-muted-foreground">
            Hash-only lookups against MalwareBazaar, ThreatFox IOCs, and YARAify community rules. No file data uploaded.
          </p>
        </div>

        {abusechResult && (
          <Card>
            <CardContent className="py-3 px-4">
              <div className="flex items-center gap-4 flex-wrap text-sm">
                <span>
                  Checked <strong>{abusechResult.binaries_checked}</strong> firmware image{abusechResult.binaries_checked !== 1 ? 's' : ''}
                </span>
                <span className="text-muted-foreground">|</span>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className={`cursor-help ${abusechResult.malwarebazaar_hits > 0 ? 'text-red-500 font-semibold' : ''}`}>
                        MalwareBazaar: {abusechResult.malwarebazaar_hits}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>Malware sample database — matches indicate known malware</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className={`cursor-help ${abusechResult.threatfox_hits > 0 ? 'text-orange-500 font-semibold' : ''}`}>
                        ThreatFox: {abusechResult.threatfox_hits}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>IOC database — tracks malicious IPs, domains, URLs, and file hashes</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className={`cursor-help ${abusechResult.yaraify_hits > 0 ? 'text-yellow-600 font-semibold' : ''}`}>
                        YARAify: {abusechResult.yaraify_hits}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>Community YARA rule matches from abuse.ch</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <span className="text-muted-foreground">|</span>
                <span className="inline-flex items-center gap-1">
                  {abusechResult.errors.length > 0
                    ? <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
                    : <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />}
                  {abusechResult.findings_created} finding{abusechResult.findings_created !== 1 ? 's' : ''} created
                </span>
                {abusechResult.errors.length > 0 && (
                  <span className="text-xs text-destructive">
                    ({abusechResult.errors.length} error{abusechResult.errors.length !== 1 ? 's' : ''})
                  </span>
                )}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* CIRCL Hashlookup Section */}
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Button onClick={handleKnownGoodScan} disabled={knownGoodScanning || abusechScanning} variant="outline">
            {knownGoodScanning
              ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              : <ShieldCheck className="mr-2 h-4 w-4" />}
            {knownGoodScanning ? 'Scanning...' : 'Run CIRCL Hashlookup'}
          </Button>
          <p className="text-xs text-muted-foreground">
            Identifies known-good binaries via NSRL database. Reduces analyst workload by flagging legitimate software.
          </p>
        </div>

        {knownGoodResult && (
          <Card>
            <CardContent className="py-3 px-4 space-y-3">
              <div className="flex items-center gap-4 flex-wrap text-sm">
                <span>
                  Checked <strong>{knownGoodResult.binaries_checked}</strong> binar{knownGoodResult.binaries_checked !== 1 ? 'ies' : 'y'}
                </span>
                <span className="text-muted-foreground">|</span>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="cursor-help text-green-600 font-semibold">
                        {knownGoodResult.known_good_count} known-good
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>NIST National Software Reference Library — identifies known legitimate software</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <span className="text-yellow-600">
                  {knownGoodResult.unknown_count} unknown
                </span>
                <span className="inline-flex items-center gap-1">
                  {knownGoodResult.errors.length > 0
                    ? <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
                    : <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />}
                </span>
                {knownGoodResult.errors.length > 0 && (
                  <span className="text-xs text-destructive">
                    ({knownGoodResult.errors.length} error{knownGoodResult.errors.length !== 1 ? 's' : ''})
                  </span>
                )}
              </div>

              {knownGoodResult.binaries_checked > 0 && (
                <Progress
                  value={(knownGoodResult.known_good_count / knownGoodResult.binaries_checked) * 100}
                  className="h-2"
                />
              )}

              {knownGoodToShow.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b text-left text-muted-foreground">
                        <th className="pb-2 pr-3 font-medium">File Path</th>
                        <th className="pb-2 pr-3 font-medium">Product</th>
                        <th className="pb-2 pr-3 font-medium">Vendor</th>
                        <th className="pb-2 pr-3 font-medium">Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {knownGoodToShow.map((f) => (
                        <tr key={f.sha256} className="border-b border-border/30 hover:bg-muted/50">
                          <td className="py-1.5 pr-3 font-mono truncate max-w-[250px]">
                            <Link
                              to={`/projects/${projectId}/explore?path=${encodeURIComponent(f.path)}`}
                              className="hover:underline hover:text-primary"
                            >
                              {f.path}
                            </Link>
                          </td>
                          <td className="py-1.5 pr-3 truncate max-w-[200px]">{f.product || '-'}</td>
                          <td className="py-1.5 pr-3 truncate max-w-[150px]">{f.vendor || '-'}</td>
                          <td className="py-1.5 pr-3">
                            <Badge variant="outline" className="text-xs">
                              {f.source}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!showAllKnownGood && knownGoodResult.known_good_files.length > 20 && (
                    <button
                      type="button"
                      className="text-xs text-primary hover:underline mt-2"
                      onClick={() => setShowAllKnownGood(true)}
                    >
                      Show all {knownGoodResult.known_good_files.length} known-good files
                    </button>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Findings from abuse.ch scan */}
      {loadingFindings ? (
        <div className="flex items-center gap-2 py-8 justify-center text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            No threat intelligence findings yet. Run an abuse.ch scan to check firmware against known malware databases.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
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
              <Link to={`/projects/${projectId}/findings?source=abusech_scan`}>
                View in Findings page
              </Link>
            </Button>
          </div>

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
                <Link to={`/projects/${projectId}/findings?source=abusech_scan`} className="underline">
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
