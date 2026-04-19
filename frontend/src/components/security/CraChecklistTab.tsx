import { useCallback, useEffect, useState } from 'react'
import { Loader2, RefreshCw, Download, Shield, ChevronDown, ChevronRight } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  listCraAssessments,
  getCraAssessment,
  createCraAssessment,
  autoPopulateCra,
  updateCraRequirement,
  exportCraChecklist,
  type CraAssessment,
  type CraAssessmentSummary,
  type CraRequirementResult,
} from '@/api/craCompliance'

interface CraChecklistTabProps {
  projectId: string
  selectedFirmwareId: string | null
}

const STATUS_COLORS: Record<string, string> = {
  pass: 'bg-green-600 text-white',
  fail: 'bg-red-600 text-white',
  partial: 'bg-yellow-500 text-black',
  not_tested: 'bg-gray-500 text-white',
  not_applicable: 'bg-blue-500 text-white',
}

const STATUS_OPTIONS = [
  { value: 'pass', label: 'Pass' },
  { value: 'fail', label: 'Fail' },
  { value: 'partial', label: 'Partial' },
  { value: 'not_tested', label: 'Not Tested' },
  { value: 'not_applicable', label: 'N/A' },
]

function statusLabel(status: string): string {
  const opt = STATUS_OPTIONS.find((o) => o.value === status)
  return opt ? opt.label : status
}

export default function CraChecklistTab({ projectId, selectedFirmwareId }: CraChecklistTabProps) {
  const [assessments, setAssessments] = useState<CraAssessmentSummary[]>([])
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null)
  const [assessment, setAssessment] = useState<CraAssessment | null>(null)
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [populating, setPopulating] = useState(false)
  const [expandedReq, setExpandedReq] = useState<string | null>(null)
  const [saving, setSaving] = useState<string | null>(null)
  const [showNewForm, setShowNewForm] = useState(false)
  const [newProductName, setNewProductName] = useState('')
  const [newProductVersion, setNewProductVersion] = useState('')
  const [newAssessorName, setNewAssessorName] = useState('')

  // Editable fields for the expanded requirement
  const [editStatus, setEditStatus] = useState('')
  const [editNotes, setEditNotes] = useState('')
  const [editEvidence, setEditEvidence] = useState('')

  const loadAssessments = useCallback(async () => {
    setLoading(true)
    try {
      const list = await listCraAssessments(projectId)
      setAssessments(list)
      if (list.length > 0 && !selectedAssessmentId) {
        setSelectedAssessmentId(list[0].id)
      }
    } catch (e) {
      // Intentional silent fallback: an empty list renders as the
      // "Start CRA Assessment" empty state, which is the correct UX
      // both for a brand-new project (no assessments) and for a
      // transient API failure (user can retry by reloading). Still
      // log for ops visibility so real regressions surface in
      // devtools instead of being swallowed.
      console.warn('[CraChecklistTab] loadAssessments failed', e)
      setAssessments([])
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedAssessmentId])

  const loadAssessment = useCallback(async () => {
    if (!selectedAssessmentId) {
      setAssessment(null)
      return
    }
    setLoading(true)
    try {
      const data = await getCraAssessment(projectId, selectedAssessmentId)
      setAssessment(data)
    } catch (e) {
      // Intentional silent fallback: if the selected assessment
      // fails to load (deleted between list + open, 404, 500), the
      // UI gracefully falls back to the assessment-selector list,
      // which is acceptable UX. Log for ops visibility.
      console.warn('[CraChecklistTab] loadAssessment failed', e)
      setAssessment(null)
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedAssessmentId])

  useEffect(() => {
    loadAssessments()
  }, [loadAssessments])

  useEffect(() => {
    loadAssessment()
  }, [loadAssessment])

  const handleCreate = async () => {
    setCreating(true)
    try {
      const body: Record<string, string> = {}
      if (newProductName.trim()) body.product_name = newProductName.trim()
      if (newProductVersion.trim()) body.product_version = newProductVersion.trim()
      if (newAssessorName.trim()) body.assessor_name = newAssessorName.trim()
      if (selectedFirmwareId) body.firmware_id = selectedFirmwareId
      const created = await createCraAssessment(projectId, body)
      setSelectedAssessmentId(created.id)
      setAssessment(created)
      setAssessments((prev) => [created, ...prev])
      setShowNewForm(false)
      setNewProductName('')
      setNewProductVersion('')
      setNewAssessorName('')
    } catch {
      // keep existing state
    } finally {
      setCreating(false)
    }
  }

  const handleAutoPopulate = async () => {
    if (!selectedAssessmentId) return
    setPopulating(true)
    try {
      const updated = await autoPopulateCra(projectId, selectedAssessmentId)
      setAssessment(updated)
    } catch {
      // keep existing state
    } finally {
      setPopulating(false)
    }
  }

  const handleExpandRequirement = (req: CraRequirementResult) => {
    if (expandedReq === req.id) {
      setExpandedReq(null)
      return
    }
    setExpandedReq(req.id)
    setEditStatus(req.status)
    setEditNotes(req.manual_notes || '')
    setEditEvidence(req.manual_evidence || '')
  }

  const handleSaveRequirement = async (req: CraRequirementResult) => {
    if (!selectedAssessmentId) return
    setSaving(req.id)
    try {
      const updated = await updateCraRequirement(projectId, selectedAssessmentId, req.id, {
        status: editStatus,
        manual_notes: editNotes,
        manual_evidence: editEvidence,
      })
      // Update the requirement in the local assessment state
      setAssessment((prev) => {
        if (!prev) return prev
        return {
          ...prev,
          requirement_results: prev.requirement_results.map((r) =>
            r.id === updated.id ? updated : r
          ),
        }
      })
    } catch {
      // keep existing state
    } finally {
      setSaving(null)
    }
  }

  const handleExport = async () => {
    if (!selectedAssessmentId) return
    try {
      const data = await exportCraChecklist(projectId, selectedAssessmentId)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cra-checklist-${selectedAssessmentId}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch {
      // keep existing state
    }
  }

  const requirements = assessment?.requirement_results || []
  const part1 = requirements.filter((r) => r.annex_part === 1)
  const part2 = requirements.filter((r) => r.annex_part === 2)
  const totalReqs = requirements.length
  const assessedCount = requirements.filter((r) => r.status !== 'not_tested').length

  // Progress bar segment widths
  const passCount = requirements.filter((r) => r.status === 'pass').length
  const failCount = requirements.filter((r) => r.status === 'fail').length
  const partialCount = requirements.filter((r) => r.status === 'partial').length
  const notTestedCount = requirements.filter((r) => r.status === 'not_tested').length
  const naCount = requirements.filter((r) => r.status === 'not_applicable').length

  return (
    <div className="space-y-4">
      {/* Assessment selector / create */}
      <div className="flex items-center gap-3 flex-wrap">
        {assessments.length > 0 && (
          <select
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            value={selectedAssessmentId || ''}
            onChange={(e) => setSelectedAssessmentId(e.target.value || null)}
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.product_name || 'Untitled'} {a.product_version ? `v${a.product_version}` : ''} — {new Date(a.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
        )}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowNewForm(!showNewForm)}
        >
          {assessments.length === 0 ? 'Start CRA Assessment' : 'New Assessment'}
        </Button>
        {assessment && (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={handleAutoPopulate}
              disabled={populating}
            >
              {populating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {populating ? 'Populating...' : 'Auto-populate from Findings'}
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" />
              Export JSON
            </Button>
          </>
        )}
      </div>

      {/* New assessment form */}
      {showNewForm && (
        <Card>
          <CardContent className="py-3 px-4 space-y-3">
            <p className="text-sm font-medium">Create New CRA Assessment</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <input
                type="text"
                placeholder="Product name"
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                value={newProductName}
                onChange={(e) => setNewProductName(e.target.value)}
              />
              <input
                type="text"
                placeholder="Product version"
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                value={newProductVersion}
                onChange={(e) => setNewProductVersion(e.target.value)}
              />
              <input
                type="text"
                placeholder="Assessor name"
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                value={newAssessorName}
                onChange={(e) => setNewAssessorName(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={handleCreate} disabled={creating}>
                {creating ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                {creating ? 'Creating...' : 'Create'}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setShowNewForm(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Loading state */}
      {loading && !assessment && (
        <div className="flex items-center gap-2 py-8 justify-center text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading assessment...
        </div>
      )}

      {/* Empty state */}
      {!loading && !assessment && assessments.length === 0 && !showNewForm && (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            No CRA assessments yet. Click &quot;Start CRA Assessment&quot; to begin compliance checking.
          </p>
        </div>
      )}

      {/* Assessment detail */}
      {assessment && (
        <>
          {/* Overall status + progress */}
          <Card>
            <CardContent className="py-3 px-4 space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium">
                    {assessment.product_name || 'Untitled Assessment'}
                    {assessment.product_version ? ` v${assessment.product_version}` : ''}
                  </span>
                  <Badge variant="outline" className="text-xs">
                    {assessment.overall_status.replace('_', ' ')}
                  </Badge>
                </div>
                <span className="text-sm text-muted-foreground">
                  {assessedCount}/{totalReqs} assessed
                </span>
              </div>

              {/* Progress bar */}
              {totalReqs > 0 && (
                <div className="h-3 bg-muted rounded-full overflow-hidden flex">
                  {passCount > 0 && (
                    <div
                      className="h-full bg-green-600 transition-all"
                      style={{ width: `${(passCount / totalReqs) * 100}%` }}
                      title={`Pass: ${passCount}`}
                    />
                  )}
                  {failCount > 0 && (
                    <div
                      className="h-full bg-red-600 transition-all"
                      style={{ width: `${(failCount / totalReqs) * 100}%` }}
                      title={`Fail: ${failCount}`}
                    />
                  )}
                  {partialCount > 0 && (
                    <div
                      className="h-full bg-yellow-500 transition-all"
                      style={{ width: `${(partialCount / totalReqs) * 100}%` }}
                      title={`Partial: ${partialCount}`}
                    />
                  )}
                  {naCount > 0 && (
                    <div
                      className="h-full bg-blue-500 transition-all"
                      style={{ width: `${(naCount / totalReqs) * 100}%` }}
                      title={`N/A: ${naCount}`}
                    />
                  )}
                  {notTestedCount > 0 && (
                    <div
                      className="h-full bg-gray-500 transition-all"
                      style={{ width: `${(notTestedCount / totalReqs) * 100}%` }}
                      title={`Not Tested: ${notTestedCount}`}
                    />
                  )}
                </div>
              )}

              {/* Legend */}
              <div className="flex gap-3 flex-wrap text-xs">
                {passCount > 0 && <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-green-600 inline-block" /> Pass: {passCount}</span>}
                {failCount > 0 && <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-red-600 inline-block" /> Fail: {failCount}</span>}
                {partialCount > 0 && <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-yellow-500 inline-block" /> Partial: {partialCount}</span>}
                {naCount > 0 && <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-blue-500 inline-block" /> N/A: {naCount}</span>}
                {notTestedCount > 0 && <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-gray-500 inline-block" /> Not Tested: {notTestedCount}</span>}
              </div>
            </CardContent>
          </Card>

          {/* Part 1: Security Requirements */}
          <RequirementGroup
            title="Part 1: Security Requirements"
            deadline="Dec 2027 deadline"
            requirements={part1}
            expandedReq={expandedReq}
            saving={saving}
            editStatus={editStatus}
            editNotes={editNotes}
            editEvidence={editEvidence}
            onExpand={handleExpandRequirement}
            onStatusChange={setEditStatus}
            onNotesChange={setEditNotes}
            onEvidenceChange={setEditEvidence}
            onSave={handleSaveRequirement}
          />

          {/* Part 2: Vulnerability Handling */}
          <RequirementGroup
            title="Part 2: Vulnerability Handling"
            deadline="Sep 2026 deadline"
            requirements={part2}
            expandedReq={expandedReq}
            saving={saving}
            editStatus={editStatus}
            editNotes={editNotes}
            editEvidence={editEvidence}
            onExpand={handleExpandRequirement}
            onStatusChange={setEditStatus}
            onNotesChange={setEditNotes}
            onEvidenceChange={setEditEvidence}
            onSave={handleSaveRequirement}
          />
        </>
      )}
    </div>
  )
}

interface RequirementGroupProps {
  title: string
  deadline: string
  requirements: CraRequirementResult[]
  expandedReq: string | null
  saving: string | null
  editStatus: string
  editNotes: string
  editEvidence: string
  onExpand: (req: CraRequirementResult) => void
  onStatusChange: (v: string) => void
  onNotesChange: (v: string) => void
  onEvidenceChange: (v: string) => void
  onSave: (req: CraRequirementResult) => void
}

function RequirementGroup({
  title,
  deadline,
  requirements,
  expandedReq,
  saving,
  editStatus,
  editNotes,
  editEvidence,
  onExpand,
  onStatusChange,
  onNotesChange,
  onEvidenceChange,
  onSave,
}: RequirementGroupProps) {
  if (requirements.length === 0) return null

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 mb-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        <Badge variant="outline" className="text-[10px]">{deadline}</Badge>
      </div>

      {requirements.map((req) => {
        const isExpanded = expandedReq === req.id
        return (
          <div key={req.id} className="border rounded-md">
            {/* Row header */}
            <button
              type="button"
              className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-muted/50 transition-colors"
              onClick={() => onExpand(req)}
            >
              {isExpanded ? (
                <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
              )}
              <span className="text-xs font-mono text-muted-foreground w-20 shrink-0">
                {req.requirement_id}
              </span>
              <span className="text-sm flex-1 truncate">{req.requirement_title}</span>
              <div className="flex items-center gap-2 shrink-0">
                {req.auto_populated && (
                  <Badge variant="secondary" className="text-[10px] px-1.5 py-0">AUTO</Badge>
                )}
                {req.tool_sources.length > 0 && req.tool_sources.slice(0, 2).map((src) => (
                  <Badge key={src} variant="secondary" className="text-[10px] px-1.5 py-0">
                    {src}
                  </Badge>
                ))}
                <Badge className={`text-xs ${STATUS_COLORS[req.status] || 'bg-gray-500 text-white'}`}>
                  {statusLabel(req.status)}
                </Badge>
              </div>
            </button>

            {/* Expanded detail */}
            {isExpanded && (
              <div className="px-3 pb-3 pt-1 border-t space-y-3">
                {/* Evidence summary (read-only, from auto-populate) */}
                {req.evidence_summary && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground mb-1">Evidence Summary</p>
                    <p className="text-xs whitespace-pre-wrap bg-muted/50 rounded p-2">
                      {req.evidence_summary}
                    </p>
                  </div>
                )}

                {/* Related CWEs / CVEs */}
                {(req.related_cwes.length > 0 || req.related_cves.length > 0) && (
                  <div className="flex gap-3 flex-wrap">
                    {req.related_cwes.map((cwe) => (
                      <Badge key={cwe} variant="outline" className="text-[10px]">{cwe}</Badge>
                    ))}
                    {req.related_cves.map((cve) => (
                      <Badge key={cve} variant="outline" className="text-[10px] border-red-300 text-red-400">{cve}</Badge>
                    ))}
                  </div>
                )}

                {/* Editable fields */}
                <div className="grid grid-cols-1 gap-3">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Status</label>
                    <select
                      className="h-8 rounded-md border border-input bg-background px-2 text-sm w-48"
                      value={editStatus}
                      onChange={(e) => onStatusChange(e.target.value)}
                    >
                      {STATUS_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Manual Notes</label>
                    <textarea
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm min-h-[60px] resize-y"
                      placeholder="Add manual assessment notes..."
                      value={editNotes}
                      onChange={(e) => onNotesChange(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground block mb-1">Manual Evidence</label>
                    <textarea
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm min-h-[60px] resize-y"
                      placeholder="Add evidence references, screenshots, test results..."
                      value={editEvidence}
                      onChange={(e) => onEvidenceChange(e.target.value)}
                    />
                  </div>
                </div>

                <Button
                  size="sm"
                  onClick={() => onSave(req)}
                  disabled={saving === req.id}
                >
                  {saving === req.id ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  {saving === req.id ? 'Saving...' : 'Save'}
                </Button>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
