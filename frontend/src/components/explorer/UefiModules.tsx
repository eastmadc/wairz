import { useState, useEffect } from 'react'
import { Loader2, Cpu, Search, ChevronRight, ChevronDown, FileCode, Download, Shield, AlertTriangle } from 'lucide-react'
import { getUefiModules, getFileDownloadUrl, scanUefiModules, type UefiModule, type UefiScanResult } from '@/api/files'
import { formatFileSize } from '@/utils/format'

const TYPE_COLORS: Record<string, string> = {
  'DXE driver': 'bg-blue-500/10 text-blue-400',
  'DXE core': 'bg-blue-500/20 text-blue-300',
  'PEI module': 'bg-green-500/10 text-green-400',
  'PEI core': 'bg-green-500/20 text-green-300',
  'SMM module': 'bg-red-500/10 text-red-400',
  'SMM core': 'bg-red-500/20 text-red-300',
  'Application': 'bg-purple-500/10 text-purple-400',
  'SEC core': 'bg-yellow-500/10 text-yellow-400',
  'Freeform': 'bg-gray-500/10 text-gray-400',
  'Volume image': 'bg-gray-500/10 text-gray-400',
  'Raw': 'bg-gray-500/10 text-gray-500',
  'Pad': 'bg-gray-500/5 text-gray-600',
}

const SECTION_COLORS: Record<string, string> = {
  'PE32 image section': 'text-blue-400',
  'TE image section': 'text-cyan-400',
  'UI section': 'text-gray-400',
  'Version section': 'text-gray-400',
  'DXE dependency section': 'text-yellow-400',
  'PEI dependency section': 'text-green-400',
  'MM dependency section': 'text-red-400',
  'Raw section': 'text-gray-500',
  'Compressed section': 'text-orange-400',
}

function getTypeColor(type: string): string {
  return TYPE_COLORS[type] || 'bg-gray-500/10 text-gray-400'
}

function parseSizeHex(sizeStr: string): number {
  // "F2Eh (3886)" → 3886
  const match = sizeStr.match(/\((\d+)\)/)
  return match ? parseInt(match[1], 10) : 0
}

interface Props {
  projectId: string
}

export default function UefiModules({ projectId }: Props) {
  const [modules, setModules] = useState<UefiModule[]>([])
  const [loading, setLoading] = useState(true)
  const [isUefi, setIsUefi] = useState(false)
  const [filter, setFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<UefiScanResult | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    getUefiModules(projectId)
      .then((data) => {
        if (!cancelled) {
          setModules(data.modules)
          setIsUefi(data.is_uefi)
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [projectId])

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (!isUefi) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-muted-foreground">
        <Cpu className="mb-2 h-8 w-8 opacity-30" />
        <p className="text-sm">Not a UEFI firmware image.</p>
        <p className="text-xs opacity-60">UEFI modules are only available for BIOS/UEFI firmware.</p>
      </div>
    )
  }

  const typeCounts = new Map<string, number>()
  for (const m of modules) {
    typeCounts.set(m.type, (typeCounts.get(m.type) || 0) + 1)
  }

  const filtered = modules.filter((m) => {
    if (typeFilter && m.type !== typeFilter) return false
    if (!filter) return true
    const q = filter.toLowerCase()
    return (
      m.guid.toLowerCase().includes(q) ||
      m.name.toLowerCase().includes(q) ||
      m.type.toLowerCase().includes(q) ||
      m.text.toLowerCase().includes(q)
    )
  })

  const toggleExpand = (guid: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(guid)) next.delete(guid)
      else next.add(guid)
      return next
    })
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-2">
        <Cpu className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">
          UEFI Modules ({modules.length})
        </span>
        <span className="text-xs text-muted-foreground">
          {typeCounts.get('DXE driver') || 0} DXE, {typeCounts.get('SMM module') || 0} SMM, {typeCounts.get('PEI module') || 0} PEI
        </span>
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => {
              setScanning(true)
              setScanResult(null)
              scanUefiModules(projectId)
                .then((r) => { setScanResult(r); setScanning(false) })
                .catch(() => setScanning(false))
            }}
            disabled={scanning}
            className="flex items-center gap-1 rounded bg-red-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-red-500 disabled:opacity-50"
          >
            {scanning ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Shield className="h-3 w-3" />
            )}
            {scanning ? 'Scanning...' : 'Scan All Modules'}
          </button>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by GUID, name, or type..."
              className="h-7 w-56 rounded border border-border bg-background pl-7 pr-2 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>
        </div>
      </div>

      {/* Scan results banner */}
      {scanResult && (
        <div className={`flex items-center gap-3 border-b px-4 py-2 text-xs ${
          scanResult.findings_created > 0
            ? 'border-red-500/30 bg-red-500/10 text-red-300'
            : 'border-green-500/30 bg-green-500/10 text-green-300'
        }`}>
          {scanResult.findings_created > 0 ? (
            <AlertTriangle className="h-4 w-4 shrink-0" />
          ) : (
            <Shield className="h-4 w-4 shrink-0" />
          )}
          <span>
            Scanned {scanResult.modules_scanned} PE32+ modules
            {scanResult.findings_created > 0
              ? ` — ${scanResult.findings_created} security issues found`
              : ' — no issues found'}
          </span>
          {Object.entries(scanResult.summary).length > 0 && (
            <span className="text-[10px] opacity-70">
              ({Object.entries(scanResult.summary).map(([k, v]) => `${v} ${k.replace('UEFI module ', '')}`).join(', ')})
            </span>
          )}
          <button
            onClick={() => setScanResult(null)}
            className="ml-auto text-[10px] opacity-50 hover:opacity-100"
          >
            dismiss
          </button>
        </div>
      )}

      {/* Type filter chips */}
      <div className="flex flex-wrap gap-1 border-b border-border px-4 py-1.5">
        <button
          onClick={() => setTypeFilter(null)}
          className={`rounded px-2 py-0.5 text-xs ${
            typeFilter === null
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:bg-accent'
          }`}
        >
          All ({modules.length})
        </button>
        {Array.from(typeCounts.entries())
          .sort((a, b) => b[1] - a[1])
          .map(([type, count]) => (
            <button
              key={type}
              onClick={() => setTypeFilter(typeFilter === type ? null : type)}
              className={`rounded px-2 py-0.5 text-xs ${
                typeFilter === type
                  ? 'bg-primary text-primary-foreground'
                  : `${getTypeColor(type)} hover:opacity-80`
              }`}
            >
              {type} ({count})
            </button>
          ))}
      </div>

      {/* Module list */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-background">
            <tr className="border-b border-border text-left text-muted-foreground">
              <th className="w-6 px-1 py-1.5"></th>
              <th className="px-3 py-1.5 font-medium">Type</th>
              <th className="px-3 py-1.5 font-medium">Name</th>
              <th className="px-3 py-1.5 font-medium">GUID</th>
              <th className="px-3 py-1.5 font-medium text-center">Sections</th>
              <th className="px-3 py-1.5 font-medium text-right">Size</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((m) => {
              const isExpanded = expanded.has(m.guid + m.path)
              const sizeNum = parseSizeHex(m.size)
              return (
                <>
                  <tr
                    key={m.guid + m.path}
                    onClick={() => toggleExpand(m.guid + m.path)}
                    className={`cursor-pointer border-b border-border/50 hover:bg-accent/50 ${
                      isExpanded ? 'bg-accent/30' : ''
                    }`}
                  >
                    <td className="px-1 py-1 text-center text-muted-foreground">
                      {m.sections.length > 0 ? (
                        isExpanded ? (
                          <ChevronDown className="inline h-3 w-3" />
                        ) : (
                          <ChevronRight className="inline h-3 w-3" />
                        )
                      ) : null}
                    </td>
                    <td className="px-3 py-1">
                      <span
                        className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${getTypeColor(m.type)}`}
                      >
                        {m.type}
                      </span>
                    </td>
                    <td className="px-3 py-1 font-medium">
                      {m.name || m.text || (
                        <span className="text-muted-foreground/40">-</span>
                      )}
                    </td>
                    <td className="px-3 py-1 font-mono text-[10px] text-muted-foreground">
                      {m.guid}
                    </td>
                    <td className="px-3 py-1 text-center">
                      {m.has_pe32 && (
                        <span className="inline-flex items-center gap-0.5 rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-400">
                          <FileCode className="h-2.5 w-2.5" />
                          PE32+
                        </span>
                      )}
                      {m.sections.length > 0 && !m.has_pe32 && (
                        <span className="text-muted-foreground/50">{m.sections.length}</span>
                      )}
                    </td>
                    <td className="px-3 py-1 text-right text-muted-foreground">
                      {sizeNum > 0 ? formatFileSize(sizeNum) : m.size}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr key={m.guid + m.path + '-detail'}>
                      <td colSpan={6} className="bg-muted/30 px-8 py-2">
                        <div className="space-y-2">
                          {/* Sections */}
                          {m.sections.length > 0 && (
                            <div>
                              <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                                Sections
                              </div>
                              <div className="space-y-0.5">
                                {m.sections.map((s, si) => (
                                  <div key={si} className="flex items-center gap-3">
                                    <span
                                      className={`text-[11px] ${SECTION_COLORS[s.type] || 'text-gray-400'}`}
                                    >
                                      {s.type}
                                    </span>
                                    <span className="text-[10px] text-muted-foreground">
                                      {formatFileSize(s.size)}
                                    </span>
                                    {s.is_pe && (
                                      <span className="rounded bg-blue-500/20 px-1 py-0.5 text-[9px] font-bold text-blue-300">
                                        EXECUTABLE
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Actions */}
                          <div className="flex items-center gap-2 pt-1">
                            {m.has_pe32 && m.pe32_path && (
                              <a
                                href={getFileDownloadUrl(projectId, '/' + m.pe32_path)}
                                download
                                className="inline-flex items-center gap-1 rounded bg-blue-600 px-2 py-1 text-[10px] font-medium text-white hover:bg-blue-500"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <Download className="h-3 w-3" />
                                Download PE32+
                              </a>
                            )}
                            <span className="text-[10px] text-muted-foreground">
                              {m.checksum_valid ? '✓ Checksum valid' : '✗ Checksum invalid'}
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="flex items-center justify-center p-8 text-sm text-muted-foreground">
            No modules match the filter.
          </div>
        )}
      </div>
    </div>
  )
}
