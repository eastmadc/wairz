import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  AlertTriangle,
  Cpu,
  Download,
  Loader2,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  getFirmwareDrivers,
  getHardwareFirmwareBlob,
  getHardwareFirmwareCves,
  listHardwareFirmware,
  runCveMatch,
  type FirmwareCveMatch,
  type FirmwareDriver,
  type HardwareFirmwareBlob,
} from '@/api/hardwareFirmware'
import { listFirmware } from '@/api/firmware'
import { useProjectStore } from '@/stores/projectStore'
import { extractErrorMessage } from '@/utils/error'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import StatsHeader from '@/components/hardware-firmware/StatsHeader'
import BlobFilters from '@/components/hardware-firmware/BlobFilters'
import BlobTable from '@/components/hardware-firmware/BlobTable'
import BlobDetail from '@/components/hardware-firmware/BlobDetail'
import DriversTable from '@/components/hardware-firmware/DriversTable'
import PartitionTree from '@/components/hardware-firmware/PartitionTree'
import DriverGraph from '@/components/hardware-firmware/DriverGraph'
import type { FirmwareDetail } from '@/types'

export default function HardwareFirmwarePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)

  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [blobs, setBlobs] = useState<HardwareFirmwareBlob[]>([])
  const [drivers, setDrivers] = useState<FirmwareDriver[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [category, setCategory] = useState<string | null>(null)
  const [vendor, setVendor] = useState<string | null>(null)
  const [signedOnly, setSignedOnly] = useState(false)
  const [hideKernelModules, setHideKernelModules] = useState(true)
  const [dedupeBySha, setDedupeBySha] = useState(true)

  const [selectedBlobId, setSelectedBlobId] = useState<string | null>(null)
  const [blobDetail, setBlobDetail] = useState<HardwareFirmwareBlob | null>(null)
  const [blobCves, setBlobCves] = useState<FirmwareCveMatch[]>([])
  const [cveLoading, setCveLoading] = useState(false)

  const [running, setRunning] = useState(false)
  const [runResult, setRunResult] = useState<string | null>(null)

  // Load firmware list for selector
  useEffect(() => {
    if (projectId) {
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    }
  }, [projectId])

  // Load blobs + drivers whenever project / firmware / filters change
  const loadAll = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setError(null)
    try {
      const [blobsResp, driversResp] = await Promise.all([
        listHardwareFirmware(projectId, {
          firmwareId: selectedFirmwareId,
          category: category ?? undefined,
          vendor: vendor ?? undefined,
          signedOnly,
        }),
        getFirmwareDrivers(projectId, selectedFirmwareId).catch(() => ({
          drivers: [] as FirmwareDriver[],
          total: 0,
        })),
      ])
      setBlobs(blobsResp.blobs)
      setDrivers(driversResp.drivers)
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load hardware firmware data'))
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedFirmwareId, category, vendor, signedOnly])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  // Load detail + CVEs when a blob is selected
  useEffect(() => {
    if (!projectId || !selectedBlobId) {
      setBlobDetail(null)
      setBlobCves([])
      return
    }
    let cancelled = false
    setCveLoading(true)
    Promise.all([
      getHardwareFirmwareBlob(projectId, selectedBlobId, selectedFirmwareId),
      getHardwareFirmwareCves(projectId, selectedBlobId, selectedFirmwareId).catch(
        () => [] as FirmwareCveMatch[],
      ),
    ])
      .then(([blob, cves]) => {
        if (cancelled) return
        setBlobDetail(blob)
        setBlobCves(cves)
      })
      .catch((err) => {
        if (cancelled) return
        setBlobDetail(null)
        setBlobCves([])
        setError(extractErrorMessage(err, 'Failed to load blob detail'))
      })
      .finally(() => {
        if (!cancelled) setCveLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId, selectedBlobId, selectedFirmwareId])

  const handleRunCveMatch = useCallback(async () => {
    if (!projectId) return
    setRunning(true)
    setRunResult(null)
    try {
      const res = await runCveMatch(projectId, {
        forceRescan: false,
        firmwareId: selectedFirmwareId,
      })
      {
        const distinct = res.count ?? 0
        const hwfw = res.hw_firmware_cves ?? distinct
        const kernel = res.kernel_cves ?? 0
        const kmodRows = res.kernel_module_rows ?? 0
        const parts: string[] = []
        if (hwfw > 0) parts.push(`${hwfw} hw-firmware`)
        if (kernel > 0) parts.push(`${kernel} kernel (across ${kmodRows} modules)`)
        const breakdown = parts.length ? ` — ${parts.join(', ')}` : ''
        setRunResult(`Found ${distinct} distinct CVE(s)${breakdown}.`)
      }
      // Refresh the list and any selected blob's CVEs.
      await loadAll()
      if (selectedBlobId) {
        const cves = await getHardwareFirmwareCves(
          projectId,
          selectedBlobId,
          selectedFirmwareId,
        ).catch(() => [] as FirmwareCveMatch[])
        setBlobCves(cves)
      }
    } catch (err) {
      setError(extractErrorMessage(err, 'CVE matcher failed'))
    } finally {
      setRunning(false)
    }
  }, [projectId, selectedFirmwareId, selectedBlobId, loadAll])

  // Client-side filtering — apply kernel-module hide + sha dedup on top of
  // the server's category/vendor/signed filters.
  const visibleBlobs = useMemo(() => {
    let list = blobs
    if (hideKernelModules) {
      list = list.filter((b) => b.category !== 'kernel_module')
    }
    if (dedupeBySha) {
      const seen = new Set<string>()
      list = list.filter((b) => {
        if (seen.has(b.blob_sha256)) return false
        seen.add(b.blob_sha256)
        return true
      })
    }
    return list
  }, [blobs, hideKernelModules, dedupeBySha])

  // Derived values (from the POST-FILTER list so stats match what the user sees)
  const totalBlobs = visibleBlobs.length
  const kernelModuleCount = useMemo(
    () => blobs.filter((b) => b.category === 'kernel_module').length,
    [blobs],
  )
  const hiddenDupCount = blobs.length - visibleBlobs.length - (hideKernelModules ? kernelModuleCount : 0)
  const notSignedCount = useMemo(
    () =>
      visibleBlobs.filter(
        (b) => b.signed === 'unsigned' || b.signed === 'weakly_signed' || b.signed === 'unknown',
      ).length,
    [visibleBlobs],
  )
  const vendorCount = useMemo(() => {
    const set = new Set<string>()
    for (const b of visibleBlobs) {
      if (b.vendor) set.add(b.vendor)
    }
    return set.size
  }, [visibleBlobs])
  const cveCount = blobCves.length

  const categories = useMemo(() => {
    const set = new Set<string>()
    for (const b of blobs) set.add(b.category)
    return [...set].sort()
  }, [blobs])

  const vendors = useMemo(() => {
    const set = new Set<string>()
    for (const b of blobs) {
      if (b.vendor) set.add(b.vendor)
    }
    return [...set].sort()
  }, [blobs])

  // Build the HBOM download URL.  The endpoint streams JSON directly, so
  // an anchor tag with `download` lets the browser save it without a
  // blob-URL round-trip through axios.
  const hbomUrl = useMemo(() => {
    if (!projectId) return '#'
    const base = `/api/v1/projects/${projectId}/hardware-firmware/cdx.json`
    return selectedFirmwareId
      ? `${base}?firmware_id=${encodeURIComponent(selectedFirmwareId)}`
      : base
  }, [projectId, selectedFirmwareId])

  if (!projectId) {
    return null
  }

  if (loading && blobs.length === 0) {
    return (
      <div className="flex h-[calc(100vh-8rem)] items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        <span className="text-sm">Loading hardware firmware...</span>
      </div>
    )
  }

  const hasData = totalBlobs > 0

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <Cpu className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-lg font-semibold">Hardware Firmware</h1>
            <p className="text-sm text-muted-foreground">
              Modem / TEE / Wi-Fi / GPU / DSP blobs, drivers, and three-tier CVE matches.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <FirmwareSelector projectId={projectId} firmwareList={firmwareList} />
          <Button
            variant="outline"
            size="sm"
            onClick={handleRunCveMatch}
            disabled={running || !hasData}
          >
            {running ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            )}
            Run CVE match
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasData}
            asChild
            title="Download CycloneDX v1.6 HBOM"
          >
            <a
              href={hbomUrl}
              download={`hbom-${selectedFirmwareId ?? projectId}.cdx.json`}
            >
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export HBOM
            </a>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={loadAll}
            disabled={loading}
            title="Reload blobs and drivers"
          >
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {runResult && (
        <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs">
          {runResult}
        </div>
      )}

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!hasData ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border p-10 text-center text-sm text-muted-foreground">
          <Cpu className="h-6 w-6 text-muted-foreground" />
          <p>No hardware firmware detected.</p>
          <p className="text-xs">
            Upload an Android firmware image to trigger automatic detection.
          </p>
        </div>
      ) : (
        <>
          <StatsHeader
            totalBlobs={totalBlobs}
            notSignedCount={notSignedCount}
            vendorCount={vendorCount}
            cveCount={cveCount}
          />

          <div className="space-y-3">
            <BlobFilters
              categories={categories}
              vendors={vendors}
              category={category}
              vendor={vendor}
              signedOnly={signedOnly}
              onCategory={setCategory}
              onVendor={setVendor}
              onSignedOnly={setSignedOnly}
            />
            <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={hideKernelModules}
                  onChange={(e) => setHideKernelModules(e.target.checked)}
                  className="h-3.5 w-3.5"
                />
                <span>
                  Hide kernel modules
                  {kernelModuleCount > 0 && (
                    <span className="ml-1 opacity-70">({kernelModuleCount})</span>
                  )}
                </span>
              </label>
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={dedupeBySha}
                  onChange={(e) => setDedupeBySha(e.target.checked)}
                  className="h-3.5 w-3.5"
                />
                <span>
                  Dedupe by SHA-256
                  {hiddenDupCount > 0 && (
                    <span className="ml-1 opacity-70">({hiddenDupCount} hidden)</span>
                  )}
                </span>
              </label>
            </div>
          </div>

          <Tabs defaultValue="tree" className="w-full">
            <TabsList>
              <TabsTrigger value="tree">Tree ({totalBlobs})</TabsTrigger>
              <TabsTrigger value="blobs">Flat table ({totalBlobs})</TabsTrigger>
              <TabsTrigger value="drivers">Drivers ({drivers.length})</TabsTrigger>
              <TabsTrigger value="graph">Driver graph</TabsTrigger>
            </TabsList>

            <TabsContent value="tree" className="pt-3">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_minmax(360px,440px)]">
                <PartitionTree
                  blobs={visibleBlobs}
                  selectedId={selectedBlobId}
                  onSelect={setSelectedBlobId}
                />
                <BlobDetail blob={blobDetail} cves={blobCves} loading={cveLoading} />
              </div>
            </TabsContent>

            <TabsContent value="blobs" className="pt-3">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_minmax(360px,440px)]">
                <BlobTable
                  blobs={visibleBlobs}
                  selectedId={selectedBlobId}
                  onSelect={setSelectedBlobId}
                />
                <BlobDetail blob={blobDetail} cves={blobCves} loading={cveLoading} />
              </div>
            </TabsContent>

            <TabsContent value="drivers" className="pt-3">
              <DriversTable drivers={drivers} />
            </TabsContent>

            <TabsContent value="graph" className="pt-3">
              <DriverGraph projectId={projectId} firmwareId={selectedFirmwareId} />
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  )
}
