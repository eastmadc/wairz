import { useEffect, useMemo, useState } from 'react'
import {
  Background,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { AlertTriangle, Loader2, Network } from 'lucide-react'
import {
  getFirmwareEdges,
  type FirmwareEdge,
  type FirmwareEdgesResponse,
} from '@/api/hardwareFirmware'
import { extractErrorMessage } from '@/utils/error'
import { displayPath } from './BlobTable'

interface DriverGraphProps {
  projectId: string
  firmwareId: string | null
}

// Node dimensions used for the simple two-column grid layout.
const NODE_WIDTH = 240
const NODE_HEIGHT = 40
const COLUMN_GAP = 360
const ROW_GAP = 60

// Exhaustive style map keyed by the `source` field on an edge (CLAUDE.md
// rule 9).  Fallback to a neutral style if a backend value is missing.
const EDGE_STYLE: Record<string, { stroke: string; dash?: string }> = {
  kmod_modinfo: { stroke: '#3b82f6' },
  vmlinux_strings: { stroke: '#a855f7', dash: '4 3' },
  dtb_firmware_name: { stroke: '#22c55e', dash: '2 2' },
  unresolved: { stroke: '#ef4444', dash: '2 2' },
}

function miniMapNodeColor(node: Node): string {
  const kind = (node.data as { kind?: string }).kind
  if (kind === 'driver') return '#3b82f6'
  if (kind === 'firmware') return '#22c55e'
  if (kind === 'unresolved') return '#ef4444'
  return '#6b7280'
}

// Build ReactFlow nodes + edges from the FirmwareEdgesResponse.  Drivers
// are placed in the left column; firmware blobs (resolved + unresolved)
// in the right column.  Layout is a simple vertical grid — no external
// layout lib required (per the spec).
function toFlowGraph(
  edges: FirmwareEdge[],
): { nodes: Node[]; flowEdges: Edge[] } {
  // Canonical sets, ordered so the layout is stable across renders.
  const drivers = new Map<string, string>() // id -> label
  const firmwareBlobs = new Map<
    string,
    { id: string; label: string; resolved: boolean }
  >()

  for (const e of edges) {
    const driverId = `driver::${e.driver_path}`
    if (!drivers.has(driverId)) {
      drivers.set(driverId, displayPath(e.driver_path))
    }

    const fwKey = e.firmware_blob_path ?? e.firmware_name
    const fwId = `fw::${fwKey}`
    if (!firmwareBlobs.has(fwId)) {
      firmwareBlobs.set(fwId, {
        id: fwId,
        label: e.firmware_blob_path
          ? displayPath(e.firmware_blob_path)
          : e.firmware_name,
        resolved: !!e.firmware_blob_path,
      })
    }
  }

  // Sort keys so the layout is deterministic.
  const sortedDrivers = [...drivers.entries()].sort((a, b) =>
    a[1].localeCompare(b[1]),
  )
  const sortedFirmware = [...firmwareBlobs.values()].sort((a, b) =>
    a.label.localeCompare(b.label),
  )

  const driverNodes: Node[] = sortedDrivers.map(([id, label], i) => ({
    id,
    type: 'default',
    position: { x: 0, y: i * ROW_GAP },
    data: { label, kind: 'driver' },
    style: {
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      fontSize: 11,
      borderRadius: 6,
      border: '1px solid rgb(59 130 246 / 0.5)',
      background: 'rgb(59 130 246 / 0.08)',
    },
  }))

  const firmwareNodes: Node[] = sortedFirmware.map((fw, i) => ({
    id: fw.id,
    type: 'default',
    position: { x: COLUMN_GAP, y: i * ROW_GAP },
    data: {
      label: fw.label,
      kind: fw.resolved ? 'firmware' : 'unresolved',
    },
    style: {
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      fontSize: 11,
      borderRadius: 6,
      border: fw.resolved
        ? '1px solid rgb(34 197 94 / 0.5)'
        : '1px solid rgb(239 68 68 / 0.5)',
      background: fw.resolved
        ? 'rgb(34 197 94 / 0.08)'
        : 'rgb(239 68 68 / 0.08)',
    },
  }))

  const seen = new Set<string>()
  const flowEdges: Edge[] = []
  for (const e of edges) {
    const driverId = `driver::${e.driver_path}`
    const fwKey = e.firmware_blob_path ?? e.firmware_name
    const fwId = `fw::${fwKey}`
    const edgeId = `${driverId}__${fwId}__${e.source}`
    if (seen.has(edgeId)) continue
    seen.add(edgeId)
    const styleKey = e.firmware_blob_path ? e.source : 'unresolved'
    const style = EDGE_STYLE[styleKey] ?? EDGE_STYLE.unresolved
    flowEdges.push({
      id: edgeId,
      source: driverId,
      target: fwId,
      style: {
        stroke: style.stroke,
        strokeDasharray: style.dash,
        strokeWidth: 1.5,
      },
      label: e.source,
      labelStyle: { fontSize: 9, fill: '#6b7280' },
      labelBgPadding: [2, 1],
      labelBgBorderRadius: 2,
    })
  }

  return {
    nodes: [...driverNodes, ...firmwareNodes],
    flowEdges,
  }
}

function DriverGraphInner({ projectId, firmwareId }: DriverGraphProps) {
  const [data, setData] = useState<FirmwareEdgesResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    getFirmwareEdges(projectId, firmwareId)
      .then((resp) => {
        if (!cancelled) setData(resp)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(extractErrorMessage(err, 'Failed to load firmware edges'))
          setData(null)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId, firmwareId])

  const { nodes, flowEdges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], flowEdges: [] as Edge[] }
    return toFlowGraph(data.edges)
  }, [data])

  if (loading) {
    return (
      <div className="flex h-[500px] items-center justify-center rounded-md border border-border text-sm text-muted-foreground">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        Loading driver graph...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>{error}</span>
      </div>
    )
  }

  if (!data || data.edges.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border p-10 text-center text-sm text-muted-foreground">
        <Network className="h-6 w-6" />
        <p>No driver -&gt; firmware links detected.</p>
        <p className="text-xs">
          Load a firmware image with kernel modules, DTBs, or a vmlinux to
          populate this view.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span>
          <span className="font-semibold">{data.edges.length}</span> edge
          {data.edges.length === 1 ? '' : 's'}
        </span>
        <span>
          <span className="font-semibold">{data.kmod_drivers}</span> kmod
          driver{data.kmod_drivers === 1 ? '' : 's'}
        </span>
        <span>
          <span className="font-semibold">{data.dtb_sources}</span> DTB
          source{data.dtb_sources === 1 ? '' : 's'}
        </span>
        {data.unresolved_count > 0 && (
          <span className="text-red-500">
            <span className="font-semibold">{data.unresolved_count}</span>{' '}
            unresolved
          </span>
        )}
      </div>

      <div className="h-[600px] overflow-hidden rounded-md border border-border">
        <ReactFlow
          nodes={nodes}
          edges={flowEdges}
          fitView
          fitViewOptions={{ padding: 0.1 }}
          minZoom={0.1}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={true}
          className="bg-background"
        >
          <Background gap={20} size={1} />
          <MiniMap
            nodeColor={miniMapNodeColor}
            maskColor="rgba(0,0,0,0.6)"
            className="!bottom-3 !right-3 !rounded-md !border !border-border !bg-background/80"
            pannable
            zoomable
          />
        </ReactFlow>
      </div>
    </div>
  )
}

export default function DriverGraph(props: DriverGraphProps) {
  return (
    <ReactFlowProvider>
      <DriverGraphInner {...props} />
    </ReactFlowProvider>
  )
}
