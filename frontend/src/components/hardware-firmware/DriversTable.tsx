import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import type { FirmwareDriver } from '@/api/hardwareFirmware'

interface DriversTableProps {
  drivers: FirmwareDriver[]
}

export default function DriversTable({ drivers }: DriversTableProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  if (drivers.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No drivers requesting firmware were detected.
      </div>
    )
  }

  const toggle = (path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground">
            <th className="py-2 pr-3 w-6"></th>
            <th className="py-2 pr-3 font-medium">Driver</th>
            <th className="py-2 pr-3 font-medium">Format</th>
            <th className="py-2 pr-3 font-medium text-right">Resolved</th>
            <th className="py-2 pr-3 font-medium text-right">Unresolved</th>
          </tr>
        </thead>
        <tbody>
          {drivers.map((d) => {
            const isOpen = expanded.has(d.driver_path)
            const resolvedCount = d.firmware_blobs.length
            const unresolvedCount = Math.max(0, d.total - resolvedCount)
            return (
              <Fragment key={d.driver_path}>
                <tr
                  className="cursor-pointer border-b border-border/50 hover:bg-accent/30"
                  onClick={() => toggle(d.driver_path)}
                >
                  <td className="py-1.5 pr-3">
                    {isOpen ? (
                      <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                    )}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-[11px]" title={d.driver_path}>
                    <div className="max-w-[320px] truncate">{d.driver_path}</div>
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-[11px]">{d.format}</td>
                  <td className="py-1.5 pr-3 text-right">
                    <Badge
                      variant="outline"
                      className="border-green-500/40 text-green-600 text-[10px] dark:text-green-400"
                    >
                      {resolvedCount}
                    </Badge>
                  </td>
                  <td className="py-1.5 pr-3 text-right">
                    {unresolvedCount > 0 ? (
                      <Badge
                        variant="outline"
                        className="border-red-500/40 text-red-600 text-[10px] dark:text-red-400"
                      >
                        {unresolvedCount}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-border/50">
                    <td></td>
                    <td colSpan={4} className="py-2 pr-3">
                      <div className="space-y-1 pl-2">
                        {d.firmware_deps.length === 0 ? (
                          <p className="text-[11px] italic text-muted-foreground">
                            No firmware dependencies recorded.
                          </p>
                        ) : (
                          d.firmware_deps.map((dep, idx) => {
                            const resolved = d.firmware_blobs[idx]
                            return (
                              <div
                                key={`${d.driver_path}-${dep}-${idx}`}
                                className="flex items-start gap-2 text-[11px]"
                              >
                                <span className="font-mono">{dep}</span>
                                {resolved ? (
                                  <Badge
                                    variant="outline"
                                    className="border-green-500/40 text-green-600 text-[9px] dark:text-green-400"
                                  >
                                    resolved
                                  </Badge>
                                ) : (
                                  <Badge
                                    variant="outline"
                                    className="border-red-500/40 text-red-600 text-[9px] dark:text-red-400"
                                  >
                                    missing
                                  </Badge>
                                )}
                              </div>
                            )
                          })
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
