import { useState } from 'react'
import {
  ExternalLink,
  Globe,
  Terminal,
  Network,
  Shield,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { FirmwareService } from '@/types'

const SERVICE_ICONS: Record<string, typeof Globe> = {
  http: Globe,
  https: Globe,
  ssh: Terminal,
  telnet: Terminal,
  ftp: Shield,
}

function getServiceIcon(service: string) {
  const lower = service.toLowerCase()
  for (const [key, Icon] of Object.entries(SERVICE_ICONS)) {
    if (lower.includes(key)) return Icon
  }
  return Network
}

function getProtocolBadgeClass(protocol: string): string {
  switch (protocol.toLowerCase()) {
    case 'tcp':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/30'
    case 'udp':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30'
    default:
      return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30'
  }
}

export interface FirmwareServicesPanelProps {
  services: FirmwareService[]
  firmwareIp: string | null
  onConnectTerminal?: (port: number) => void
}

export function FirmwareServicesPanel({
  services,
  firmwareIp,
  onConnectTerminal,
}: FirmwareServicesPanelProps) {
  const [filter, setFilter] = useState<string>('')

  const filtered = filter
    ? services.filter(
        (s) =>
          s.service.toLowerCase().includes(filter.toLowerCase()) ||
          s.protocol.toLowerCase().includes(filter.toLowerCase()) ||
          String(s.port).includes(filter),
      )
    : services

  const isInteractiveService = (service: string): boolean => {
    const lower = service.toLowerCase()
    return lower.includes('ssh') || lower.includes('telnet') || lower.includes('shell')
  }

  const isHttpService = (service: string): boolean => {
    const lower = service.toLowerCase()
    return lower.includes('http') || lower.includes('web') || lower.includes('www')
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-foreground">
            Discovered Services
          </h3>
          <Badge variant="outline" className="text-[10px]">
            {services.length}
          </Badge>
        </div>
        {firmwareIp && (
          <span className="text-xs text-muted-foreground font-mono">
            {firmwareIp}
          </span>
        )}
      </div>

      {services.length > 3 && (
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter services..."
          className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs focus:border-primary focus:outline-none"
        />
      )}

      {filtered.length === 0 ? (
        <p className="text-xs text-muted-foreground/60 py-2">
          {services.length === 0
            ? 'No network services discovered yet'
            : 'No services match the filter'}
        </p>
      ) : (
        <div className="space-y-1.5">
          {filtered.map((svc) => {
            const Icon = getServiceIcon(svc.service)
            return (
              <div
                key={`${svc.protocol}-${svc.port}`}
                className="flex items-center gap-2 rounded-md border border-border px-3 py-2 hover:border-border/80 transition-colors"
              >
                <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">
                      {svc.service}
                    </span>
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${getProtocolBadgeClass(svc.protocol)}`}
                    >
                      {svc.protocol.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="text-[10px] text-muted-foreground font-mono">
                    :{svc.port}
                    {svc.host_port != null && (
                      <span className="ml-1">
                        (host :{svc.host_port})
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {isHttpService(svc.service) && svc.host_port != null && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-[10px]"
                      onClick={() =>
                        window.open(
                          svc.url || `http://localhost:${svc.host_port}`,
                          '_blank',
                        )
                      }
                      title="Open in browser"
                    >
                      <ExternalLink className="mr-1 h-3 w-3" />
                      Open
                    </Button>
                  )}
                  {isInteractiveService(svc.service) && onConnectTerminal && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[10px]"
                      onClick={() => onConnectTerminal(svc.port)}
                      title="Connect via terminal"
                    >
                      <Terminal className="mr-1 h-3 w-3" />
                      Connect
                    </Button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
