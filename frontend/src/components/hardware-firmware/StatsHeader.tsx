import { Cpu, ShieldAlert, Factory, Bug } from 'lucide-react'

interface StatsHeaderProps {
  totalBlobs: number
  unsignedCount: number
  vendorCount: number
  cveCount: number
}

export default function StatsHeader({
  totalBlobs,
  unsignedCount,
  vendorCount,
  cveCount,
}: StatsHeaderProps) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <StatCard
        icon={<Cpu className="h-4 w-4 text-muted-foreground" />}
        label="Total blobs"
        value={totalBlobs}
      />
      <StatCard
        icon={<ShieldAlert className="h-4 w-4 text-muted-foreground" />}
        label="Unsigned"
        value={unsignedCount}
        alert={unsignedCount > 0}
      />
      <StatCard
        icon={<Factory className="h-4 w-4 text-muted-foreground" />}
        label="Vendors"
        value={vendorCount}
      />
      <StatCard
        icon={<Bug className="h-4 w-4 text-muted-foreground" />}
        label="CVEs (selected)"
        value={cveCount}
        alert={cveCount > 0}
      />
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  alert,
}: {
  icon: React.ReactNode
  label: string
  value: number
  alert?: boolean
}) {
  return (
    <div
      className={`rounded-lg border p-3 ${
        alert ? 'border-red-500/30 bg-red-500/5' : 'border-border'
      }`}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <p className={`mt-1 text-2xl font-bold ${alert ? 'text-red-500' : ''}`}>{value}</p>
    </div>
  )
}
