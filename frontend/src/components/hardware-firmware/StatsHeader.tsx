import { Cpu, ShieldAlert, Factory, Bug } from 'lucide-react'

interface StatsHeaderProps {
  totalBlobs: number
  notSignedCount: number  // unsigned + unknown + weakly_signed
  vendorCount: number
  // Firmware-wide CVE count from GET /cve-aggregate (persisted in DB,
  // doesn't require running the matcher every page load).
  hardwareCveCount: number
  // Per-blob CVE count for the currently-selected blob (or undefined
  // when no blob is selected).  Rendered as a sub-line under the
  // hardware CVE total.
  selectedBlobCveCount?: number
  // Advisory count (ADVISORY-* presence flags) — rendered as a small
  // chip next to the headline total when > 0.
  advisoryCount: number
}

export default function StatsHeader({
  totalBlobs,
  notSignedCount,
  vendorCount,
  hardwareCveCount,
  selectedBlobCveCount,
  advisoryCount,
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
        label="Not signed"
        hint="unsigned / unknown / weakly"
        value={notSignedCount}
        alert={notSignedCount > 0}
      />
      <StatCard
        icon={<Factory className="h-4 w-4 text-muted-foreground" />}
        label="Vendors"
        value={vendorCount}
      />
      <StatCard
        icon={<Bug className="h-4 w-4 text-muted-foreground" />}
        label="Hardware CVEs"
        hint={
          selectedBlobCveCount !== undefined
            ? `${selectedBlobCveCount} on selected blob`
            : 'firmware-wide (parser + curated + chipset tiers)'
        }
        value={hardwareCveCount}
        alert={hardwareCveCount > 0}
        chip={advisoryCount > 0 ? `+${advisoryCount} advisory` : undefined}
      />
    </div>
  )
}

function StatCard({
  icon,
  label,
  hint,
  value,
  alert,
  chip,
}: {
  icon: React.ReactNode
  label: string
  hint?: string
  value: number
  alert?: boolean
  chip?: string
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
      <div className="mt-1 flex items-baseline gap-2">
        <p className={`text-2xl font-bold ${alert ? 'text-red-500' : ''}`}>{value}</p>
        {chip && (
          <span className="text-[10px] text-amber-600 dark:text-amber-400">
            {chip}
          </span>
        )}
      </div>
      {hint && <p className="text-[10px] text-muted-foreground/70">{hint}</p>}
    </div>
  )
}
