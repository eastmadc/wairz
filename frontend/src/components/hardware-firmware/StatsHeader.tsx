import { Cpu, ShieldAlert, Factory, Bug, Boxes } from 'lucide-react'

interface StatsHeaderProps {
  totalBlobs: number
  notSignedCount: number  // unsigned + unknown + weakly_signed
  vendorCount: number
  // Firmware-wide hw-firmware CVE count from GET /cve-aggregate (persisted
  // in DB, doesn't require running the matcher every page load).
  hardwareCveCount: number
  // Firmware-wide kernel-tier CVE count (kernel_cpe + kernel_subsystem).
  // Surfaced as its own card so the 400+ kernel-module CVEs aren't
  // invisible behind a single "Hardware CVEs" number.
  kernelCveCount: number
  // Per-blob CVE count for the currently-selected blob (or undefined
  // when no blob is selected).  Rendered as a sub-line under the
  // hardware CVE total.
  selectedBlobCveCount?: number
  // Advisory count (ADVISORY-* presence flags) — rendered as a small
  // chip next to the headline total when > 0.
  advisoryCount: number
  // Per-severity breakdown of the hardware-firmware CVE count.  All
  // four default to 0 when the backend doesn't populate them (older
  // response payloads).
  severityCritical: number
  severityHigh: number
  severityMedium: number
  severityLow: number
  // Cards are clickable so the user can drill in.  Undefined handlers
  // render a static (non-interactive) card.
  onHardwareCvesClick?: () => void
  onKernelCvesClick?: () => void
  onNotSignedClick?: () => void
  // True when the current page filter corresponds to that card, so it
  // renders in an active state.
  hardwareCvesActive?: boolean
  kernelCvesActive?: boolean
  notSignedActive?: boolean
}

export default function StatsHeader({
  totalBlobs,
  notSignedCount,
  vendorCount,
  hardwareCveCount,
  kernelCveCount,
  selectedBlobCveCount,
  advisoryCount,
  severityCritical,
  severityHigh,
  severityMedium,
  severityLow,
  onHardwareCvesClick,
  onKernelCvesClick,
  onNotSignedClick,
  hardwareCvesActive,
  kernelCvesActive,
  notSignedActive,
}: StatsHeaderProps) {
  const severityParts: string[] = []
  if (severityCritical > 0) severityParts.push(`${severityCritical} crit`)
  if (severityHigh > 0) severityParts.push(`${severityHigh} high`)
  if (severityMedium > 0) severityParts.push(`${severityMedium} med`)
  if (severityLow > 0) severityParts.push(`${severityLow} low`)
  const severitySummary = severityParts.length
    ? severityParts.join(' · ')
    : selectedBlobCveCount !== undefined
      ? `${selectedBlobCveCount} on selected blob`
      : 'firmware-wide (parser + curated + chipset tiers)'

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
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
        onClick={notSignedCount > 0 ? onNotSignedClick : undefined}
        active={notSignedActive}
      />
      <StatCard
        icon={<Factory className="h-4 w-4 text-muted-foreground" />}
        label="Vendors"
        value={vendorCount}
      />
      <StatCard
        icon={<Bug className="h-4 w-4 text-muted-foreground" />}
        label="Hardware CVEs"
        hint={severitySummary}
        value={hardwareCveCount}
        alert={hardwareCveCount > 0}
        chip={advisoryCount > 0 ? `+${advisoryCount} advisory` : undefined}
        onClick={hardwareCveCount > 0 ? onHardwareCvesClick : undefined}
        active={hardwareCvesActive}
      />
      <StatCard
        icon={<Boxes className="h-4 w-4 text-muted-foreground" />}
        label="Kernel CVEs"
        hint="kernel_module CPE + subsystem tiers"
        value={kernelCveCount}
        alert={kernelCveCount > 0}
        onClick={kernelCveCount > 0 ? onKernelCvesClick : undefined}
        active={kernelCvesActive}
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
  onClick,
  active,
}: {
  icon: React.ReactNode
  label: string
  hint?: string
  value: number
  alert?: boolean
  chip?: string
  onClick?: () => void
  active?: boolean
}) {
  const interactive = !!onClick
  const base = `rounded-lg border p-3 text-left transition-colors ${
    interactive ? 'cursor-pointer hover:bg-accent/40' : ''
  }`
  const tone = active
    ? 'border-primary/60 bg-primary/5'
    : alert
      ? 'border-red-500/30 bg-red-500/5'
      : 'border-border'
  const Tag: 'button' | 'div' = interactive ? 'button' : 'div'
  return (
    <Tag
      type={interactive ? 'button' : undefined}
      onClick={onClick}
      aria-pressed={interactive ? !!active : undefined}
      className={`${base} ${tone} ${interactive ? 'w-full' : ''}`}
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
    </Tag>
  )
}
