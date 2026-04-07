import { Badge } from '@/components/ui/badge'
import type { ToolInfo } from '@/api/tools'

const CATEGORY_COLORS: Record<string, string> = {
  'Security': 'bg-red-500/10 text-red-500',
  'Binary Analysis': 'bg-purple-500/10 text-purple-500',
  'SBOM & Vulnerabilities': 'bg-orange-500/10 text-orange-500',
  'Filesystem': 'bg-green-500/10 text-green-500',
  'Strings': 'bg-yellow-500/10 text-yellow-500',
  'Comparison': 'bg-cyan-500/10 text-cyan-500',
  'Emulation': 'bg-blue-500/10 text-blue-500',
  'Fuzzing': 'bg-pink-500/10 text-pink-500',
  'Reporting': 'bg-emerald-500/10 text-emerald-500',
  'Other': 'bg-gray-500/10 text-gray-500',
}

function formatToolName(name: string): string {
  return name
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

interface ToolCardProps {
  tool: ToolInfo
  isSelected: boolean
  category: string
  onClick: () => void
}

export default function ToolCard({ tool, isSelected, category, onClick }: ToolCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full text-left rounded-md px-3 py-2 transition-colors ${
        isSelected
          ? 'bg-accent ring-2 ring-primary text-accent-foreground'
          : 'hover:bg-muted/50'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-medium leading-tight">
          {formatToolName(tool.name)}
        </span>
        <Badge
          variant="ghost"
          className={`shrink-0 text-[10px] px-1.5 py-0 ${CATEGORY_COLORS[category] ?? CATEGORY_COLORS['Other']}`}
        >
          {category}
        </Badge>
      </div>
      {tool.description && (
        <p className="mt-0.5 text-xs text-muted-foreground line-clamp-1">
          {tool.description}
        </p>
      )}
    </button>
  )
}

export { CATEGORY_COLORS, formatToolName }
