import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

interface BlobFiltersProps {
  categories: string[]
  vendors: string[]
  category: string | null
  vendor: string | null
  signedOnly: boolean
  onCategory: (v: string | null) => void
  onVendor: (v: string | null) => void
  onSignedOnly: (v: boolean) => void
}

export default function BlobFilters({
  categories,
  vendors,
  category,
  vendor,
  signedOnly,
  onCategory,
  onVendor,
  onSignedOnly,
}: BlobFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border pb-3">
      <div className="flex items-center gap-2">
        <Label htmlFor="hwfw-category" className="text-xs text-muted-foreground">
          Category
        </Label>
        <select
          id="hwfw-category"
          value={category ?? ''}
          onChange={(e) => onCategory(e.target.value || null)}
          className="h-8 rounded-md border bg-background px-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">All</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <Label htmlFor="hwfw-vendor" className="text-xs text-muted-foreground">
          Vendor
        </Label>
        <select
          id="hwfw-vendor"
          value={vendor ?? ''}
          onChange={(e) => onVendor(e.target.value || null)}
          className="h-8 rounded-md border bg-background px-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">All</option>
          {vendors.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox
          id="hwfw-signed-only"
          checked={signedOnly}
          onCheckedChange={(v) => onSignedOnly(v === true)}
        />
        <Label htmlFor="hwfw-signed-only" className="text-xs text-muted-foreground">
          Signed only
        </Label>
      </div>
    </div>
  )
}
