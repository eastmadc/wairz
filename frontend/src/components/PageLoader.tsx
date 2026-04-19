import { Loader2 } from 'lucide-react'

/**
 * Suspense fallback for lazy-loaded route chunks.
 *
 * Kept deliberately light — this renders during the ~100-300ms window while
 * a per-route chunk is fetched on first visit. Matches the existing "loading"
 * visual vocabulary already used by FindingsPage / ProjectDetailPage etc.
 */
export default function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Loader2
        className="h-6 w-6 animate-spin text-muted-foreground"
        aria-label="Loading page"
      />
    </div>
  )
}
