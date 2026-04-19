import { useEffect, type ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { useExplorerStore } from '@/stores/explorerStore'
import { useVulnerabilityStore } from '@/stores/vulnerabilityStore'
import { useProjectStore } from '@/stores/projectStore'

/**
 * Wraps `/projects/:projectId/*` routes and resets project-scoped stores on
 * projectId change. Complements the `currentProjectId` guards inside each
 * store: the guards prevent late A-scoped responses from clobbering B-state;
 * this component proactively clears A-state the instant the route changes.
 *
 * Needed because URL-only navigation between sibling project routes (e.g.
 * /projects/A/explore → /projects/B/explore) does NOT unmount the child
 * page — React Router rehydrates the same component tree with new params.
 * The per-page `useEffect` cleanup that used to call `resetExplorer()`
 * fires only on actual unmount, never on URL change.
 */
export default function ProjectRouteGuard({ children }: { children: ReactNode }) {
  const { projectId } = useParams<{ projectId: string }>()
  const resetExplorer = useExplorerStore((s) => s.reset)
  const resetVulnerabilities = useVulnerabilityStore((s) => s.reset)
  const clearCurrent = useProjectStore((s) => s.clearCurrentProject)

  useEffect(() => {
    // Cleanup runs when projectId changes (React re-runs the effect) or on
    // unmount. Both are moments where the previously-hydrated stores should
    // be dropped so the next project's mount starts from a clean slate.
    return () => {
      resetExplorer()
      resetVulnerabilities()
      clearCurrent()
    }
  }, [projectId, resetExplorer, resetVulnerabilities, clearCurrent])

  return <>{children}</>
}
