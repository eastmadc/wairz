import { useEffect } from 'react'
import { useProjectStore } from '@/stores/projectStore'
import type { FirmwareDetail } from '@/types'

export interface FirmwareListResult {
  firmwareList: FirmwareDetail[]
  loading: boolean
}

/**
 * Shared firmware-list subscription.  Replaces the
 *   const [firmwareList, setFirmwareList] = useState([])
 *   useEffect(() => { listFirmware(projectId).then(setFirmwareList) }, ...)
 * pattern that was duplicated across 9 pages — each copy issued its
 * own fetch on every route transition.
 *
 * The list is cached in projectStore, keyed by projectId.  Successive
 * callers within the same project get the cached array.  Upload /
 * delete paths invalidate via `invalidateFirmwareList()` so other
 * pages pick up changes on their next render.
 *
 * Returns an empty list (not stale data from a previous project)
 * until the new project's list has loaded, so consumers don't need
 * guard code against showing cross-project firmware.
 */
export function useFirmwareList(
  projectId: string | undefined,
): FirmwareListResult {
  const firmwareList = useProjectStore((s) => s.firmwareList)
  const listProjectId = useProjectStore((s) => s.firmwareListProjectId)
  const loading = useProjectStore((s) => s.firmwareListLoading)
  const load = useProjectStore((s) => s.loadFirmwareList)

  // Dep on listProjectId so an invalidation (store sets it to null)
  // causes this effect to re-fire and refetch.  Without that dep,
  // invalidation would clear the cache but no consumer would reload
  // until the next projectId change.
  useEffect(() => {
    if (projectId && listProjectId !== projectId) {
      load(projectId)
    }
  }, [projectId, listProjectId, load])

  const matches = listProjectId === projectId
  return {
    firmwareList: matches ? firmwareList : [],
    loading: !matches || loading,
  }
}
