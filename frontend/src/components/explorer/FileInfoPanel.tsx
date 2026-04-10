import { Loader2 } from 'lucide-react'
import { formatFileSize } from '@/utils/format'
import type { FileInfo } from '@/types'
import BinaryInfo from './BinaryInfo'

export default function FileInfoPanel({
  fileInfo,
  infoLoading,
}: {
  fileInfo: FileInfo | null
  infoLoading: boolean
}) {
  if (fileInfo) {
    return (
      <div className="space-y-4">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Path</dt>
          <dd className="font-mono break-all">{fileInfo.path}</dd>
          <dt className="text-muted-foreground">Type</dt>
          <dd>{fileInfo.type}</dd>
          <dt className="text-muted-foreground">MIME</dt>
          <dd>{fileInfo.mime_type}</dd>
          <dt className="text-muted-foreground">Size</dt>
          <dd>{formatFileSize(fileInfo.size)}</dd>
          <dt className="text-muted-foreground">Permissions</dt>
          <dd className="font-mono">{fileInfo.permissions}</dd>
          {fileInfo.sha256 && (
            <>
              <dt className="text-muted-foreground">SHA256</dt>
              <dd className="font-mono break-all">{fileInfo.sha256}</dd>
            </>
          )}
        </dl>
        {fileInfo.elf_info && <BinaryInfo fileInfo={fileInfo} />}
      </div>
    )
  }

  if (infoLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return <p className="text-sm text-muted-foreground">File info unavailable.</p>
}
