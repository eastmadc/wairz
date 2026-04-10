import { useState, useMemo } from 'react'
import { Loader2, AlertTriangle, Search } from 'lucide-react'
import type { FunctionInfo, ImportInfo } from '@/types'

export default function FunctionListPanel({
  functions,
  imports,
  loading,
  error,
  selectedFunction,
  onSelectFunction,
}: {
  functions: FunctionInfo[]
  imports: ImportInfo[]
  loading: boolean
  error: string | null
  selectedFunction: string | null
  onSelectFunction: (name: string) => void
}) {
  const [filter, setFilter] = useState('')

  // Build a lookup: function name -> library name from imports
  const importMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const imp of imports) {
      if (imp.name && imp.libname) {
        map.set(imp.name, imp.libname)
      }
    }
    return map
  }, [imports])

  const filtered = useMemo(() => {
    if (!filter) return functions
    const lower = filter.toLowerCase()
    return functions.filter((f) => {
      if (f.name.toLowerCase().includes(lower)) return true
      // Also match on library name
      const lib = importMap.get(f.name)
      if (lib && lib.toLowerCase().includes(lower)) return true
      return false
    })
  }, [functions, filter, importMap])

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Analyzing binary (this may take a few minutes for large binaries)…</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-3 px-4 text-center">
          <AlertTriangle className="h-6 w-6 text-yellow-500" />
          <p className="text-sm text-muted-foreground">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      {/* Search bar */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-2">
        <Search className="h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Filter functions…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
        <span className="text-xs text-muted-foreground">
          {filtered.length} / {functions.length}
        </span>
      </div>

      {/* Function list */}
      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <div className="p-4 text-center text-sm text-muted-foreground">
            {functions.length === 0 ? 'No functions found.' : 'No matches.'}
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-background">
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-4 py-1.5 font-medium">Function</th>
                <th className="px-4 py-1.5 font-medium">Imported From</th>
                <th className="px-4 py-1.5 font-medium text-right">Size</th>
                <th className="px-4 py-1.5 font-medium text-right">Address</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((fn) => {
                const lib = importMap.get(fn.name)
                return (
                  <tr
                    key={fn.name}
                    onClick={() => onSelectFunction(fn.name)}
                    className={`cursor-pointer border-b border-border/50 ${
                      fn.name === selectedFunction
                        ? 'bg-accent text-accent-foreground'
                        : 'hover:bg-accent/50'
                    }`}
                  >
                    <td className="px-4 py-1.5 font-mono">{fn.name}</td>
                    <td className="px-4 py-1.5 font-mono text-muted-foreground">
                      {lib ?? ''}
                    </td>
                    <td className="px-4 py-1.5 text-right text-muted-foreground">
                      {fn.size} B
                    </td>
                    <td className="px-4 py-1.5 text-right font-mono text-muted-foreground">
                      0x{fn.offset.toString(16).padStart(8, '0')}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
