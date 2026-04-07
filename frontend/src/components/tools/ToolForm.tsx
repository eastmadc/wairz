import { useState, useEffect } from 'react'
import { Loader2, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import type { ToolInfo } from '@/api/tools'

interface ToolFormProps {
  tool: ToolInfo
  onSubmit: (input: Record<string, unknown>) => void
  loading: boolean
}

interface SchemaProperty {
  type?: string
  description?: string
  enum?: string[]
  default?: unknown
}

export default function ToolForm({ tool, onSubmit, loading }: ToolFormProps) {
  const [values, setValues] = useState<Record<string, unknown>>({})

  const schema = tool.input_schema as {
    properties?: Record<string, SchemaProperty>
    required?: string[]
  }
  const properties = schema.properties ?? {}
  const required = new Set(schema.required ?? [])
  const fieldNames = Object.keys(properties)

  // Reset form values when tool changes
  useEffect(() => {
    const defaults: Record<string, unknown> = {}
    for (const [key, prop] of Object.entries(properties)) {
      if (prop.default !== undefined) {
        defaults[key] = prop.default
      } else if (prop.type === 'boolean') {
        defaults[key] = false
      }
    }
    setValues(defaults)
  }, [tool.name]) // eslint-disable-line react-hooks/exhaustive-deps

  const setValue = (key: string, value: unknown) => {
    setValues((prev) => ({ ...prev, [key]: value }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Strip empty strings and undefined values
    const cleaned: Record<string, unknown> = {}
    for (const [key, val] of Object.entries(values)) {
      if (val !== '' && val !== undefined && val !== null) {
        cleaned[key] = val
      }
    }
    onSubmit(cleaned)
  }

  const isPathField = (name: string) =>
    name.includes('path') || name.includes('file') || name.includes('directory')

  const renderField = (name: string, prop: SchemaProperty) => {
    const isRequired = required.has(name)
    const label = name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

    // Enum / select
    if (prop.enum && prop.enum.length > 0) {
      return (
        <div key={name} className="space-y-1.5">
          <Label htmlFor={name}>
            {label}
            {isRequired && <span className="text-destructive ml-0.5">*</span>}
          </Label>
          <select
            id={name}
            value={(values[name] as string) ?? ''}
            onChange={(e) => setValue(name, e.target.value)}
            className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] outline-none dark:bg-input/30"
          >
            <option value="">Select...</option>
            {prop.enum.map((val) => (
              <option key={val} value={val}>
                {val}
              </option>
            ))}
          </select>
          {prop.description && (
            <p className="text-xs text-muted-foreground">{prop.description}</p>
          )}
        </div>
      )
    }

    // Boolean / checkbox
    if (prop.type === 'boolean') {
      return (
        <div key={name} className="flex items-start gap-2 py-1">
          <Checkbox
            id={name}
            checked={!!values[name]}
            onCheckedChange={(checked) => setValue(name, !!checked)}
          />
          <div className="space-y-0.5 leading-none">
            <Label htmlFor={name} className="cursor-pointer">
              {label}
              {isRequired && <span className="text-destructive ml-0.5">*</span>}
            </Label>
            {prop.description && (
              <p className="text-xs text-muted-foreground">{prop.description}</p>
            )}
          </div>
        </div>
      )
    }

    // Number / integer
    if (prop.type === 'integer' || prop.type === 'number') {
      return (
        <div key={name} className="space-y-1.5">
          <Label htmlFor={name}>
            {label}
            {isRequired && <span className="text-destructive ml-0.5">*</span>}
          </Label>
          <Input
            id={name}
            type="number"
            step={prop.type === 'integer' ? 1 : 'any'}
            value={(values[name] as string) ?? ''}
            onChange={(e) => {
              const v = e.target.value
              if (v === '') {
                setValue(name, undefined)
              } else {
                setValue(name, prop.type === 'integer' ? parseInt(v, 10) : parseFloat(v))
              }
            }}
            placeholder={prop.description ?? ''}
          />
          {prop.description && (
            <p className="text-xs text-muted-foreground">{prop.description}</p>
          )}
        </div>
      )
    }

    // Default: string input
    return (
      <div key={name} className="space-y-1.5">
        <Label htmlFor={name}>
          {label}
          {isRequired && <span className="text-destructive ml-0.5">*</span>}
        </Label>
        <Input
          id={name}
          type="text"
          value={(values[name] as string) ?? ''}
          onChange={(e) => setValue(name, e.target.value)}
          placeholder={prop.description ?? ''}
          className={isPathField(name) ? 'font-mono text-xs' : ''}
        />
        {prop.description && (
          <p className="text-xs text-muted-foreground">{prop.description}</p>
        )}
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {fieldNames.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          This tool takes no parameters.
        </p>
      ) : (
        fieldNames.map((name) => renderField(name, properties[name]))
      )}

      <Button type="submit" disabled={loading} className="w-full">
        {loading ? (
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        ) : (
          <Play className="mr-2 h-4 w-4" />
        )}
        {loading ? 'Running...' : 'Run Tool'}
      </Button>
    </form>
  )
}
