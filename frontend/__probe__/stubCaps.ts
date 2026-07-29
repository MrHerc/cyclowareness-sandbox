import type { Capabilities } from '../src/lib/types'

export function useCapabilities(): Capabilities | null {
  const g = globalThis as unknown as Record<string, unknown>
  return (g.__CAPS__ ?? null) as Capabilities | null
}
