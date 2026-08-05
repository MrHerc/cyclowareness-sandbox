import { useEffect, useState } from 'react'
import { api } from './api'
import type { Capabilities } from './types'

let cache: Capabilities | null = null

/**
 * Read the PUBLIC capability facts once and share them.
 *
 * This hook runs before anyone has logged in -- the login screen prints the demo
 * credentials from `demo_mode` -- so it reads `/api/capabilities/public`, which
 * carries that flag and nothing else. The full descriptor names the upload
 * ceiling, the extension allowlist and the analyzer inventory, which together
 * are a map for getting a sample past this deployment; it now requires an
 * analyst session and the Engines page reads it directly.
 */
export function useCapabilities(): Capabilities | null {
  const [caps, setCaps] = useState<Capabilities | null>(cache)
  useEffect(() => {
    if (cache) return
    let live = true
    api
      .get<Capabilities>('/api/capabilities/public')
      .then((c) => {
        cache = c
        if (live) setCaps(c)
      })
      .catch(() => {
        /* capabilities are advisory; a failure just leaves the UI generic */
      })
    return () => {
      live = false
    }
  }, [])
  return caps
}
