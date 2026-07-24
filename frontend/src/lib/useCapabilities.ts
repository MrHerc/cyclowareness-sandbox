import { useEffect, useState } from 'react'
import { api } from './api'
import type { Capabilities } from './types'

let cache: Capabilities | null = null

/** Read /api/capabilities once and share it. What the deployment can honestly do. */
export function useCapabilities(): Capabilities | null {
  const [caps, setCaps] = useState<Capabilities | null>(cache)
  useEffect(() => {
    if (cache) return
    let live = true
    api
      .get<Capabilities>('/api/capabilities')
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
