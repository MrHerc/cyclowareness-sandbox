import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from './api'

/**
 * Poll a fetcher on an interval.
 *
 * Returns `status` alongside `error` so callers can distinguish *why* a load
 * failed — "you don't have an employee profile" (403) needs a different screen
 * from "the API is down" (0/5xx), and a bare message string cannot tell them
 * apart.
 *
 * Two properties this hook has to guarantee:
 *
 * 1. **A slow response never overwrites a newer one.** Ticks overlap whenever a
 *    request outlives the interval, and they do not return in order. Without a
 *    per-request sequence number, a slow response from tick N lands on top of
 *    fresh data from tick N+1 and the dashboard shows a stale loop stage until
 *    some later race happens to go the other way.
 *
 * 2. **A dead API is not hammered.** The old `setInterval` fired regardless of
 *    outcome, so an unreachable backend took a request every few seconds
 *    forever, per open tab. On the executive view — where each poll costs a
 *    model call — a forgotten background tab billed a completion every 15
 *    seconds all day. Failures now back off, and polling pauses while the tab
 *    is hidden.
 */
export function usePoll<T>(fetcher: () => Promise<T>, intervalMs = 2500, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [status, setStatus] = useState<number | null>(null)

  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  // Generation: bumped when deps change, so responses aimed at the previous
  // target (the loop run you just navigated away from) are discarded.
  const generation = useRef(0)
  // Sequence: monotonic per request; `applied` is the newest response written
  // to state, so anything older arriving late is dropped.
  const sequence = useRef(0)
  const applied = useRef(0)
  const failures = useRef(0)

  const refresh = useCallback(async () => {
    const gen = generation.current
    const seq = ++sequence.current
    try {
      const result = await fetcherRef.current()
      if (gen !== generation.current || seq <= applied.current) return
      applied.current = seq
      failures.current = 0
      setData(result)
      setError(null)
      setStatus(null)
    } catch (e) {
      if (gen !== generation.current || seq <= applied.current) return
      applied.current = seq
      failures.current += 1
      setError(e instanceof Error ? e.message : String(e))
      setStatus(e instanceof ApiError ? e.status : null)
    }
  }, [])

  useEffect(() => {
    generation.current += 1
    sequence.current = 0
    applied.current = 0
    failures.current = 0
    setData(null)
    setError(null)
    setStatus(null)

    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false

    const schedule = () => {
      if (stopped) return
      // Exponential back-off on consecutive failures, capped at 8x.
      const backoff = Math.min(2 ** failures.current, 8)
      timer = setTimeout(() => void tick(), intervalMs * backoff)
    }

    const tick = async () => {
      if (stopped) return
      if (document.visibilityState === 'visible') await refresh()
      schedule()
    }

    // Returning to a tab should show current data at once, not whenever the
    // next scheduled tick happens to land.
    const onVisibility = () => {
      if (document.visibilityState === 'visible') void refresh()
    }
    document.addEventListener('visibilitychange', onVisibility)

    void refresh()
    schedule()

    return () => {
      stopped = true
      if (timer) clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisibility)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, refresh, ...deps])

  return { data, error, status, refresh }
}
