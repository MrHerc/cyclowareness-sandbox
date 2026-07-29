// Probe stub: usePoll normally fills `data` from a useEffect, which never runs
// under renderToString. This returns the payload synchronously so the populated
// page renders instead of the loading state.
export function usePoll<T>(_fetcher: () => Promise<T>, _intervalMs?: number, _deps?: unknown[]) {
  const g = globalThis as unknown as Record<string, unknown>
  return {
    data: (g.__POLL__ ?? null) as T | null,
    error: (g.__ERR__ ?? null) as string | null,
    status: (g.__STATUS__ ?? null) as number | null,
    stale: Boolean(g.__STALE__),
    refresh: async () => {},
  }
}
