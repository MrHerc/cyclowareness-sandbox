// Minimal typed API client. Bearer-token auth, with helpers for multipart
// upload and authenticated binary downloads (exports carry the token too, so a
// plain <a href> would 401 — they go through fetch + blob instead).

import type { Session } from './types'

const TOKEN_KEY = 'csbx_session'

export function getSession(): Session | null {
  const raw = localStorage.getItem(TOKEN_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as Session
  } catch {
    return null
  }
}

export function setSession(session: Session | null) {
  if (session) localStorage.setItem(TOKEN_KEY, JSON.stringify(session))
  else localStorage.removeItem(TOKEN_KEY)
}

const sessionCleared = new Set<() => void>()
export function onSessionCleared(listener: () => void): () => void {
  sessionCleared.add(listener)
  return () => {
    sessionCleared.delete(listener)
  }
}
function notifySessionCleared() {
  for (const listener of sessionCleared) listener()
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export const API_UNREACHABLE =
  "Can't reach the Cyclowareness Sandbox API — make sure the backend is running on port 8000, then try again."

function authHeader(): Record<string, string> {
  const s = getSession()
  return s ? { Authorization: `Bearer ${s.token}` } : {}
}

async function handle(res: Response, path: string): Promise<Response> {
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new ApiError(res.status, API_UNREACHABLE)
  }
  if (res.status === 401 && !path.endsWith('/auth/login')) {
    setSession(null)
    notifySessionCleared()
    throw new ApiError(401, 'Your session has expired. Sign in again to continue.')
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const data = await res.json()
      detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)
    } catch {
      /* keep statusText */
    }
    throw new ApiError(res.status, detail)
  }
  return res
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, API_UNREACHABLE)
  }
  await handle(res, path)
  return res.json() as Promise<T>
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),

  /** Multipart upload — the browser sets the boundary Content-Type itself. */
  async upload<T>(path: string, form: FormData): Promise<T> {
    let res: Response
    try {
      res = await fetch(path, { method: 'POST', headers: authHeader(), body: form })
    } catch {
      throw new ApiError(0, API_UNREACHABLE)
    }
    await handle(res, path)
    return res.json() as Promise<T>
  },

  /** Authenticated download — fetch with the token, then save the blob. */
  async download(path: string, filename: string): Promise<void> {
    let res: Response
    try {
      res = await fetch(path, { headers: authHeader() })
    } catch {
      throw new ApiError(0, API_UNREACHABLE)
    }
    await handle(res, path)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}
