import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, getSession, onSessionCleared, setSession } from './api'
import type { Session } from './types'

interface AuthContextValue {
  session: Session | null
  login: (username: string, password: string) => Promise<Session>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSessionState] = useState<Session | null>(getSession())

  // A 401 on any request — including a background poll — clears the stored
  // token inside api.ts. Mirroring that into React state lets the route guard
  // send the analyst back to the login screen on the next render.
  useEffect(() => onSessionCleared(() => setSessionState(null)), [])

  const login = useCallback(async (username: string, password: string) => {
    const s = await api.post<Session>('/api/auth/login', { username, password })
    setSession(s)
    setSessionState(s)
    return s
  }, [])

  const logout = useCallback(() => {
    setSession(null)
    setSessionState(null)
  }, [])

  return <AuthContext.Provider value={{ session, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth outside AuthProvider')
  return ctx
}
