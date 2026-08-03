import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { Brand } from '../components/Brand'
import { Button, Callout, Input } from '../components/ui'
import { useAuth } from '../lib/auth'
import { useCapabilities } from '../lib/useCapabilities'

export function Login() {
  const { login } = useAuth()
  const caps = useCapabilities()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? '/'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Brand size={30} withText={false} />
          <div>
            <h1 className="text-title">
              Cyclowareness <span className="text-brand-fg">Sandbox</span>
            </h1>
            <p className="text-sm mt-1 text-c2">Static-first file and URL threat analysis</p>
          </div>
        </div>

        <form
          onSubmit={onSubmit}
          className="rise rounded-panel border border-hair bg-panel p-6 shadow-sm"
        >
          <div className="space-y-4">
            <Input
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              required
            />
            <Input
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
            {error && (
              <Callout tone="danger" title="Could not sign in">
                {error}
              </Callout>
            )}
            <Button type="submit" variant="primary" size="lg" busy={busy} className="w-full">
              <ShieldCheck size={16} aria-hidden />
              Sign in
            </Button>
          </div>
        </form>

        {caps?.demo_mode && (
          <p className="text-xs mt-4 text-center text-c3">
            Demo build — sign in with <span className="tech text-c2">analyst</span> /{' '}
            <span className="tech text-c2">analyst</span>
          </p>
        )}
      </div>
    </div>
  )
}
