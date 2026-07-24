import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Cpu, ListChecks, LogOut, Moon, SlidersHorizontal, Sun, Upload } from 'lucide-react'
import { Brand } from './Brand'
import { cx } from './ui'
import { useAuth } from '../lib/auth'
import { useCapabilities } from '../lib/useCapabilities'
import { useTheme } from '../lib/useTheme'

const NAV = [
  { to: '/', label: 'Submit', icon: Upload, end: true },
  { to: '/queue', label: 'Queue', icon: ListChecks, end: false },
  { to: '/integrations', label: 'Integrations', icon: Cpu, end: false },
  { to: '/tuning', label: 'Tuning', icon: SlidersHorizontal, end: false },
]

export function Layout() {
  const { session, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const caps = useCapabilities()
  const navigate = useNavigate()

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-hair bg-canvas/85 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <NavLink to="/" className="shrink-0">
            <Brand />
          </NavLink>

          <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cx(
                    'inline-flex items-center gap-2 rounded-control px-3 py-1.5 text-sm font-medium transition-colors',
                    isActive ? 'bg-raised text-c1' : 'text-c2 hover:bg-raised hover:text-c1',
                  )
                }
              >
                <Icon size={15} aria-hidden />
                {label}
              </NavLink>
            ))}
          </nav>

          <div className="flex items-center gap-2">
            {caps?.demo_mode && (
              <span className="label hidden rounded-chip border border-brand/40 px-1.5 py-0.5 text-brand-fg sm:inline-flex">
                Demo
              </span>
            )}
            <button
              type="button"
              onClick={toggle}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
              className="inline-flex h-9 w-9 items-center justify-center rounded-control border border-transparent text-c2 transition-colors hover:bg-raised hover:text-c1"
            >
              {theme === 'dark' ? <Sun size={17} aria-hidden /> : <Moon size={17} aria-hidden />}
            </button>
            {session && (
              <button
                type="button"
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                className="inline-flex h-9 items-center gap-2 rounded-control border border-line bg-raised px-3 text-sm text-c1 transition-colors hover:border-line-strong"
              >
                <LogOut size={15} aria-hidden />
                <span className="hidden sm:inline">{session.subject}</span>
              </button>
            )}
          </div>
        </div>

        {/* Mobile nav */}
        <nav
          className="flex items-center gap-1 overflow-x-auto border-t border-hair px-2 py-1.5 md:hidden"
          aria-label="Primary mobile"
        >
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  'inline-flex shrink-0 items-center gap-1.5 rounded-control px-3 py-1.5 text-sm font-medium transition-colors',
                  isActive ? 'bg-raised text-c1' : 'text-c2',
                )
              }
            >
              <Icon size={15} aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">
        <Outlet />
      </main>
    </div>
  )
}
