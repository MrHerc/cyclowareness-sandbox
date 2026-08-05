import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Cpu, LayoutDashboard, ListChecks, LogOut, Moon, SlidersHorizontal, Sun, Upload } from 'lucide-react'
import { Brand } from './Brand'
import { cx } from './ui'
import { useAuth } from '../lib/auth'
import { useCapabilities } from '../lib/useCapabilities'
import { useTheme } from '../lib/useTheme'

/**
 * A left rail, not a top bar.
 *
 * The previous layout put primary navigation in a horizontal header AND
 * repeated it in a second scrolling strip below for narrow screens — two
 * renderings of the same five links, both on screen at 767px, stacked. The rail
 * replaces the first and a bottom bar replaces the second, so exactly one is
 * ever visible.
 *
 * The rail keeps a 10px label under each icon. The design it follows is
 * icon-only, and that works when the icons are Home / Search / Profile; ours
 * are Integrations and Tuning, which no glyph communicates. An unlabelled rail
 * would have looked cleaner in a screenshot and cost a visitor at an exhibition
 * the ability to find anything.
 */
const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/submit', label: 'Submit', icon: Upload, end: false },
  { to: '/queue', label: 'Queue', icon: ListChecks, end: false },
  { to: '/integrations', label: 'Engines', icon: Cpu, end: false },
  { to: '/tuning', label: 'Tuning', icon: SlidersHorizontal, end: false },
]

const railItem = (isActive: boolean) =>
  cx(
    'group flex w-full flex-col items-center gap-1.5 rounded-control px-1 py-2.5 transition-colors',
    isActive ? 'bg-brand text-on-brand' : 'text-c3 hover:bg-raised hover:text-c1',
  )

export function Layout() {
  const { session, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const caps = useCapabilities()
  const navigate = useNavigate()

  const signOut = () => {
    // `logout` now reaches the server before it clears the session, so it is
    // awaited -- otherwise the navigation races the revocation and a failure
    // would be invisible.
    void logout().finally(() => navigate('/login'))
  }

  return (
    <div className="min-h-screen sm:pl-[84px]">
      {/* ---- the rail (>= sm) ------------------------------------------- */}
      <aside
        className="fixed inset-y-0 left-0 z-30 hidden w-[84px] flex-col items-center gap-1 border-r border-hair bg-panel/70 px-3 py-4 backdrop-blur sm:flex"
        aria-label="Primary"
      >
        <NavLink to="/" className="mb-3 rounded-control" aria-label="Cyclowareness Sandbox — overview">
          <Brand withText={false} size={26} />
        </NavLink>

        <nav className="flex w-full flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => railItem(isActive)}>
              <Icon size={19} aria-hidden />
              <span className="text-[10px] font-medium leading-none tracking-tight">{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex w-full flex-col items-center gap-1">
          {caps?.demo_mode && (
            <span className="label mb-1 rounded-chip border border-brand/40 px-1.5 py-0.5 text-brand-fg">
              Demo
            </span>
          )}
          <button
            type="button"
            onClick={toggle}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
            className="inline-flex h-10 w-10 items-center justify-center rounded-control text-c3 transition-colors hover:bg-raised hover:text-c1"
          >
            {theme === 'dark' ? <Sun size={18} aria-hidden /> : <Moon size={18} aria-hidden />}
          </button>
          {session && (
            <button
              type="button"
              onClick={signOut}
              title={`Sign out — ${session.subject}`}
              aria-label={`Sign out, signed in as ${session.subject}`}
              className="inline-flex h-10 w-10 items-center justify-center rounded-control text-c3 transition-colors hover:bg-raised hover:text-c1"
            >
              <LogOut size={18} aria-hidden />
            </button>
          )}
        </div>
      </aside>

      {/* ---- the top strip: identity only. Every page draws its own title. -- */}
      <div className="flex h-14 items-center justify-between gap-3 px-4 sm:h-16 sm:px-8">
        <div className="sm:hidden">
          <Brand />
        </div>
        <div className="ml-auto flex items-center gap-3">
          {caps?.demo_mode && (
            <span className="label rounded-chip border border-brand/40 px-1.5 py-0.5 text-brand-fg sm:hidden">
              Demo
            </span>
          )}
          {session && (
            <span className="text-sm hidden items-center gap-2 text-c2 sm:inline-flex">
              <span
                className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-brand-dim text-xs font-semibold text-brand-fg"
                aria-hidden
              >
                {session.subject.slice(0, 2).toUpperCase()}
              </span>
              {session.subject}
            </span>
          )}
          <button
            type="button"
            onClick={toggle}
            aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            className="inline-flex h-9 w-9 items-center justify-center rounded-control text-c3 transition-colors hover:bg-raised hover:text-c1 sm:hidden"
          >
            {theme === 'dark' ? <Sun size={17} aria-hidden /> : <Moon size={17} aria-hidden />}
          </button>
        </div>
      </div>

      <main className="mx-auto max-w-6xl px-4 pb-24 pt-1 sm:px-8 sm:pb-12">
        <Outlet />
      </main>

      {/* ---- the bottom bar (< sm). The rail's counterpart, never both. ---- */}
      <nav
        className="fixed inset-x-0 bottom-0 z-30 flex items-stretch justify-around border-t border-hair bg-panel/90 px-1 py-1.5 backdrop-blur sm:hidden"
        aria-label="Primary mobile"
      >
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cx(
                'flex flex-1 flex-col items-center gap-1 rounded-control px-1 py-1.5 transition-colors',
                isActive ? 'bg-brand text-on-brand' : 'text-c3',
              )
            }
          >
            <Icon size={18} aria-hidden />
            <span className="text-[10px] font-medium leading-none">{label}</span>
          </NavLink>
        ))}
        {session && (
          <button
            type="button"
            onClick={signOut}
            aria-label="Sign out"
            className="flex flex-1 flex-col items-center gap-1 rounded-control px-1 py-1.5 text-c3"
          >
            <LogOut size={18} aria-hidden />
            <span className="text-[10px] font-medium leading-none">Out</span>
          </button>
        )}
      </nav>
    </div>
  )
}
