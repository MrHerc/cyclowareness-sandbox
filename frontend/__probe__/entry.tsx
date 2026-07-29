import { renderToString } from 'react-dom/server'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { JobDetail } from '../src/pages/JobDetail'
import { Dashboard } from '../src/pages/Dashboard'
import { Queue } from '../src/pages/Queue'
import { Integrations } from '../src/pages/Integrations'
import { Submit } from '../src/pages/Submit'

const g = globalThis as unknown as Record<string, unknown>

function set(payload: unknown, opts: { stale?: boolean; error?: string | null } = {}) {
  g.__POLL__ = payload
  g.__STALE__ = opts.stale ?? false
  g.__ERR__ = opts.error ?? null
}

export function renderJob(job: unknown, opts = {}) {
  set(job, opts)
  return renderToString(
    <MemoryRouter initialEntries={['/job/probe-id']}>
      <Routes>
        <Route path="/job/:id" element={<JobDetail />} />
      </Routes>
    </MemoryRouter>,
  )
}

export function renderDashboard(stats: unknown, opts = {}) {
  set(stats, opts)
  return renderToString(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </MemoryRouter>,
  )
}

export function renderQueue(page: unknown, opts = {}) {
  set(page, opts)
  return renderToString(
    <MemoryRouter initialEntries={['/queue']}>
      <Routes>
        <Route path="/queue" element={<Queue />} />
      </Routes>
    </MemoryRouter>,
  )
}

export function renderIntegrations(caps: unknown, opts = {}) {
  set(caps, opts)
  return renderToString(
    <MemoryRouter initialEntries={['/integrations']}>
      <Routes>
        <Route path="/integrations" element={<Integrations />} />
      </Routes>
    </MemoryRouter>,
  )
}

export function renderSubmit(caps: unknown) {
  g.__CAPS__ = caps
  return renderToString(
    <MemoryRouter initialEntries={['/submit']}>
      <Routes>
        <Route path="/submit" element={<Submit />} />
      </Routes>
    </MemoryRouter>,
  )
}
