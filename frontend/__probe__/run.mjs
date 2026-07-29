import fs from 'node:fs'
import path from 'node:path'

const PL = process.argv[2]
const m = await import('./out/entry.js')

const files = fs.readdirSync(PL).filter((f) => f.endsWith('.json'))
const read = (f) => JSON.parse(fs.readFileSync(path.join(PL, f), 'utf8'))

let fails = 0
function attempt(label, fn) {
  try {
    const html = fn()
    if (typeof html !== 'string' || html.length < 50) {
      console.log(`WARN  ${label}: rendered ${html?.length ?? 0} chars`)
    } else {
      console.log(`ok    ${label} (${html.length} chars)`)
    }
    return html
  } catch (e) {
    fails++
    console.log(`FAIL  ${label}: ${e && e.message}`)
    if (process.env.PROBE_STACK) console.log(String(e && e.stack).split('\n').slice(0, 6).join('\n'))
    return null
  }
}

const caps = read('capabilities.json')
globalThis.__CAPS__ = caps

console.log('=== JobDetail against every captured live payload ===')
for (const f of files.filter((f) => f.startsWith('job-'))) {
  const job = read(f)
  attempt(`JobDetail ${job.status.padEnd(18)} ${f.slice(4, 16)}`, () => m.renderJob(job))
}

console.log('\n=== Other pages ===')
attempt('Dashboard  live stats', () => m.renderDashboard(read('stats.json')))
attempt('Queue      live page ', () => m.renderQueue(read('jobs.json')))
attempt('Integrations live caps', () => m.renderIntegrations(caps))
attempt('Submit     live caps ', () => m.renderSubmit(caps))

console.log('\n=== Degraded / empty deployment states ===')
attempt('Dashboard  empty deployment', () =>
  m.renderDashboard({
    total: 0, completed: 0, in_flight: 0,
    verdicts: { malicious: 0, suspicious: 0, clean: 0, unclassified: 0 },
    needs_attention: 0, average_score: 0, families: [], top_risk: [],
  }),
)
attempt('Queue      empty deployment', () => m.renderQueue({ items: [], total: 0, limit: 50, offset: 0 }))
attempt('Dashboard  stale (polls failing)', () =>
  m.renderDashboard(read('stats.json'), { stale: true, error: 'Network error' }),
)
attempt('Queue      stale', () => m.renderQueue(read('jobs.json'), { stale: true, error: 'Network error' }))
attempt('Integrations stale', () => m.renderIntegrations(caps, { stale: true, error: 'Network error' }))

console.log('\n=== Synthetic job states the deployment has not produced yet ===')
const base = read(files.find((f) => f.startsWith('job-') && read(f).status === 'completed'))
const clone = (o) => JSON.parse(JSON.stringify(o))

attempt('JobDetail  status=queued', () => {
  const j = clone(base)
  j.status = 'queued'; j.stage = 'queued'; j.completed_at = null
  return m.renderJob(j)
})
attempt('JobDetail  status=running', () => {
  const j = clone(base)
  j.status = 'running'; j.stage = 'static analysis'; j.completed_at = null
  return m.renderJob(j)
})
attempt('JobDetail  status=failed + error', () => {
  const j = clone(base)
  j.status = 'failed'; j.error = 'Analysis crashed'
  return m.renderJob(j)
})
attempt('JobDetail  running + stale poll', () => {
  const j = clone(base)
  j.status = 'running'; j.completed_at = null
  return m.renderJob(j, { stale: true, error: 'Network error' })
})
attempt('JobDetail  completed, everything empty', () =>
  m.renderJob({
    ...clone(base),
    tiers: {}, analysis: {}, dynamic: {}, iocs: {}, score_breakdown: {},
    impact: {}, verdict: {}, mitre: [], children: [], error: null,
  }),
)

console.log('\n=== Type-assertion probes: what the API could return that types.ts forbids ===')
attempt('JobDetail  mitre=null', () => m.renderJob({ ...clone(base), mitre: null }))
attempt('JobDetail  impact=null', () => m.renderJob({ ...clone(base), impact: null }))
attempt('JobDetail  verdict=null', () => m.renderJob({ ...clone(base), verdict: null }))
attempt('JobDetail  iocs value objects', () =>
  m.renderJob({ ...clone(base), iocs: { urls: [{ value: 'http://x', ctx: 'y' }] } }),
)
attempt('JobDetail  signal.detail an object', () => {
  const j = clone(base)
  const k = Object.keys(j.analysis)[0]
  if (j.analysis[k]?.signals?.[0]) j.analysis[k].signals[0].detail = { note: 'object' }
  return m.renderJob(j)
})
attempt('JobDetail  impact.metrics value object', () => {
  const j = clone(base)
  if (j.impact?.metrics) j.impact.metrics.AV = { v: 'N' }
  return m.renderJob(j)
})
attempt('JobDetail  mitre evidence objects', () => {
  const j = clone(base)
  if (j.mitre?.[0]) j.mitre[0].evidence = [{ sig: 'x' }]
  return m.renderJob(j)
})
attempt('JobDetail  rule_score null', () => m.renderJob({ ...clone(base), rule_score: null }))
attempt('JobDetail  final_score null', () => m.renderJob({ ...clone(base), final_score: null }))
attempt('JobDetail  duration_ms object', () => m.renderJob({ ...clone(base), duration_ms: { ms: 5 } }))
attempt('Integrations outbound_refusals as number', () => {
  const c = clone(caps)
  c.sovereignty.outbound_refusals = 7
  return m.renderIntegrations(c)
})
attempt('Integrations sovereignty missing', () => {
  const c = clone(caps)
  delete c.sovereignty
  return m.renderIntegrations(c)
})
attempt('Integrations retention missing', () => {
  const c = clone(caps)
  delete c.retention
  return m.renderIntegrations(c)
})
attempt('Submit     caps missing max_sample_mb', () => {
  const c = clone(caps)
  delete c.max_sample_mb
  return m.renderSubmit(c)
})

console.log(`\n${fails} failure(s)`)
