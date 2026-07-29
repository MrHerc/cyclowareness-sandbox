import fs from 'node:fs'
import path from 'node:path'

const PL = process.argv[2]
const m = await import('./out/entry.js')
const read = (f) => JSON.parse(fs.readFileSync(path.join(PL, f), 'utf8'))
const clone = (o) => JSON.parse(JSON.stringify(o))
globalThis.__CAPS__ = read('capabilities.json')

// A RICH job: has analysis signals, mitre techniques, impact metrics, iocs AND a
// populated dynamic.timeline. The previous run used a sparse job, so several
// mutations were silently no-ops.
const RICH = read('job-184a5be1-403a-4361-9092-92f9cca5587c.json')
console.log('base job:', RICH.public_id)
console.log('  analysis analyzers   :', Object.keys(RICH.analysis).length)
console.log('  dynamic.timeline     :', RICH.dynamic?.timeline?.length)
console.log('  dynamic.signals      :', RICH.dynamic?.signals?.length)
console.log('  mitre techniques     :', RICH.mitre?.length)
console.log('  impact.metrics keys  :', Object.keys(RICH.impact?.metrics ?? {}).length)
console.log('  ioc buckets          :', Object.keys(RICH.iocs ?? {}).length)
console.log('  timeline kinds       :', [...new Set((RICH.dynamic?.timeline ?? []).map((e) => e.kind))].join(', '))
console.log()

let fails = 0
function attempt(label, mutate) {
  const j = clone(RICH)
  try {
    mutate(j)
  } catch (e) {
    console.log(`SKIP  ${label}: mutation failed (${e.message})`)
    return
  }
  try {
    const html = m.renderJob(j)
    console.log(`ok    ${label} (${html.length} chars)`)
  } catch (e) {
    fails++
    console.log(`FAIL  ${label}\n        ${e.message}`)
  }
}

console.log('=== control ===')
attempt('unmutated rich job', () => {})

console.log('\n=== dynamic.timeline: list[dict[str, Any]], NOT field-validated by DynamicReportIn ===')
attempt('timeline[].kind is an object', (j) => {
  j.dynamic.timeline[0].kind = { process: 'explorer.exe' }
})
attempt('timeline[].kind is an array', (j) => {
  j.dynamic.timeline[0].kind = ['process']
})
attempt('timeline[].kind is a number', (j) => {
  j.dynamic.timeline[0].kind = 42
})
attempt('timeline[].detail is an object', (j) => {
  j.dynamic.timeline[0].detail = { cmd: 'x' }
})
attempt('timeline[].t_ms is a string', (j) => {
  j.dynamic.timeline[0].t_ms = '12'
})
attempt('timeline[].t_ms missing', (j) => {
  delete j.dynamic.timeline[0].t_ms
})
attempt('timeline[] entry is a bare string', (j) => {
  j.dynamic.timeline[0] = 'process started'
})
attempt('timeline[] entry is null', (j) => {
  j.dynamic.timeline[0] = null
})

console.log('\n=== dynamic.signals: SignalIn-validated (severity/detail are str) ===')
attempt('dynamic signal.severity unknown word', (j) => {
  j.dynamic.signals[0].severity = 'catastrophic'
})
attempt('dynamic signal.detail object (bypasses SignalIn?)', (j) => {
  j.dynamic.signals[0].detail = { a: 1 }
})

console.log('\n=== engine-generated fields (internal, dict[str, Any] on the wire) ===')
attempt('impact.metrics value is an object', (j) => {
  j.impact.metrics.AV = { v: 'N' }
})
attempt('impact.rationale[].why is an object', (j) => {
  j.impact.rationale[0].why = { because: 'x' }
})
attempt('impact.severity unknown', (j) => {
  j.impact.severity = 'apocalyptic'
})
attempt('impact.base_score is a string', (j) => {
  j.impact.base_score = '8.8'
})
attempt('analysis signal.detail is an object', (j) => {
  const k = Object.keys(j.analysis).find((k) => j.analysis[k].signals?.length)
  j.analysis[k].signals[0].detail = { note: 'obj' }
})
attempt('analysis signal.title is an object', (j) => {
  const k = Object.keys(j.analysis).find((k) => j.analysis[k].signals?.length)
  j.analysis[k].signals[0].title = { t: 'obj' }
})
attempt('score_breakdown.top_reasons[].detail object', (j) => {
  j.score_breakdown.top_reasons[0].detail = { d: 1 }
})
attempt('score_breakdown.rule.bands[].contribution string', (j) => {
  j.score_breakdown.rule.bands[0].contribution = '1.5'
})
attempt('score_breakdown.model.contributions[].weight object', (j) => {
  j.score_breakdown.model.contributions[0].weight = { w: 1 }
})
attempt('mitre[].evidence contains objects', (j) => {
  j.mitre[0].evidence = [{ sig: 'x' }]
})
attempt('mitre[].name is an object', (j) => {
  j.mitre[0].name = { n: 'x' }
})
attempt('mitre[].tactic is an object', (j) => {
  j.mitre[0].tactic = { t: 'x' }
})
attempt('iocs bucket contains objects', (j) => {
  j.iocs.urls = [{ value: 'http://x' }]
})
attempt('verdict.engines[].result is an object', (j) => {
  j.verdict.engines[0].result = { r: 'x' }
})
attempt('verdict.detection_ratio is an object', (j) => {
  j.verdict.detection_ratio = { d: 1 }
})
attempt('tiers.dynamic.engine is an object', (j) => {
  j.tiers.dynamic.engine = { e: 'capev2' }
})
attempt('tiers.dynamic.detail is an object', (j) => {
  j.tiers.dynamic.detail = { d: 'x' }
})
attempt('dynamic.engine is an object (panel subtitle)', (j) => {
  j.dynamic.engine = { e: 'capev2' }
})
attempt('dynamic.worker is an object (panel subtitle)', (j) => {
  j.dynamic.worker = { w: 'x' }
})

console.log(`\n${fails} failure(s)`)
