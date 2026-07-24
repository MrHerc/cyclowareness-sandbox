import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Braces,
  ChevronRight,
  Download,
  FileText,
  Flag,
  Lock,
  RefreshCw,
  Share2,
} from 'lucide-react'
import {
  Button,
  Callout,
  Chip,
  CodeBlock,
  GroupLabel,
  Input,
  LoadState,
  PageHeader,
  Panel,
  Status,
  timeAgo,
} from '../components/ui'
import { ScoreGauge } from '../components/ScoreGauge'
import { BehaviorGraph } from '../components/BehaviorGraph'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import { familyLabel, formatBytes, iocLabel } from '../lib/format'
import type { JobDetailT, SignalT } from '../lib/types'

const SEVERITY_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const SEVERITY_TONE: Record<string, 'danger' | 'warning' | 'neutral'> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'neutral',
  info: 'neutral',
}

function signalsOf(job: JobDetailT): SignalT[] {
  const out: SignalT[] = []
  for (const [name, payload] of Object.entries(job.analysis || {})) {
    if (!payload?.ran) continue
    for (const s of payload.signals || []) out.push({ ...s, analyzer: name })
  }
  out.sort((a, b) => (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0))
  return out
}

export function JobDetail() {
  const { id = '' } = useParams()
  const { data: job, error, refresh } = usePoll<JobDetailT>(
    () => api.get(`/api/result/${id}`),
    2000,
    [id],
  )
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<string | null>(null)

  async function action(name: string, fn: () => Promise<unknown>) {
    setBusy(name)
    try {
      await fn()
      await refresh()
    } finally {
      setBusy(null)
    }
  }

  if (!job) {
    return (
      <div className="space-y-6">
        <Link to="/queue" className="text-sm inline-flex items-center gap-1.5 text-c2 hover:text-c1">
          <ArrowLeft size={15} aria-hidden /> Queue
        </Link>
        <LoadState error={error} label="Loading analysis" onRetry={refresh} />
      </div>
    )
  }

  const running = job.status === 'running' || job.status === 'queued'
  const done = job.status === 'completed'
  const signals = signalsOf(job)
  const staticTier = job.tiers?.static
  const dynamicTier = job.tiers?.dynamic
  const model = job.score_breakdown?.model
  const rule = job.score_breakdown?.rule
  const iocEntries = Object.entries(job.iocs || {}).filter(([, v]) => v && v.length)
  const yaraHits = (job.analysis?.yara?.ran && job.analysis.yara.signals) || []
  const filename = job.original_name || 'sample'

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link to="/queue" className="text-sm inline-flex items-center gap-1.5 text-c2 hover:text-c1">
          <ArrowLeft size={15} aria-hidden /> Queue
        </Link>
        {done && (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" busy={busy === 'json'} onClick={() => action('json', () => api.download(`/api/jobs/${id}/export.json`, `sandbox-${filename}.json`))}>
              <Braces size={14} aria-hidden /> JSON
            </Button>
            <Button size="sm" busy={busy === 'stix'} onClick={() => action('stix', () => api.download(`/api/jobs/${id}/export.stix`, `sandbox-${filename}.stix.json`))}>
              <Share2 size={14} aria-hidden /> STIX
            </Button>
            <Button size="sm" busy={busy === 'pdf'} onClick={() => action('pdf', () => api.download(`/api/jobs/${id}/export.pdf`, `sandbox-${filename}.pdf`))}>
              <Download size={14} aria-hidden /> PDF
            </Button>
            <Button size="sm" busy={busy === 're'} onClick={() => action('re', () => api.post(`/api/jobs/${id}/reanalyze`))}>
              <RefreshCw size={14} aria-hidden /> Re-analyse
            </Button>
          </div>
        )}
      </div>

      <PageHeader
        title={<span className="break-all">{filename}</span>}
        lede={
          <span className="tech text-c3">
            {job.sha256}
          </span>
        }
        actions={<Status value={job.status} />}
      />

      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-c2">
        <span>{familyLabel(job.family)}</span>
        <span>{formatBytes(job.size_bytes)}</span>
        <span>{job.mime || 'unknown type'}</span>
        <span>{job.source === 'url' ? 'From URL' : 'Uploaded'}</span>
        <span>Submitted {timeAgo(job.created_at)}</span>
        {job.submitted_by && <span>by {job.submitted_by}</span>}
      </div>

      {job.status === 'awaiting_password' && (
        <Panel tone="feature">
          <div className="flex items-start gap-3">
            <Lock size={20} className="mt-0.5 shrink-0 text-brand-fg" aria-hidden />
            <div className="w-full">
              <h2 className="text-h">This archive is encrypted</h2>
              <p className="text-sm mt-1 text-c2">
                Provide the password to continue. It is used once and never stored — the engine does not
                brute-force.
              </p>
              <form
                className="mt-3 flex flex-wrap items-end gap-3"
                onSubmit={(e: FormEvent) => {
                  e.preventDefault()
                  action('pw', () => api.post(`/api/jobs/${id}/password`, { password }))
                }}
              >
                <div className="min-w-[220px] flex-1">
                  <Input label="Archive password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <Button type="submit" variant="primary" busy={busy === 'pw'} disabled={!password}>
                  Unlock and analyse
                </Button>
              </form>
            </div>
          </div>
        </Panel>
      )}

      {job.status === 'failed' && (
        <Callout tone="danger" title="Analysis failed">
          {job.error || 'The job did not complete. Re-analyse to try again.'}
        </Callout>
      )}

      {running && (
        <Panel>
          <div className="scan relative flex items-center gap-3 overflow-hidden">
            <div className="h-2 w-2 rounded-full bg-brand breathe" aria-hidden />
            <span className="text-body text-c2">
              Analysing — <span className="text-c1">{job.stage || job.status}</span>
            </span>
          </div>
        </Panel>
      )}

      {done && (
        <>
          {/* Verdict hero */}
          <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
            <Panel tone="feature" className="flex items-center justify-center lg:w-72">
              <ScoreGauge score={job.final_score} riskLevel={job.risk_level} />
            </Panel>
            <Panel title="Why this verdict">
              <div className="space-y-3">
                {(job.score_breakdown?.top_reasons || []).length === 0 ? (
                  <p className="text-sm text-c2">
                    No suspicious indicators were found by the analyzers that ran. This is a
                    &ldquo;nothing found&rdquo; result, not a guarantee of safety.
                  </p>
                ) : (
                  (job.score_breakdown?.top_reasons || []).map((r) => (
                    <div key={r.id} className="flex items-start gap-2.5">
                      <Chip tone={SEVERITY_TONE[r.severity] ?? 'neutral'}>{r.severity}</Chip>
                      <div className="min-w-0">
                        <p className="text-body font-medium text-c1">{r.title}</p>
                        {r.detail && <p className="text-sm text-c2">{r.detail}</p>}
                      </div>
                    </div>
                  ))
                )}
                <div className="mt-2 flex flex-wrap gap-2 border-t border-hair pt-3 text-sm text-c2">
                  <span>Rule component <span className="font-semibold text-c1">{job.rule_score.toFixed(0)}</span></span>
                  <span className="text-c3">·</span>
                  <span>Model component <span className="font-semibold text-c1">{job.ai_score.toFixed(0)}</span></span>
                  {job.score_breakdown?.formula && (
                    <span className="tech text-c3">{job.score_breakdown.formula}</span>
                  )}
                </div>
              </div>
            </Panel>
          </div>

          {/* Tier honesty */}
          <Panel title="Analysis tiers">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-control border border-hair bg-raised p-3">
                <div className="flex items-center justify-between">
                  <span className="label text-c3">Static</span>
                  <Status value={staticTier?.ran ? 'completed' : 'failed'} label={staticTier?.ran ? 'Ran' : 'Did not run'} />
                </div>
                <p className="text-sm mt-1.5 text-c2">{staticTier?.detail || 'Parsers and YARA. The sample is never executed.'}</p>
              </div>
              <div className="rounded-control border border-hair bg-raised p-3">
                <div className="flex items-center justify-between">
                  <span className="label text-c3">Dynamic</span>
                  <Status
                    value={dynamicTier?.ran ? 'completed' : 'pending'}
                    label={dynamicTier?.ran ? `Ran (${dynamicTier.engine})` : 'Not run'}
                  />
                </div>
                <p className="text-sm mt-1.5 text-c2">
                  {dynamicTier?.detail ||
                    'No isolated worker was attached, so the sample was not detonated — only statically analysed.'}
                </p>
              </div>
            </div>
          </Panel>

          {/* Behaviour graph (dynamic) */}
          {job.dynamic?.ran && job.dynamic.timeline && job.dynamic.timeline.length > 0 && (
            <Panel title="Observed behaviour" subtitle={`Detonated on the ${job.dynamic.engine} engine (${job.dynamic.worker})`}>
              <BehaviorGraph events={job.dynamic.timeline} />
              {job.dynamic.signals && job.dynamic.signals.length > 0 && (
                <div className="mt-4 space-y-2">
                  {job.dynamic.signals.map((s, i) => (
                    <div key={i} className="flex items-start gap-2.5">
                      <Chip tone={SEVERITY_TONE[s.severity] ?? 'neutral'}>{s.severity}</Chip>
                      <div className="min-w-0">
                        <p className="text-body font-medium text-c1">{s.title}</p>
                        {s.detail && <p className="text-sm text-c2">{s.detail}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )}

          {/* Signals */}
          <Panel title="Signals" subtitle={`${signals.length} observation${signals.length === 1 ? '' : 's'} across all analyzers`}>
            {signals.length === 0 ? (
              <p className="text-sm text-c2">No signals fired.</p>
            ) : (
              <div className="divide-hair -my-2">
                {signals.map((s, i) => (
                  <div key={`${s.id}-${i}`} className="flex items-start gap-3 py-2.5">
                    <Chip tone={SEVERITY_TONE[s.severity] ?? 'neutral'}>{s.severity}</Chip>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline gap-x-2">
                        <span className="text-body font-medium text-c1">{s.title}</span>
                        <span className="tech text-c3">{s.id}</span>
                      </div>
                      {s.detail && <p className="text-sm mt-0.5 text-c2">{s.detail}</p>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Score breakdown */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title="Rule component" subtitle="Severity-weighted, saturating per band">
              {rule && rule.bands.length > 0 ? (
                <div className="space-y-2">
                  {rule.bands.map((b) => (
                    <div key={b.severity} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <Chip tone={SEVERITY_TONE[b.severity] ?? 'neutral'}>{b.severity}</Chip>
                        <span className="text-c2">{b.count} signal{b.count === 1 ? '' : 's'}</span>
                      </span>
                      <span className="tabular-nums font-medium text-c1">+{b.contribution.toFixed(1)}</span>
                    </div>
                  ))}
                  <div className="mt-2 flex justify-between border-t border-hair pt-2 text-sm">
                    <span className="text-c2">Rule score</span>
                    <span className="tabular-nums font-semibold text-c1">{rule.score.toFixed(1)}</span>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-c2">No rule signals contributed.</p>
              )}
            </Panel>

            <Panel title="Model component" subtitle="Expert-weighted logistic, per-feature contributions">
              {model && model.contributions.length > 0 ? (
                <div className="space-y-2">
                  {model.contributions.map((c) => (
                    <div key={c.feature}>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-c2">{c.feature.replace(/_/g, ' ')}</span>
                        <span className="tabular-nums text-c3">×{c.weight} · +{c.contribution.toFixed(2)}</span>
                      </div>
                      <div className="mt-1 h-1 overflow-hidden rounded-full bg-sunken">
                        <div className="h-full rounded-full bg-brand" style={{ width: `${Math.min(100, c.value * 100)}%` }} />
                      </div>
                    </div>
                  ))}
                  <p className="text-xs mt-2 text-c3">{model.provenance}</p>
                </div>
              ) : (
                <p className="text-sm text-c2">The model found no contributing features (score near the {model?.bias ?? '−'} bias floor).</p>
              )}
            </Panel>
          </div>

          {/* YARA + IOCs */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Panel title="YARA matches" subtitle={`${yaraHits.length} rule${yaraHits.length === 1 ? '' : 's'} matched`}>
              {yaraHits.length === 0 ? (
                <p className="text-sm text-c2">No YARA rules matched.</p>
              ) : (
                <div className="space-y-2">
                  {yaraHits.map((h, i) => (
                    <div key={i} className="flex items-start gap-2.5">
                      <Chip tone={SEVERITY_TONE[h.severity] ?? 'neutral'}>{h.severity}</Chip>
                      <div className="min-w-0">
                        <p className="text-body font-medium text-c1">{h.title}</p>
                        {h.detail && <p className="text-sm text-c2">{h.detail}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            <Panel title="Indicators of compromise" subtitle={iocEntries.length ? undefined : 'None extracted'}>
              {iocEntries.length === 0 ? (
                <p className="text-sm text-c2">No indicators were extracted from this sample.</p>
              ) : (
                <div className="space-y-3">
                  {iocEntries.map(([key, values]) => (
                    <div key={key}>
                      <GroupLabel>{iocLabel(key)}</GroupLabel>
                      <div className="space-y-1">
                        {values.map((v) => (
                          <div key={v} className="tech rounded-chip bg-sunken px-2 py-1 text-c2">
                            {v}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </div>

          {/* Archive members */}
          {job.children && job.children.length > 0 && (
            <Panel title="Archive contents" subtitle="An archive is as dangerous as its worst member">
              <div className="divide-hair -my-2">
                {job.children.map((c) => (
                  <Link
                    key={c.public_id}
                    to={`/job/${c.public_id}`}
                    className="flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-raised"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-body text-c1">{c.original_name || c.sha256.slice(0, 16)}</p>
                      <p className="tech text-c3">{familyLabel(c.family)}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <Status value={c.status} />
                      <span className="tabular-nums text-sm font-semibold text-c1">{c.final_score.toFixed(0)}</span>
                      <ChevronRight size={16} className="text-c3" aria-hidden />
                    </div>
                  </Link>
                ))}
              </div>
            </Panel>
          )}

          {/* Feedback */}
          <Panel title="Analyst feedback" subtitle="Dispute the verdict — it feeds the reanalysis loop">
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant={job.feedback === 'false_positive' ? 'primary' : 'secondary'}
                busy={busy === 'fp'}
                onClick={() => action('fp', () => api.post(`/api/jobs/${id}/feedback`, { verdict: 'false_positive' }))}
              >
                <Flag size={14} aria-hidden /> Mark false positive
              </Button>
              <Button
                variant={job.feedback === 'true_positive' ? 'primary' : 'secondary'}
                busy={busy === 'tp'}
                onClick={() => action('tp', () => api.post(`/api/jobs/${id}/feedback`, { verdict: 'true_positive' }))}
              >
                <FileText size={14} aria-hidden /> Confirm true positive
              </Button>
              {job.feedback && (
                <span className="text-sm text-c2">
                  Recorded: {job.feedback === 'false_positive' ? 'false positive' : 'true positive'}
                </span>
              )}
            </div>
          </Panel>

          {/* Raw analysis */}
          <Panel title="Raw analysis payload" tone="quiet">
            <CodeBlock maxHeight={280}>{JSON.stringify(job.analysis, null, 2)}</CodeBlock>
          </Panel>
        </>
      )}
    </div>
  )
}
