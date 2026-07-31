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
  ShieldCheck,
  Siren,
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
  StaleNotice,
  Status,
  cx,
  timeAgo,
} from '../components/ui'
import { ScoreGauge } from '../components/ScoreGauge'
import { BehaviorGraph } from '../components/BehaviorGraph'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import {
  familyLabel,
  formatBytes,
  impactOf,
  iocLabel,
  verdictHeadline,
  verdictOf,
  verdictTone,
} from '../lib/format'
import type { JobDetailT, MitreTechnique, SignalT } from '../lib/types'

const SEVERITY_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const SEVERITY_TONE: Record<string, 'danger' | 'warning' | 'neutral'> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'neutral',
  info: 'neutral',
}
const TONE_TEXT: Record<string, string> = {
  danger: 'text-danger',
  warning: 'text-warning',
  success: 'text-success',
}
/** Long form of the impact-rating metric letters, so the vector is readable. */
const IMPACT_METRIC: Record<string, string> = {
  AV: 'Attack vector',
  AC: 'Attack complexity',
  PR: 'Privileges required',
  UI: 'User interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
}

/** ATT&CK reads by tactic, not as a flat list of technique IDs. */
function byTactic(techniques: MitreTechnique[]): [string, MitreTechnique[]][] {
  const groups = new Map<string, MitreTechnique[]>()
  // The backend already sorts by the kill-chain order of the tactic, so
  // insertion order is that order — do not re-sort.
  for (const t of techniques) {
    const list = groups.get(t.tactic)
    if (list) list.push(t)
    else groups.set(t.tactic, [t])
  }
  return Array.from(groups.entries())
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
  const { data: job, error, stale, refresh } = usePoll<JobDetailT>(
    () => api.get(`/api/result/${id}`),
    2000,
    [id],
  )
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  /**
   * Every button on this page goes through here. It used to be try/finally with
   * no catch, so a rejected promise cleared the spinner and vanished: a wrong
   * archive password (422), a re-analyse on a job that is already running (409)
   * and an export of a report that no longer exists (404) all looked exactly
   * like success. The failure has to be shown, and it has to survive the next
   * poll tick — hence state, not a toast.
   */
  async function action(name: string, fn: () => Promise<unknown>) {
    setBusy(name)
    setActionError(null)
    try {
      await fn()
      await refresh()
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e))
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
  // THREE STATES, NOT TWO. The analyzer either ran and matched, ran and matched
  // nothing, or did not run at all — and this used to collapse the last two into
  // "0 rules matched", which reads as a clean bill of health from a scan that
  // never happened. `yaraResult` keeps the distinction; `yaraRan` is the gate.
  const yaraResult = job.analysis?.yara
  const yaraRan = Boolean(yaraResult?.ran)
  const yaraHits = (yaraRan && yaraResult?.signals) || []
  const filename = job.original_name || 'sample'
  // All three are absent on jobs analysed before the verdict engine shipped.
  const verdict = verdictOf(job)
  const detection = verdict ? job.verdict ?? null : null
  const impact = impactOf(job)
  const mitre = Array.isArray(job.mitre) ? job.mitre : []

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
            {/* Both of these existed, worked, and could not be reached from the
                product. `export.signed` is the Ed25519-attested evidence copy —
                the whole reason attestation.py is in the repo — and
                `export.incident` is the NIS2/DORA notification record. A
                capability nobody can find is a capability the deployment does
                not have. */}
            <Button size="sm" busy={busy === 'signed'} onClick={() => action('signed', () => api.download(`/api/jobs/${id}/export.signed`, `sandbox-${filename}.signed.json`))} title="Ed25519-signed evidence copy a recipient can verify without trusting us">
              <ShieldCheck size={14} aria-hidden /> Signed
            </Button>
            <Button size="sm" busy={busy === 'incident'} onClick={() => action('incident', () => api.download(`/api/jobs/${id}/export.incident`, `sandbox-${filename}.incident.json`))} title="Regulatory incident record (NIS2 Article 23 / DORA Article 19)">
              <Siren size={14} aria-hidden /> Incident
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

      {actionError && (
        <Callout tone="danger" title="That action did not go through">
          {actionError}
        </Callout>
      )}

      {stale && <StaleNotice error={error} onRetry={refresh} />}

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
              {/* A password that did not work is an ANSWER, not a fresh prompt.
                  The job returns to `awaiting_password` either way, so without
                  this the same box was simply re-drawn and the analyst could not
                  tell a wrong password from a click that did nothing. */}
              {job.error ? (
                <p className="text-sm mt-1 text-warning">{job.error} Try another one.</p>
              ) : (
                <p className="text-sm mt-1 text-c2">
                  Provide the password to continue. It is used once and never stored — the engine does not
                  brute-force.
                </p>
              )}
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

      {/* A COMPLETED job can still carry an error, and 48 on this deployment do.
          `error` was rendered only when status === 'failed', so a sample the
          detonation sandbox REFUSED — "CAPE refused the sample: Linux binaries
          analysis isn't enabled" — read as a finished analysis, and 46 of them
          read `low`. The tier card says "Not run", which is the same words it
          uses when no worker is attached at all. The gap in the evidence has to
          be visible next to the verdict, not one panel further down. */}
      {job.status !== 'failed' && job.error && (
        <Callout tone="warning" title="This analysis is incomplete">
          {job.error} The verdict below rests on the tiers that did run.
        </Callout>
      )}

      {running && (
        <Panel>
          {/* The animation is a claim that progress is being observed. When the
              polls are failing it is not, and saying so beats an indefinite
              "Analysing…" over a stage that stopped changing minutes ago. */}
          <div className={cx('relative flex items-center gap-3 overflow-hidden', !stale && 'scan')}>
            <div className={cx('h-2 w-2 rounded-full', stale ? 'bg-warning' : 'bg-brand breathe')} aria-hidden />
            <span className="text-body text-c2">
              {stale ? (
                <>
                  Progress unknown — last seen at{' '}
                  <span className="text-c1">{job.stage || job.status}</span>
                </>
              ) : (
                <>
                  Analysing — <span className="text-c1">{job.stage || job.status}</span>
                </>
              )}
            </span>
          </div>
        </Panel>
      )}

      {done && (
        <>
          {/* Verdict hero.
              What the reader takes as the answer is the threat name and the
              word above it, and both are driven by the verdict. The 0-100 score
              is shown beside them as a magnitude, never as the decision — five
              droppers the engine had called malicious used to render here as a
              green gauge captioned "Low risk" and nothing else. */}
          <Panel tone="feature">
            <div className="grid gap-6 lg:grid-cols-[1fr_auto] lg:items-center">
              <div className="min-w-0">
                {verdict ? (
                  <>
                    <p className={cx('label', TONE_TEXT[verdictTone(verdict)])}>
                      {verdictHeadline(verdict)}
                    </p>
                    {/* break-all alone split the name mid-word on a phone —
                        "Win32.Ransom.Formb / ook", which reads as a rendering
                        bug rather than as a threat name. A zero-width space
                        after each dot gives the browser a natural place to wrap,
                        so it breaks between the platform, the category and the
                        family instead of through one of them. */}
                    <h2 className={cx('text-display mt-1 break-words', TONE_TEXT[verdictTone(verdict)])}>
                      {(detection?.threat_name || filename).replace(/\./g, '.​')}
                    </h2>
                    <p className="text-body mt-1.5 text-c2">
                      <span className="font-semibold text-c1">{detection?.detection_ratio}</span>{' '}
                      detection engines flagged this sample.
                      {detection?.category ? ` Classified as ${detection.category} on ${detection.platform}.` : ''}
                    </p>
                  </>
                ) : (
                  <>
                    <p className="label text-c3">No verdict recorded</p>
                    <h2 className="text-title mt-1 text-c1">This report predates the verdict engine</h2>
                    <p className="text-body mt-1.5 text-c2">
                      Re-analyse the sample to classify it. Until then the risk score is all this job
                      carries, and a low score is not a clean verdict.
                    </p>
                  </>
                )}
                {impact && (
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Chip tone={SEVERITY_TONE[impact.severity] ?? 'neutral'}>
                      Impact {impact.base_score.toFixed(1)} {impact.severity}
                    </Chip>
                    <span className="tech text-c3">{impact.vector}</span>
                  </div>
                )}
              </div>
              <div className="justify-self-center lg:w-64">
                <ScoreGauge score={job.final_score} riskLevel={job.risk_level} verdict={verdict} />
              </div>
            </div>
          </Panel>

          {/* Multi-engine detection panel — the familiar per-engine breakdown a
              scanner report is read for. */}
          {detection && detection.engines?.length > 0 && (
            <Panel
              title="Detection engines"
              subtitle={`${detection.detection_ratio} flagged this sample`}
            >
              <div className="divide-hair -my-2">
                {[...detection.engines]
                  .sort((a, b) => Number(b.detected) - Number(a.detected))
                  .map((e, i) => (
                    <div key={`${e.engine}-${i}`} className="flex items-center justify-between gap-3 py-2">
                      <span className="tech min-w-0 flex-1 truncate text-c2">{e.engine}</span>
                      {e.detected ? (
                        <span className="flex shrink-0 items-center gap-2">
                          <span className="text-sm font-medium text-c1">{e.result}</span>
                          <Chip tone={SEVERITY_TONE[e.severity] ?? 'neutral'}>{e.severity}</Chip>
                        </span>
                      ) : (
                        <span className="text-sm shrink-0 text-c3">Undetected</span>
                      )}
                    </div>
                  ))}
              </div>
            </Panel>
          )}

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Cyclowareness Impact Rating */}
            <Panel
              title="Cyclowareness Impact Rating"
              subtitle="Severity of what this sample can do, not of the file"
            >
              {impact ? (
                <div className="space-y-3">
                  <div className="flex items-baseline gap-3">
                    <span
                      className={cx(
                        'text-display font-semibold tabular-nums',
                        TONE_TEXT[SEVERITY_TONE[impact.severity] ?? 'neutral'] ?? 'text-c1',
                      )}
                    >
                      {impact.base_score.toFixed(1)}
                    </span>
                    <Chip tone={SEVERITY_TONE[impact.severity] ?? 'neutral'}>{impact.severity}</Chip>
                  </div>
                  <p className="tech text-c3">{impact.vector}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(impact.metrics || {}).map(([m, v]) => (
                      <Chip key={m} tone="neutral">
                        {IMPACT_METRIC[m] ?? m}: {v}
                      </Chip>
                    ))}
                  </div>
                  {(impact.rationale || []).length > 0 && (
                    <div className="space-y-1.5 border-t border-hair pt-3">
                      {impact.rationale.map((r, i) => (
                        <p key={i} className="text-sm text-c2">
                          <span className="tech text-c1">
                            {r.metric}:{r.value}
                          </span>{' '}
                          {r.why}
                        </p>
                      ))}
                    </div>
                  )}
                  {/* Said on the screen and not only in the export: a 0-10 number
                      on a security report is read as CVSS unless it says it isn't. */}
                  <p className="text-sm border-t border-hair pt-3 text-c3">
                    {impact.disclaimer ??
                      'Derived from the capabilities this sample was observed to have. Not a vulnerability score, and not CVSS — the arithmetic is CVSS-compatible so the 0-10 scale reads as expected.'}
                  </p>
                </div>
              ) : (
                <p className="text-sm text-c2">
                  No impact rating on this job — it was analysed before the scoring engine shipped.
                </p>
              )}
            </Panel>

            {/* MITRE ATT&CK */}
            <Panel
              title="MITRE ATT&CK"
              subtitle={`${mitre.length} technique${mitre.length === 1 ? '' : 's'} mapped from observed evidence`}
            >
              {mitre.length === 0 ? (
                <p className="text-sm text-c2">
                  No technique was evidenced. A technique is only claimed when a signal supports it.
                </p>
              ) : (
                <div className="space-y-4">
                  {byTactic(mitre).map(([tactic, techniques]) => (
                    <div key={tactic}>
                      <GroupLabel>{tactic}</GroupLabel>
                      <div className="space-y-2">
                        {techniques.map((t) => (
                          <div key={t.technique_id} className="min-w-0">
                            <p className="text-body font-medium text-c1">
                              <span className="tech text-brand-fg">{t.technique_id}</span> {t.name}
                            </p>
                            {t.evidence?.length > 0 && (
                              <p className="tech text-c3">{t.evidence.join(', ')}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </div>

          <Panel title="Why this score">
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
                    /* `queued`, not `pending`: the engine's own word, and the
                       only one of the two STATUS_TONE now knows. */
                    value={dynamicTier?.ran ? 'completed' : 'queued'}
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
            <Panel
              title="YARA matches"
              subtitle={
                yaraRan
                  ? `${yaraHits.length} rule${yaraHits.length === 1 ? '' : 's'} matched`
                  : 'Not run on this sample'
              }
            >
              {!yaraRan ? (
                <p className="text-sm text-warning">
                  YARA did not run, so this sample has not been checked against the
                  rule set — treat it as unscanned, not as clean.
                  {yaraResult?.unavailable_reason ? ` Reason: ${yaraResult.unavailable_reason}` : ''}
                </p>
              ) : yaraHits.length === 0 ? (
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
                      {/* A member that has not completed carries the column
                          default, and a bold "0" beside its name reads as
                          "analysed, harmless". Queue.tsx already guards this. */}
                      <span className="tabular-nums text-sm font-semibold text-c1">
                        {c.status === 'completed' ? c.final_score.toFixed(0) : '—'}
                      </span>
                      <ChevronRight size={16} className="text-c3" aria-hidden />
                    </div>
                  </Link>
                ))}
              </div>
            </Panel>
          )}

          {/* Feedback.

              The subtitle used to read "it feeds the reanalysis loop". It does
              not: `job.feedback` is written by the route and read by nothing —
              scoring, the pipeline and every export ignore it. Promising an
              analyst that their dispute retrains the engine is how you get them
              to stop reporting once they notice nothing changes. */}
          <Panel
            title="Analyst feedback"
            subtitle="Recorded on this report and in the chain of custody. It does not change the score."
          >
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
