import { type CSSProperties } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Activity, ArrowRight, Plus, ShieldCheck } from 'lucide-react'
import {
  Button,
  Empty,
  LoadState,
  PageHeader,
  Panel,
  RiskMeter,
  StaleNotice,
  Status,
  cx,
  timeAgo,
} from '../components/ui'
import { VerdictDonut, FamilyBars } from '../components/Charts'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import { familyLabel, verdictOf } from '../lib/format'
import { useCountUp } from '../lib/useCountUp'
import type { JobStats } from '../lib/types'

/**
 * The dashboard buckets by the engine's verdict, not by the score band. The
 * band legend it replaces filed every sample under 30 as "Low / clean" — which
 * put five samples the engine had called malicious under a row captioned clean.
 *
 * `unclassified` is not a synonym for clean: it is a job the verdict engine
 * never saw (analysed before it shipped, or a summary payload that omits it).
 * Naming it is the honest alternative to guessing a verdict from the score.
 */
const VERDICT_BUCKETS = [
  { key: 'malicious', label: 'Malicious' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'clean', label: 'Clean' },
  { key: 'unclassified', label: 'Not classified' },
]

const TONE_TEXT: Record<string, string> = {
  danger: 'text-danger',
  warning: 'text-warning',
  success: 'text-success',
  brand: 'text-brand-fg',
  neutral: 'text-c1',
}

/**
 * One tile may be `hero` — filled with the accent, the way the reference fills
 * its headline metric. It is `Analysed`, and it is deliberately the boring one.
 *
 * `Malicious` would have been the striking choice and it is the one the palette
 * forbids: the accent is not a status colour (rule 2 in index.css), and filling
 * the malware count with it teaches a viewer that lime means danger, three
 * inches from a red `Malicious` chip that also means danger. A neutral total
 * carries the accent without claiming anything.
 *
 * Captions are one or two words now. Each tile used to carry a full sentence —
 * "flagged or unclassified above the floor" under a number — and four of those
 * across a row is a paragraph pretending to be a metric strip. The sentence
 * moved to the `title` attribute, where it is still available on hover and no
 * longer competes with the figure it explains.
 */
function StatTile({
  label,
  value,
  tone = 'neutral',
  caption,
  hint,
  hero = false,
  i = 0,
}: {
  label: string
  value: number
  tone?: keyof typeof TONE_TEXT
  caption?: string
  hint?: string
  hero?: boolean
  i?: number
}) {
  const v = useCountUp(value)
  return (
    <div
      className={cx(
        'rise-in lift rounded-panel border px-5 py-5',
        hero ? 'border-brand bg-brand' : 'border-hair bg-panel',
      )}
      style={{ '--i': i } as CSSProperties}
      title={hint}
    >
      <div className={cx('label', hero ? 'text-on-brand/70' : 'text-c3')}>{label}</div>
      <div
        className={cx(
          'mt-2.5 text-display font-semibold tabular-nums',
          hero ? 'text-on-brand' : TONE_TEXT[tone],
        )}
      >
        {Math.round(v)}
      </div>
      {caption && (
        <div className={cx('text-xs mt-1.5', hero ? 'text-on-brand/70' : 'text-c3')}>{caption}</div>
      )}
    </div>
  )
}

export function Dashboard() {
  const navigate = useNavigate()
  // Counted over the whole tenant, not over a page. Deriving these from
  // `/api/jobs` meant the tiles described the last 50 rows and called it the
  // deployment: "Analysed" read 50 against 269, "Malicious" 10 against 151.
  const { data, error, stale, refresh } = usePoll<JobStats>(
    () => api.get('/api/jobs/stats'),
    4000,
  )

  if (!data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <LoadState error={error} label="Loading the dashboard" onRetry={refresh} />
      </div>
    )
  }

  const running = data.in_flight
  const bucketCount = (k: string) => data.verdicts[k] ?? 0
  const total = data.completed
  const attention = data.needs_attention
  const avg = data.average_score

  const slices = VERDICT_BUCKETS.map((b) => ({ key: b.key, label: b.label, value: bucketCount(b.key) }))

  // Six bars is a readable chart; silently dropping the rest is not an
  // honest one. The remainder is counted so the caption can say so.
  const FAMILY_BARS = 6
  const families = data.families
    .slice(0, FAMILY_BARS)
    .map((f) => ({ label: familyLabel(f.family), count: f.count }))
  const familiesHidden = Math.max(0, data.families.length - FAMILY_BARS)
  const familiesHiddenCount = data.families
    .slice(FAMILY_BARS)
    .reduce((total, f) => total + f.count, 0)

  // Ordered by verdict then magnitude in SQL, for the same reason it used to be
  // ordered that way here: a malicious sample outranks a suspicious one whatever
  // their scores.
  const topRisk = data.top_risk

  return (
    <div className="space-y-6">
      <div className="hero-glow">
        <PageHeader
          title="Overview"
          lede="A live picture of everything this deployment has analysed."
          actions={
            <Button variant="primary" onClick={() => navigate('/submit')}>
              <Plus size={16} aria-hidden /> New analysis
            </Button>
          }
        />
      </div>

      {stale && <StaleNotice error={error} onRetry={refresh} />}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Analysed" value={total} caption="completed" hero i={0} />
        <StatTile
          label="Malicious"
          value={bucketCount('malicious')}
          tone={bucketCount('malicious') ? 'danger' : 'neutral'}
          caption="engine verdict"
          i={1}
        />
        <StatTile
          label="Needs attention"
          value={attention}
          tone={attention ? 'warning' : 'neutral'}
          caption="flagged"
          // Not only the flagged ones: the API also counts a completed job that
          // scored at or above the attention floor without reaching a verdict.
          // Excluding it would hide the "could not classify, looks bad" case —
          // so the caption is short and the full rule is on hover, rather than
          // the rule being dropped to make the caption short.
          hint="Flagged by the engine, or completed above the attention floor without reaching a verdict"
          i={2}
        />
        <StatTile label="Analysing now" value={running} tone={running ? 'brand' : 'neutral'} caption="in the queue" i={3} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Verdict distribution" subtitle={`Average score ${avg.toFixed(0)} across ${total} sample${total === 1 ? '' : 's'}`} className="rise-in" >
          <VerdictDonut slices={slices} total={total} />
        </Panel>

        {/* Six bars is a readable chart. Dropping the rest without saying so
            misstates the shape of the traffic, so the caption counts them. */}
        <Panel
          title="By file type"
          subtitle={
            familiesHidden > 0
              ? `What is being submitted — top ${FAMILY_BARS} of ${data.families.length}, ${familiesHiddenCount} more sample${familiesHiddenCount === 1 ? '' : 's'} not shown`
              : 'What is being submitted'
          }
          className="rise-in"
        >
          <FamilyBars data={families} />
        </Panel>
      </div>

      {/* The API returns five. Saying "everything" over five rows, directly
          under a tile counting hundreds, is two numbers on one screen that
          cannot both be right. */}
      <Panel
        title="Needs attention"
        subtitle={
          attention > topRisk.length
            ? `The ${topRisk.length} worst of ${attention}, worst verdict first`
            : 'Everything the engine flagged, worst verdict first'
        }
        className="rise-in"
        actions={
          <Link to="/queue" className="text-sm inline-flex items-center gap-1 text-brand-fg hover:underline">
            Full queue <ArrowRight size={14} aria-hidden />
          </Link>
        }
      >
        {topRisk.length === 0 ? (
          <Empty icon={<ShieldCheck size={20} aria-hidden />}>
            Nothing flagged yet. Submit a sample to see it here.
          </Empty>
        ) : (
          <div className="divide-hair -my-2">
            {topRisk.map((j) => (
              <Link
                key={j.public_id}
                to={`/job/${j.public_id}`}
                className="flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-raised"
              >
                <div className="min-w-0">
                  <p className="truncate text-body font-medium text-c1">{j.original_name || 'sample'}</p>
                  <p className="text-xs text-c3">
                    {familyLabel(j.family)} · {timeAgo(j.created_at)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <RiskMeter score={j.final_score} />
                  {/* The verdict is the label; the band is only the stand-in for
                      a job that never got one. */}
                  <Status value={verdictOf(j) ?? j.risk_level} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Panel>

      {/* Never claim "live" while the polls are failing — that promise is the
          reason an outage went unnoticed for a whole session. */}
      <p className={cx('flex items-center justify-center gap-1.5 text-xs', stale ? 'text-warning' : 'text-c3')}>
        <Activity size={12} aria-hidden />
        {stale ? 'Not live — the last update did not reach the API' : 'Live — updates every few seconds'}
      </p>
    </div>
  )
}
