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
  Status,
  cx,
  timeAgo,
} from '../components/ui'
import { VerdictDonut, FamilyBars } from '../components/Charts'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import { familyLabel } from '../lib/format'
import { useCountUp } from '../lib/useCountUp'
import type { JobSummary } from '../lib/types'

const BANDS = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Suspicious' },
  { key: 'low', label: 'Low / clean' },
]

const TONE_TEXT: Record<string, string> = {
  danger: 'text-danger',
  warning: 'text-warning',
  success: 'text-success',
  brand: 'text-brand-fg',
  neutral: 'text-c1',
}

function StatTile({
  label,
  value,
  tone = 'neutral',
  caption,
  i = 0,
}: {
  label: string
  value: number
  tone?: keyof typeof TONE_TEXT
  caption?: string
  i?: number
}) {
  const v = useCountUp(value)
  return (
    <div
      className="rise-in lift rounded-panel border border-hair bg-panel px-4 py-3.5"
      style={{ '--i': i } as CSSProperties}
    >
      <div className="label text-c3">{label}</div>
      <div className={cx('mt-1 text-display font-semibold tabular-nums', TONE_TEXT[tone])}>{Math.round(v)}</div>
      {caption && <div className="text-xs mt-1 text-c3">{caption}</div>}
    </div>
  )
}

export function Dashboard() {
  const navigate = useNavigate()
  const { data, error, refresh } = usePoll<JobSummary[]>(() => api.get('/api/jobs'), 4000)

  if (!data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <LoadState error={error} label="Loading the dashboard" onRetry={refresh} />
      </div>
    )
  }

  const completed = data.filter((j) => j.status === 'completed')
  const running = data.filter((j) => j.status === 'running' || j.status === 'queued').length
  const bandCount = (k: string) => completed.filter((j) => j.risk_level === k).length
  const total = completed.length
  const highPlus = bandCount('critical') + bandCount('high')
  const avg = total ? completed.reduce((s, j) => s + j.final_score, 0) / total : 0

  const slices = BANDS.map((b) => ({ key: b.key, label: b.label, value: bandCount(b.key) }))

  const familyCounts = new Map<string, number>()
  for (const j of data) familyCounts.set(j.family, (familyCounts.get(j.family) ?? 0) + 1)
  const families = Array.from(familyCounts.entries())
    .map(([f, count]) => ({ label: familyLabel(f), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)

  const topRisk = [...completed]
    .filter((j) => j.final_score >= 30)
    .sort((a, b) => b.final_score - a.final_score)
    .slice(0, 5)

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

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Analysed" value={total} caption="completed jobs" i={0} />
        <StatTile label="High or critical" value={highPlus} tone={highPlus ? 'danger' : 'neutral'} caption="need attention" i={1} />
        <StatTile label="Suspicious" value={bandCount('medium')} tone={bandCount('medium') ? 'warning' : 'neutral'} caption="medium band" i={2} />
        <StatTile label="Analysing now" value={running} tone={running ? 'brand' : 'neutral'} caption="in the queue" i={3} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Verdict distribution" subtitle={`Average score ${avg.toFixed(0)} across ${total} sample${total === 1 ? '' : 's'}`} className="rise-in" >
          <VerdictDonut slices={slices} total={total} />
        </Panel>

        <Panel title="By file type" subtitle="What is being submitted" className="rise-in">
          <FamilyBars data={families} />
        </Panel>
      </div>

      <Panel
        title="Needs attention"
        subtitle="Highest-scoring samples"
        className="rise-in"
        actions={
          <Link to="/queue" className="text-sm inline-flex items-center gap-1 text-brand-fg hover:underline">
            Full queue <ArrowRight size={14} aria-hidden />
          </Link>
        }
      >
        {topRisk.length === 0 ? (
          <Empty icon={<ShieldCheck size={20} aria-hidden />}>
            Nothing above the low band yet. Submit a sample to see it here.
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
                  <Status value={j.risk_level} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Panel>

      <p className="flex items-center justify-center gap-1.5 text-xs text-c3">
        <Activity size={12} aria-hidden /> Live — updates every few seconds
      </p>
    </div>
  )
}
