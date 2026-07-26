import { type MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { FileSearch } from 'lucide-react'
import {
  Empty,
  LoadState,
  PageHeader,
  Panel,
  RiskMeter,
  StaleNotice,
  Status,
  TD,
  TH,
  Table,
  timeAgo,
} from '../components/ui'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import { familyLabel, verdictOf } from '../lib/format'
import type { JobSummary } from '../lib/types'

const TERMINAL = new Set(['completed', 'failed', 'awaiting_password'])

export function Queue() {
  const navigate = useNavigate()
  const { data, error, stale, refresh } = usePoll<JobSummary[]>(() => api.get('/api/jobs'), 3000)

  /**
   * Whole-row click, without the row *being* the control.
   *
   * A `<tr onClick>` is invisible to the keyboard and to assistive technology —
   * no role, no tab stop, no Enter handling — which left every report in this
   * product unreachable without a mouse (WCAG 2.1.1 and 4.1.2, both Level A).
   * The real control is the link in the first cell; this handler only widens its
   * hit area for pointer users, and stands down when the pointer was already on
   * the link so the click is not handled twice.
   */
  const rowClick = (e: MouseEvent<HTMLTableRowElement>, publicId: string) => {
    if ((e.target as HTMLElement).closest('a')) return
    navigate(`/job/${publicId}`)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Analysis queue"
        lede="Every sample submitted to this deployment, newest first."
      />

      {stale && <StaleNotice error={error} onRetry={refresh} />}

      <Panel padded={false} className="overflow-hidden">
        {!data ? (
          <div className="p-5">
            <LoadState error={error} label="Loading the queue" onRetry={refresh} />
          </div>
        ) : data.length === 0 ? (
          <div className="p-5">
            <Empty icon={<FileSearch size={20} aria-hidden />}>
              Nothing analysed yet. Submit a file or URL to get started.
            </Empty>
          </div>
        ) : (
          <div className="p-5">
            <Table minWidth={720}>
              <thead>
                <tr>
                  <TH>Sample</TH>
                  <TH>Type</TH>
                  <TH>Source</TH>
                  <TH>Risk</TH>
                  <TH>Status</TH>
                  <TH numeric>Submitted</TH>
                </tr>
              </thead>
              <tbody>
                {data.map((job) => (
                  <tr
                    key={job.public_id}
                    onClick={(e) => rowClick(e, job.public_id)}
                    className="cursor-pointer transition-colors hover:bg-raised"
                  >
                    <TD>
                      <div className="min-w-0">
                        <Link
                          to={`/job/${job.public_id}`}
                          className="block truncate font-medium text-c1 hover:underline"
                        >
                          {job.original_name || 'sample'}
                          <span className="sr-only"> — open analysis report</span>
                        </Link>
                        <div className="tech text-c3">{job.sha256.slice(0, 24)}…</div>
                      </div>
                    </TD>
                    <TD muted>{familyLabel(job.family)}</TD>
                    <TD muted>{job.source === 'url' ? 'URL' : 'Upload'}</TD>
                    <TD>
                      {TERMINAL.has(job.status) && job.status === 'completed' ? (
                        <span className="flex flex-wrap items-center gap-2">
                          <RiskMeter score={job.final_score} />
                          {/* The verdict, where there is one — a score alone has
                              read "20, green" on samples called malicious. */}
                          {verdictOf(job) && <Status value={verdictOf(job) as string} />}
                        </span>
                      ) : (
                        <span className="text-sm text-c3">—</span>
                      )}
                    </TD>
                    <TD>
                      <Status value={job.status} />
                    </TD>
                    <TD numeric muted>
                      {timeAgo(job.created_at)}
                    </TD>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>
    </div>
  )
}
