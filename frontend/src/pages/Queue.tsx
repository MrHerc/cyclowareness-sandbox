import { type MouseEvent, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { FileSearch } from 'lucide-react'
import {
  Button,
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
import type { JobPage } from '../lib/types'

const TERMINAL = new Set(['completed', 'failed', 'awaiting_password'])

/**
 * The API's own ceiling is 200; fifty is a screenful. The point of the pager is
 * not the page size — it is that the rows past the first page are reachable at
 * all. They were not: this page sent no parameters, took the default 50, and
 * said "Every sample submitted to this deployment" over the top of them.
 */
const PAGE = 50

export function Queue() {
  const navigate = useNavigate()
  // A stack of cursors, one per page walked. The API hands back the cursor for
  // the NEXT page; keeping the ones already used is what makes "Newer" work
  // without asking the server to count backwards.
  //
  // Cursors rather than offsets because this page POLLS EVERY THREE SECONDS
  // against a queue whose whole purpose is that things arrive in it. OFFSET
  // counts rows from the top, so one submission landing between two clicks
  // showed the last row of page one again at the top of page two — and a
  // retention sweep in the same window hid a row on no page at all.
  const [trail, setTrail] = useState<(string | null)[]>([null])
  const cursor = trail[trail.length - 1]
  const { data, error, stale, refresh } = usePoll<JobPage>(
    () => api.get(`/api/jobs?limit=${PAGE}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`),
    3000,
    [cursor],
  )
  const pageIndex = trail.length - 1
  const offset = pageIndex * PAGE
  const jobs = data?.items ?? []
  const total = data?.total ?? 0
  const shownFrom = total === 0 ? 0 : offset + 1
  const shownTo = offset + jobs.length

  // An empty PAGE is not an empty DEPLOYMENT. Retention deletes rows and the
  // page polls every three seconds, so an offset can outlive the rows behind
  // it — and branching on `jobs.length` alone put "Nothing analysed yet" over a
  // table of 271 samples with no control left on screen to get back, because
  // the pager lived inside the other branch.
  const pagedPastTheEnd = total > 0 && jobs.length === 0 && pageIndex > 0

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
        ) : pagedPastTheEnd ? (
          <div className="p-5 space-y-3">
            <Empty icon={<FileSearch size={20} aria-hidden />}>
              Nothing on this page — the queue holds {total} sample{total === 1 ? '' : 's'}.
            </Empty>
            <div className="flex justify-center">
              <Button size="sm" onClick={() => setTrail([null])}>
                Back to the newest
              </Button>
            </div>
          </div>
        ) : jobs.length === 0 ? (
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
                {jobs.map((job) => (
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

            {/* Say which rows these are. The page used to show fifty and let the
                header call them everything; on this deployment that was fifty of
                269, with no way to ask for the rest. */}
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm text-c3 tabular-nums">
                Showing {shownFrom}–{shownTo} of {total}
              </p>
              {total > PAGE && (
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={pageIndex === 0}
                    onClick={() => setTrail((t) => t.slice(0, -1))}
                  >
                    Newer
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!data?.next_cursor}
                    onClick={() => setTrail((t) => [...t, data?.next_cursor ?? null])}
                  >
                    Older
                  </Button>
                </div>
              )}
            </div>
          </div>
        )}
      </Panel>
    </div>
  )
}
