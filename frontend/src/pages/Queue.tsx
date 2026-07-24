import { useNavigate } from 'react-router-dom'
import { FileSearch } from 'lucide-react'
import {
  Empty,
  LoadState,
  PageHeader,
  Panel,
  RiskMeter,
  Status,
  TD,
  TH,
  Table,
  timeAgo,
} from '../components/ui'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import { familyLabel } from '../lib/format'
import type { JobSummary } from '../lib/types'

const TERMINAL = new Set(['completed', 'failed', 'awaiting_password'])

export function Queue() {
  const navigate = useNavigate()
  const { data, error, refresh } = usePoll<JobSummary[]>(() => api.get('/api/jobs'), 3000)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Analysis queue"
        lede="Every sample submitted to this deployment, newest first."
      />

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
                    onClick={() => navigate(`/job/${job.public_id}`)}
                    className="cursor-pointer transition-colors hover:bg-raised"
                  >
                    <TD>
                      <div className="min-w-0">
                        <div className="truncate font-medium text-c1">{job.original_name || 'sample'}</div>
                        <div className="tech text-c3">{job.sha256.slice(0, 24)}…</div>
                      </div>
                    </TD>
                    <TD muted>{familyLabel(job.family)}</TD>
                    <TD muted>{job.source === 'url' ? 'URL' : 'Upload'}</TD>
                    <TD>
                      {TERMINAL.has(job.status) && job.status === 'completed' ? (
                        <RiskMeter score={job.final_score} />
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
