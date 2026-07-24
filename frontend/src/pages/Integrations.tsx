import { CheckCircle2, Circle, Cpu } from 'lucide-react'
import { LoadState, PageHeader, Panel, Chip, Metric } from '../components/ui'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import type { Capabilities, EngineDescriptor } from '../lib/types'

const KIND_LABEL: Record<string, string> = {
  native: 'Native engine',
  emulator: 'Emulator',
  'opensource-sandbox': 'Open-source sandbox',
  'threat-intel': 'Threat intelligence',
}

function EngineCard({ e }: { e: EngineDescriptor }) {
  return (
    <div className="rounded-control border border-hair bg-panel p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-body font-medium text-c1">{e.name}</p>
          {e.vendor && <p className="text-xs text-c3">{e.vendor}</p>}
        </div>
        {e.configured ? (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-success">
            <CheckCircle2 size={14} aria-hidden /> Enabled
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-xs text-c3">
            <Circle size={14} aria-hidden /> Available
          </span>
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        <Chip tone="neutral">{KIND_LABEL[e.kind] ?? e.kind}</Chip>
        <Chip tone={e.tier === 'dynamic' ? 'brand' : 'info'}>{e.tier}</Chip>
      </div>
      {e.notes && <p className="text-sm mt-2 text-c2">{e.notes}</p>}
      {e.requires && !e.configured && <p className="text-xs mt-2 text-c3">Enable: {e.requires}</p>}
    </div>
  )
}

export function Integrations() {
  const { data: caps, error, refresh } = usePoll<Capabilities>(() => api.get('/api/capabilities'), 10000)

  if (!caps) {
    return (
      <div className="space-y-6">
        <PageHeader title="Integrations and capabilities" />
        <LoadState error={error} label="Loading capabilities" onRetry={refresh} />
      </div>
    )
  }

  const configured = caps.integrations.filter((e) => e.configured).length
  const dynamic = caps.integrations.filter((e) => e.tier === 'dynamic')
  const staticIntel = caps.integrations.filter((e) => e.tier === 'static')

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrations and capabilities"
        lede="What this deployment can honestly do. Static analysis runs here; dynamic engines run on the operator's isolated worker."
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Metric label="Static analyzers" value={caps.static_analyzers.length} size="sm" />
        <Metric label="YARA rules" value={caps.yara.loaded} size="sm" />
        <Metric label="Engines" value={caps.integrations.length} size="sm" />
        <Metric
          label="Enabled now"
          value={configured}
          size="sm"
          tone={configured >= 4 ? 'success' : 'warning'}
        />
      </div>

      <Panel title="Dynamic engines" subtitle="Detonation and behaviour — run off-host on an isolated worker">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {dynamic.map((e) => (
            <EngineCard key={e.key} e={e} />
          ))}
        </div>
      </Panel>

      <Panel title="Static and intelligence engines" subtitle="Safe to run in-process — no sample is executed">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {staticIntel.map((e) => (
            <EngineCard key={e.key} e={e} />
          ))}
        </div>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Static analyzers" subtitle="Per-family parsers, dispatched by content type">
          <div className="flex flex-wrap gap-1.5">
            {caps.static_analyzers.map((a) => (
              <Chip key={a} tone="neutral">
                {a}
              </Chip>
            ))}
          </div>
          {Object.keys(caps.unavailable_analyzers || {}).length > 0 && (
            <p className="text-xs mt-3 text-warning">
              Unavailable: {Object.keys(caps.unavailable_analyzers).join(', ')}
            </p>
          )}
        </Panel>

        <Panel title="Scoring model">
          <div className="flex items-start gap-3">
            <Cpu size={18} className="mt-0.5 shrink-0 text-brand-fg" aria-hidden />
            <div>
              <p className="text-body text-c1">{caps.scoring.model}</p>
              <p className="text-sm mt-1 text-c2">
                Aggregation split: rule {caps.scoring.weights.rule} · model {caps.scoring.weights.model}. Tunable
                under Tuning.
              </p>
              <p className="text-xs mt-2 text-c3">AI provider: {caps.ai_provider}</p>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
