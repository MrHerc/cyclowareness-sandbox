import { type CSSProperties } from 'react'
import { CheckCircle2, Circle, Cpu, ShieldAlert, ShieldCheck } from 'lucide-react'
import { LoadState, PageHeader, Panel, Chip, Metric, StaleNotice } from '../components/ui'
import { api } from '../lib/api'
import { usePoll } from '../lib/usePoll'
import type { Capabilities, EngineDescriptor } from '../lib/types'

const KIND_LABEL: Record<string, string> = {
  native: 'Native engine',
  emulator: 'Emulator',
  'opensource-sandbox': 'Open-source sandbox',
  'threat-intel': 'Threat intelligence',
}

function EngineCard({ e, i = 0, sovereign }: { e: EngineDescriptor; i?: number; sovereign: boolean }) {
  return (
    <div className="rise-in lift rounded-control border border-hair bg-panel p-4" style={{ '--i': i } as CSSProperties}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-body font-medium text-c1">{e.name}</p>
          {e.vendor && <p className="text-xs text-c3">{e.vendor}</p>}
        </div>
        {/* `configured` means credentials are present, which is not the same as
            "will run". A sovereign deployment that kept a VirusTotal key must
            show the key AND the refusal, or a green tick reads as proof the
            lookup happened. The API has always said which; this card used to
            read only the first half. */}
        {e.configured && e.blocked_by_sovereign_mode ? (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-warning">
            <ShieldAlert size={14} aria-hidden /> Refused
          </span>
        ) : e.configured ? (
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
      {/* WHOSE ENVIRONMENT THIS STATUS WAS READ FROM.
          Shown for every worker-run engine regardless of the status above,
          because it qualifies all of them: a green "Enabled" and a grey
          "Available" are equally a reading of the web service's environment for
          an engine the worker runs. */}
      {e.configured_on_worker && e.configuration_caveat && (
        <p className="text-xs mt-2 text-c3">{e.configuration_caveat}</p>
      )}
      {e.configured && e.blocked_by_sovereign_mode ? (
        <p className="text-xs mt-2 text-warning">
          Credentials are present, but sovereign mode refuses this call — nothing is sent.
        </p>
      ) : (
        /* Only tell an operator to set an env var when setting it would work.
           On a sovereign deployment this instruction was unfollowable advice. */
        e.requires &&
        !e.configured && (
          <p className="text-xs mt-2 text-c3">
            {e.sends_data_off_host && sovereign
              ? `Would send data off-host; sovereign mode must be relaxed first. Then: ${e.requires}`
              : `Enable: ${e.requires}`}
          </p>
        )
      )}
    </div>
  )
}

export function Integrations() {
  const { data: caps, error, stale, refresh } = usePoll<Capabilities>(() => api.get('/api/capabilities'), 10000)

  if (!caps) {
    return (
      <div className="space-y-6">
        <PageHeader title="Integrations and capabilities" />
        <LoadState error={error} label="Loading capabilities" onRetry={refresh} />
      </div>
    )
  }

  // "Enabled" has to mean "will actually run". Counting `configured` alone put
  // engines that sovereign mode refuses on every call into the green tile.
  const running = caps.integrations.filter((e) => e.configured && !e.blocked_by_sovereign_mode)
  const refused = caps.integrations.filter((e) => e.configured && e.blocked_by_sovereign_mode)
  const configured = running.length
  const dynamic = caps.integrations.filter((e) => e.tier === 'dynamic')
  const staticIntel = caps.integrations.filter((e) => e.tier === 'static')

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrations and capabilities"
        lede="What this deployment can honestly do. Static analysis runs here; dynamic engines run on the operator's isolated worker."
      />

      {stale && <StaleNotice error={error} onRetry={refresh} />}

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Metric label="Static analyzers" value={caps.static_analyzers.length} size="sm" />
        <Metric label="YARA rules" value={caps.yara.loaded} size="sm" />
        <Metric label="Engines" value={caps.integrations.length} size="sm" />
        <Metric
          label="Running now"
          value={configured}
          size="sm"
          tone={configured >= 4 ? 'success' : 'warning'}
          caption={refused.length ? `${refused.length} configured but refused` : undefined}
        />
      </div>

      {/* THE CLAIM THIS PRODUCT IS SOLD ON.
          `/api/capabilities` has always published `sovereignty` and `retention`
          — the sovereignty posture with its refusal count, and the answer to the
          question every DPA asks — and nothing in the interface read either of
          them. The one thing a sovereign deployment exists to prove was
          invisible inside the deployment. */}
      <Panel
        title="Data sovereignty"
        subtitle="Where analysis data may go, and what has been refused"
      >
        <div className="flex items-start gap-3">
          {caps.sovereignty?.enabled ? (
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-success" aria-hidden />
          ) : (
            <ShieldAlert size={18} className="mt-0.5 shrink-0 text-warning" aria-hidden />
          )}
          <div className="min-w-0">
            <p className="text-body text-c1">
              {caps.sovereignty?.statement ?? 'Sovereignty posture not reported by this build.'}
            </p>
            {caps.sovereignty && (
              <p className="text-sm mt-1 text-c2">
                {/* The count is what makes it checkable rather than asserted. */}
                {caps.sovereignty.outbound_refusals?.total ?? 0} outbound call
                {caps.sovereignty.outbound_refusals?.total === 1 ? '' : 's'} refused ·{' '}
                {caps.sovereignty.destinations?.filter((d) => !d.allowed).length ?? 0} of{' '}
                {caps.sovereignty.destinations?.length ?? 0} destinations closed
              </p>
            )}
          </div>
        </div>
        {caps.sovereignty?.destinations?.length ? (
          <div className="divide-hair mt-4">
            {caps.sovereignty.destinations.map((d) => (
              <div key={d.key} className="flex items-start justify-between gap-3 py-2">
                <p className="min-w-0 text-sm text-c2">{d.what_would_leave}</p>
                <Chip tone={d.allowed ? (d.is_deliberate_exception ? 'info' : 'warning') : 'success'}>
                  {d.allowed ? (d.is_deliberate_exception ? 'Allowed by design' : 'Open') : 'Blocked'}
                </Chip>
              </div>
            ))}
          </div>
        ) : null}
        {caps.retention && (
          <p className="text-sm mt-4 border-t border-hair pt-3 text-c2">{caps.retention.statement}</p>
        )}
      </Panel>

      <Panel title="Dynamic engines" subtitle="Detonation and behaviour — run off-host on an isolated worker">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {dynamic.map((e, i) => (
            <EngineCard key={e.key} e={e} i={i} sovereign={!!caps.sovereignty?.enabled} />
          ))}
        </div>
      </Panel>

      <Panel title="Static and intelligence engines" subtitle="Safe to run in-process — no sample is executed">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {staticIntel.map((e, i) => (
            <EngineCard key={e.key} e={e} i={i} sovereign={!!caps.sovereignty?.enabled} />
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
              {/* NOT "AI provider: <vendor>". `ai_provider` is hard-wired to
                  "template" because no LLM is called anywhere in this codebase,
                  so the old line rendered "AI provider: template" — a vendor
                  field naming a non-vendor, on the one page that exists to say
                  what this deployment talks to. */}
              <p className="text-xs mt-2 text-c3">
                Narrative: written by a deterministic template. No language model is
                called; the score never depends on one.
              </p>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
