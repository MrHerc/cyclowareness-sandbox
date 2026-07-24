import type { TimelineEvent } from '../lib/types'

/**
 * A behaviour timeline: what the sample did, in order, once detonated on the
 * off-host worker. One lane per event kind, dots placed on a shared millisecond
 * axis — the "graph visualizing file behaviours" the brief asks for. Pure SVG,
 * so it themes with the rest of the instrument and needs no chart library.
 */

const KIND_TONE: Record<string, string> = {
  process: 'fill-brand',
  network: 'fill-danger',
  file: 'fill-info',
  registry: 'fill-warning',
  memory: 'fill-danger',
  syscall: 'fill-c3',
}

function toneFor(kind: string): string {
  return KIND_TONE[kind] ?? 'fill-c3'
}

export function BehaviorGraph({ events }: { events: TimelineEvent[] }) {
  if (!events.length) return null

  const sorted = [...events].sort((a, b) => a.t_ms - b.t_ms)
  const kinds = Array.from(new Set(sorted.map((e) => e.kind)))
  const maxT = Math.max(1, ...sorted.map((e) => e.t_ms))

  const padL = 88
  const padR = 16
  const padT = 12
  const rowH = 30
  const width = 720
  const axisH = 22
  const plotW = width - padL - padR
  const height = padT + kinds.length * rowH + axisH

  const x = (t: number) => padL + (t / maxT) * plotW
  const ticks = 5

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full min-w-[560px]" role="img" aria-label="Behaviour timeline">
        {/* lane guides + labels */}
        {kinds.map((kind, i) => {
          const y = padT + i * rowH + rowH / 2
          return (
            <g key={kind}>
              <line x1={padL} y1={y} x2={width - padR} y2={y} className="stroke-hair" strokeWidth={1} />
              <text x={padL - 10} y={y + 4} textAnchor="end" className="fill-c2 text-[11px]">
                {kind}
              </text>
            </g>
          )
        })}

        {/* axis ticks */}
        {Array.from({ length: ticks + 1 }, (_, i) => {
          const t = (maxT / ticks) * i
          const xx = x(t)
          const yy = padT + kinds.length * rowH
          return (
            <g key={i}>
              <line x1={xx} y1={padT} x2={xx} y2={yy} className="stroke-hair" strokeWidth={1} strokeDasharray="2 4" />
              <text x={xx} y={yy + 15} textAnchor="middle" className="fill-c3 text-[10px]">
                {Math.round(t)} ms
              </text>
            </g>
          )
        })}

        {/* events */}
        {sorted.map((e, i) => {
          const laneIndex = kinds.indexOf(e.kind)
          const y = padT + laneIndex * rowH + rowH / 2
          return (
            <g key={i}>
              <circle cx={x(e.t_ms)} cy={y} r={5} className={toneFor(e.kind)}>
                <title>{`${e.t_ms} ms · ${e.kind}: ${e.detail}`}</title>
              </circle>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
