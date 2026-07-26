import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { brandColor, cssVar, verdictColors } from '../lib/chart'

interface Slice {
  key: string
  label: string
  value: number
}

function TooltipBox({ active, payload }: { active?: boolean; payload?: { name?: string; value?: number; payload?: { label?: string } }[] }) {
  if (!active || !payload?.length) return null
  const p = payload[0]
  const label = p.payload?.label ?? p.name
  return (
    <div className="rounded-control border border-line bg-panel px-2.5 py-1.5 text-xs shadow-lg">
      <span className="text-c2">{label}: </span>
      <span className="font-semibold tabular-nums text-c1">{p.value}</span>
    </div>
  )
}

/**
 * Verdict distribution as a donut. Verdicts use the reserved status palette
 * (red/amber/green), never the brand accent, and every slice is also named in
 * the legend so identity is never colour-alone.
 */
export function VerdictDonut({ slices, total }: { slices: Slice[]; total: number }) {
  const colors = verdictColors()
  const data = slices.filter((s) => s.value > 0)
  const panel = cssVar('--color-panel')

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:gap-6">
      <div className="relative h-[180px] w-[180px] shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data.length ? data : [{ key: 'empty', label: 'No data', value: 1 }]}
              dataKey="value"
              nameKey="label"
              innerRadius={58}
              outerRadius={82}
              paddingAngle={data.length > 1 ? 2 : 0}
              stroke={panel}
              strokeWidth={2}
              startAngle={90}
              endAngle={-270}
              isAnimationActive
            >
              {(data.length ? data : [{ key: 'empty' }]).map((s) => (
                <Cell key={s.key} fill={data.length ? colors[s.key] ?? cssVar('--color-c3') : cssVar('--color-sunken')} />
              ))}
            </Pie>
            {data.length > 0 && <Tooltip content={<TooltipBox />} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-title font-semibold tabular-nums text-c1">{total}</span>
          <span className="text-xs text-c3">analysed</span>
        </div>
      </div>

      <ul className="w-full space-y-1.5">
        {slices.map((s) => (
          <li key={s.key} className="flex items-center justify-between gap-3 text-sm">
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: colors[s.key] }} aria-hidden />
              <span className="text-c2">{s.label}</span>
            </span>
            <span className="tabular-nums font-medium text-c1">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Counts per file family — one measure, one hue (brand), horizontal bars. */
export function FamilyBars({ data }: { data: { label: string; count: number }[] }) {
  if (!data.length) {
    return <p className="text-sm text-c2">No samples yet.</p>
  }
  const brand = brandColor()
  const axis = cssVar('--color-c3')
  const height = Math.max(120, data.length * 34)

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="label"
          width={104}
          tickLine={false}
          axisLine={false}
          tick={{ fill: axis, fontSize: 12 }}
        />
        <Tooltip cursor={{ fill: cssVar('--color-raised') }} content={<TooltipBox />} />
        <Bar dataKey="count" fill={brand} radius={[0, 4, 4, 0]} maxBarSize={22} isAnimationActive />
      </BarChart>
    </ResponsiveContainer>
  )
}
