import { riskTone, verdictWord } from '../lib/format'

const TONE_STROKE: Record<string, string> = {
  danger: 'stroke-danger',
  warning: 'stroke-warning',
  success: 'stroke-success',
}
const TONE_TEXT: Record<string, string> = {
  danger: 'text-danger',
  warning: 'text-warning',
  success: 'text-success',
}

/** A 270-degree arc gauge for the final 0-100 risk score, banded by verdict. */
export function ScoreGauge({ score, riskLevel }: { score: number; riskLevel: string }) {
  const tone = riskTone(riskLevel)
  const size = 168
  const stroke = 12
  const r = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  const startAngle = 135
  const sweep = 270
  const clamped = Math.max(0, Math.min(100, score))

  const polar = (angleDeg: number) => {
    const a = (angleDeg * Math.PI) / 180
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) }
  }
  const arcPath = (fromDeg: number, toDeg: number) => {
    const start = polar(fromDeg)
    const end = polar(toDeg)
    const large = toDeg - fromDeg > 180 ? 1 : 0
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 1 ${end.x} ${end.y}`
  }

  const trackEnd = startAngle + sweep
  const valueEnd = startAngle + (sweep * clamped) / 100

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full">
          <path d={arcPath(startAngle, trackEnd)} className="stroke-sunken" strokeWidth={stroke} fill="none" strokeLinecap="round" />
          <path
            d={arcPath(startAngle, Math.max(startAngle + 0.01, valueEnd))}
            className={TONE_STROKE[tone]}
            strokeWidth={stroke}
            fill="none"
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-display font-semibold tabular-nums ${TONE_TEXT[tone]}`}>{Math.round(score)}</span>
          <span className="text-xs text-c3">of 100</span>
        </div>
      </div>
      <span className={`label mt-1 ${TONE_TEXT[tone]}`}>{verdictWord(riskLevel)}</span>
    </div>
  )
}
