import { useEffect, useState } from 'react'
import { riskTone, verdictWord } from '../lib/format'
import { useCountUp } from '../lib/useCountUp'

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

/** A 270-degree arc gauge for the final 0-100 risk score. The arc draws itself
 * in and the figure counts up on mount; banded by verdict (risk = red/amber/green). */
export function ScoreGauge({ score, riskLevel }: { score: number; riskLevel: string }) {
  const tone = riskTone(riskLevel)
  const size = 176
  const stroke = 12
  const r = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  const startAngle = 135
  const sweep = 270
  const clamped = Math.max(0, Math.min(100, score))
  const shown = useCountUp(score)

  // Drive the arc draw: render empty first, then transition to the value.
  const [progress, setProgress] = useState(0)
  useEffect(() => {
    const raf = requestAnimationFrame(() => setProgress(clamped))
    return () => cancelAnimationFrame(raf)
  }, [clamped])

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

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} className="h-full w-full">
          {/* track */}
          <path d={arcPath(startAngle, trackEnd)} className="stroke-sunken" strokeWidth={stroke} fill="none" strokeLinecap="round" />
          {/* value — a full-length path revealed by dash offset */}
          <path
            d={arcPath(startAngle, trackEnd)}
            className={`gauge-arc ${TONE_STROKE[tone]}`}
            strokeWidth={stroke}
            fill="none"
            strokeLinecap="round"
            pathLength={100}
            strokeDasharray={100}
            strokeDashoffset={100 - progress}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-display font-semibold tabular-nums ${TONE_TEXT[tone]}`}>{Math.round(shown)}</span>
          <span className="text-xs text-c3">of 100</span>
        </div>
      </div>
      <span className={`label mt-1 ${TONE_TEXT[tone]}`}>{verdictWord(riskLevel)}</span>
    </div>
  )
}
