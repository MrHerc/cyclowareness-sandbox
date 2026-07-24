import { useEffect, useRef, useState } from 'react'

/**
 * Ease a number from its previous value to `target` on change. Used for stat
 * tiles and the score gauge so figures settle in rather than snapping. Honours
 * reduced-motion by jumping straight to the target.
 */
export function useCountUp(target: number, ms = 900): number {
  const [value, setValue] = useState(target)
  const fromRef = useRef(target)

  useEffect(() => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    const from = fromRef.current
    if (reduce || from === target) {
      setValue(target)
      fromRef.current = target
      return
    }
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ms)
      const eased = 1 - Math.pow(1 - t, 3)
      setValue(from + (target - from) * eased)
      if (t < 1) raf = requestAnimationFrame(tick)
      else fromRef.current = target
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, ms])

  return value
}
