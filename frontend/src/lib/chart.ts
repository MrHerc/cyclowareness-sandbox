// Chart colour access. Colours still live only in index.css — this reads the
// resolved design tokens off :root so Recharts (which needs literal colour
// strings) stays in sync with the theme. Re-read on each render; a theme toggle
// is reflected on the next poll.

export function cssVar(name: string): string {
  if (typeof window === 'undefined') return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

/**
 * Verdict colours. Separate from `riskColors` because a verdict is not a score
 * band: a sample can be called malicious at a score of 24, and colouring it by
 * the band would paint that slice green.
 */
export function verdictColors(): Record<string, string> {
  return {
    malicious: cssVar('--color-danger'),
    suspicious: cssVar('--color-warning'),
    clean: cssVar('--color-success'),
    unclassified: cssVar('--color-c3'),
  }
}

export function brandColor(): string {
  return cssVar('--color-brand')
}
