// Small display helpers specific to the sandbox (byte sizes, verdict wording).
// Colour never lives here — tone classes come from index.css via ui.tsx.

import type { ImpactT, VerdictT } from './types'

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

/** Verdict word for a risk band, from the fixed 0-29/30-59/60-79/80-100 scale. */
export function verdictWord(riskLevel: string): string {
  switch (riskLevel) {
    case 'critical':
      return 'Critical'
    case 'high':
      return 'High risk'
    case 'medium':
      return 'Suspicious'
    default:
      return 'Low risk'
  }
}

/** Map a risk band to the ui.tsx status tone vocabulary (risk = red/amber/green). */
export function riskTone(riskLevel: string): 'danger' | 'warning' | 'success' {
  if (riskLevel === 'critical' || riskLevel === 'high') return 'danger'
  if (riskLevel === 'medium') return 'warning'
  return 'success'
}

/* -----------------------------------------------------------------------------
   Verdict
   -----------------------------------------------------------------------------
   The engine's decision and the 0-100 score are different quantities, and the
   interface used to show only the score. Five droppers the engine had called
   `malicious` rendered as a green gauge captioned "Low risk", because their
   magnitude happened to sit in the 20-30 band. Everything a reader takes as the
   answer — the headline, its colour, the words — is derived here from the
   verdict, and the score is presented only as a magnitude beside it.
   -------------------------------------------------------------------------- */

export type Verdict = 'malicious' | 'suspicious' | 'clean'

/**
 * The verdict carried by a payload, or null when there is none.
 *
 * The backend serialises a missing verdict as `{}`, and jobs analysed before the
 * verdict engine shipped have exactly that — so an object is not enough, the
 * decision itself has to be present and recognised.
 */
export function verdictOf(job: { verdict?: VerdictT | null }): Verdict | null {
  const v = job.verdict?.verdict
  return v === 'malicious' || v === 'suspicious' || v === 'clean' ? v : null
}

export function verdictTone(verdict: Verdict): 'danger' | 'warning' | 'success' {
  if (verdict === 'malicious') return 'danger'
  if (verdict === 'suspicious') return 'warning'
  return 'success'
}

export function verdictHeadline(verdict: Verdict): string {
  if (verdict === 'malicious') return 'Malicious'
  if (verdict === 'suspicious') return 'Suspicious'
  return 'No threat found'
}

/**
 * Does this job belong in front of an analyst?
 *
 * Verdict first. The score threshold is the fallback for pre-verdict jobs only —
 * as the sole rule it silently dropped every malicious sample that scored under
 * 30 off the dashboard.
 */
export function needsAttention(job: { verdict?: VerdictT | null; final_score: number }): boolean {
  const v = verdictOf(job)
  if (v) return v !== 'clean'
  return job.final_score >= 30
}

/** The impact rating shares the severity vocabulary, so it shares the tone map. */
export function impactOf(job: { impact?: ImpactT | null }): ImpactT | null {
  const c = job.impact
  return c && typeof c.base_score === 'number' && c.vector ? c : null
}

export function familyLabel(family: string): string {
  const map: Record<string, string> = {
    pe: 'Windows executable',
    elf: 'Linux binary',
    office: 'Office document',
    script: 'Script',
    pdf: 'PDF document',
    archive: 'Archive',
    apk: 'Android package',
    jar: 'Java archive',
    diskimage: 'Disk image',
    unknown: 'Unclassified',
  }
  return map[family] ?? family
}

/** Human name for an IOC bucket. */
export function iocLabel(key: string): string {
  const map: Record<string, string> = {
    urls: 'URLs',
    domains: 'Domains',
    ips: 'IP addresses',
    emails: 'Email addresses',
    hashes: 'Hashes',
    file_paths: 'File paths',
    registry_keys: 'Registry keys',
    mutexes: 'Mutexes',
  }
  return map[key] ?? key
}
