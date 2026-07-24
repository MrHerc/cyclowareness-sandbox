// Small display helpers specific to the sandbox (byte sizes, verdict wording).
// Colour never lives here — tone classes come from index.css via ui.tsx.

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

export function familyLabel(family: string): string {
  const map: Record<string, string> = {
    pe: 'Windows executable',
    elf: 'Linux binary',
    office: 'Office document',
    script: 'Script',
    pdf: 'PDF document',
    archive: 'Archive',
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
