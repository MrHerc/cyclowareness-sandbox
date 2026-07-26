// Shapes mirrored from the backend (app/schemas.py). Kept deliberately close to
// the wire format so a response can be handed to a component without remapping.

export interface Session {
  token: string
  subject: string
  expires_at: number
}

/**
 * The analyst-facing outputs of the engine: what it decided, how badly it would
 * hurt, and what the sample actually does. These three are `?` on purpose —
 * every job analysed before the verdict engine shipped has them null, and a
 * report that crashes on an old job is worse than one that omits a section.
 */

/** One row of the multi-engine detection panel. */
export interface EngineDetection {
  engine: string
  detected: boolean
  result: string
  severity: string
}

export interface VerdictT {
  /** malicious | suspicious | clean — the headline, and the only thing allowed
   *  to set its colour. The 0-100 score is a magnitude, not a decision. */
  verdict: string
  threat_name: string
  /** Pre-formatted by the backend, e.g. "7 / 11". */
  detection_ratio: string
  detected: number
  total_engines: number
  platform: string
  category: string
  family: string
  engines: EngineDetection[]
}

export interface CvssT {
  vector: string
  base_score: number
  severity: string
  metrics: Record<string, string>
  rationale: { metric: string; value: string; why: string }[]
}

export interface MitreTechnique {
  technique_id: string
  name: string
  tactic: string
  evidence: string[]
}

export interface JobSummary {
  public_id: string
  source: string
  original_name: string
  submitted_url: string | null
  sha256: string
  size_bytes: number
  mime: string
  family: string
  status: string
  stage: string
  risk_level: string
  final_score: number
  created_at: string
  completed_at: string | null
  /** The list endpoint returns summaries and may omit the verdict entirely; the
   *  dashboard therefore treats "no verdict" as a distinct state rather than as
   *  a clean bill of health. */
  verdict?: VerdictT | null
}

export interface SignalT {
  id: string
  title: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  detail?: string
  evidence?: Record<string, unknown>
  analyzer?: string
}

export interface AnalyzerPayload {
  analyzer: string
  ran: boolean
  unavailable_reason: string | null
  signals: SignalT[]
  facts: Record<string, unknown>
  iocs: Record<string, string[]>
  duration_ms: number
}

export interface TierInfo {
  ran: boolean
  detail?: string
  engine?: string
  worker?: string
  unavailable_analyzers?: Record<string, string>
}

export interface TimelineEvent {
  t_ms: number
  kind: string
  detail: string
}

export interface DynamicInfo {
  engine?: string
  worker?: string
  ran?: boolean
  timeline?: TimelineEvent[]
  signals?: SignalT[]
  facts?: Record<string, unknown>
  duration_ms?: number
}

export interface ScoreBreakdown {
  formula?: string
  rule?: {
    score: number
    signal_count: number
    bands: { severity: string; count: number; contribution: number; signals: string[] }[]
  }
  model?: {
    score: number
    provenance: string
    features: Record<string, number>
    contributions: { feature: string; value: number; weight: number; contribution: number }[]
    bias: number
  }
  top_reasons?: { id: string; title: string; severity: string; detail: string }[]
  tiers?: Record<string, TierInfo>
}

export interface JobDetailT extends JobSummary {
  md5: string
  magic: string
  extension_mismatch: boolean
  submitted_by: string | null
  error: string | null
  tiers: Record<string, TierInfo>
  analysis: Record<string, AnalyzerPayload>
  dynamic: DynamicInfo
  iocs: Record<string, string[]>
  score_breakdown: ScoreBreakdown
  cvss?: CvssT | null
  mitre?: MitreTechnique[] | null
  rule_score: number
  ai_score: number
  feedback: string | null
  archive_path: string | null
  duration_ms: number | null
  children: JobSummary[]
}

export interface EngineDescriptor {
  key: string
  name: string
  vendor?: string
  kind: string
  tier: string
  configured: boolean
  requires?: string
  notes?: string
  docs_url?: string
}

export interface Capabilities {
  service: string
  demo_mode: boolean
  ai_provider: string
  scoring: { model: string; weights: { rule: number; model: number } }
  static_analyzers: string[]
  unavailable_analyzers: Record<string, string>
  yara: { loaded: number; files?: number; failed?: unknown; available?: boolean; error?: string }
  dynamic_worker: boolean
  integrations: EngineDescriptor[]
  supported_extensions: string[]
  metrics_enabled: boolean
}
