// Shapes mirrored from the backend (app/schemas.py). Kept deliberately close to
// the wire format so a response can be handed to a component without remapping.

export interface Session {
  token: string
  subject: string
  expires_at: number
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
