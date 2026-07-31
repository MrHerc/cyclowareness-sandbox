import type { HTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import { useId } from 'react'
import { CircleAlert, Loader2, RefreshCw } from 'lucide-react'

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

/* =============================================================================
   Containers

   Three tiers, not one. The previous system made every section an identical
   bordered card, so a KPI, a chart, a table and the signature loop visual all
   carried the same weight and nothing on the page led. `tone` is how a page
   says which of its parts matters.
   ========================================================================== */

export function Panel({
  title,
  subtitle,
  actions,
  footer,
  tone = 'default',
  padded = true,
  className,
  children,
  ...rest
}: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  footer?: ReactNode
  /** `feature` is for the one element on a page that must be looked at first. */
  tone?: 'default' | 'feature' | 'quiet'
  padded?: boolean
  className?: string
  children: ReactNode
  /** Spotlight hook for the guided tour. */
  'data-tour'?: string
} & Omit<HTMLAttributes<HTMLElement>, 'title' | 'className' | 'children'>) {
  const tones = {
    default: 'border-hair bg-panel',
    feature: 'border-brand/30 bg-panel',
    quiet: 'border-transparent bg-transparent',
  }
  return (
    <section
      className={cx('rounded-panel border', tones[tone], className)}
      {...rest}
    >
      {(title || actions) && (
        <header
          className={cx(
            'flex items-start justify-between gap-4',
            padded ? 'px-5 pt-4' : 'px-0 pt-0',
            children ? 'pb-3' : 'pb-4',
          )}
        >
          <div className="min-w-0">
            {title && <h2 className="text-h truncate">{title}</h2>}
            {subtitle && <p className="text-sm mt-0.5 text-c2">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx(padded && (title || actions ? 'px-5 pb-5' : 'p-5'))}>{children}</div>
      {footer && <div className={cx('border-t border-hair', padded && 'px-5 py-3')}>{footer}</div>}
    </section>
  )
}

/** Small all-caps rule above a sub-grouping inside a Panel. */
export function GroupLabel({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2.5 flex items-baseline justify-between gap-3">
      <h3 className="label text-c3">{children}</h3>
      {right}
    </div>
  )
}

export function PageHeader({
  title,
  lede,
  actions,
  breadcrumb,
}: {
  title: ReactNode
  lede?: ReactNode
  actions?: ReactNode
  breadcrumb?: ReactNode
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="min-w-0">
        {breadcrumb && <div className="text-sm mb-1.5 flex items-center gap-1.5 text-c2">{breadcrumb}</div>}
        <h1 className="text-title">{title}</h1>
        {lede && <p className="text-body mt-1 max-w-2xl text-c2">{lede}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

/* =============================================================================
   Actions
   ========================================================================== */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md' | 'lg'

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-brand text-on-brand border-brand hover:bg-brand-hover hover:border-brand-hover',
  secondary: 'bg-raised text-c1 border-line hover:border-line-strong',
  ghost: 'bg-transparent text-c2 border-transparent hover:bg-raised hover:text-c1',
  danger: 'bg-transparent text-danger border-danger/45 hover:bg-danger/10',
}

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-7 gap-1.5 px-2.5 text-xs',
  md: 'h-9 gap-2 px-3.5 text-sm',
  lg: 'h-11 gap-2 px-5 text-body',
}

export function Button({
  children,
  onClick,
  variant = 'secondary',
  size = 'md',
  disabled,
  busy,
  className,
  type = 'button',
  title,
}: {
  children: ReactNode
  onClick?: () => void
  variant?: ButtonVariant
  size?: ButtonSize
  disabled?: boolean
  busy?: boolean
  className?: string
  type?: 'button' | 'submit'
  title?: string
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || busy}
      title={title}
      aria-busy={busy || undefined}
      className={cx(
        'inline-flex select-none items-center justify-center whitespace-nowrap rounded-control border font-medium transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-45',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
    >
      {busy && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  )
}

/** Icon-only control. `label` is required — it is the accessible name. */
export function IconButton({
  label,
  onClick,
  children,
  className,
}: {
  label: string
  onClick?: () => void
  children: ReactNode
  className?: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className={cx(
        'inline-flex h-9 w-9 items-center justify-center rounded-control border border-transparent text-c2 transition-colors hover:bg-raised hover:text-c1',
        className,
      )}
    >
      {children}
    </button>
  )
}

/* =============================================================================
   Form controls

   The class string
     "w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm …"
   was pasted at fifteen call sites across five pages, and most of those inputs
   had a placeholder and no label — which is no accessible name at all.
   ========================================================================== */

const CONTROL =
  'w-full rounded-control border border-line bg-raised px-3 text-body text-c1 outline-none transition-colors placeholder:text-c3 focus:border-brand disabled:opacity-50'

export function Field({
  label,
  hint,
  children,
  htmlFor,
}: {
  label: string
  hint?: ReactNode
  children: ReactNode
  htmlFor?: string
}) {
  return (
    <div className="min-w-0">
      <label htmlFor={htmlFor} className="label mb-1.5 block text-c3">
        {label}
      </label>
      {children}
      {hint && <p className="text-xs mt-1 text-c3">{hint}</p>}
    </div>
  )
}

export function Input({
  label,
  hint,
  className,
  ...rest
}: { label: string; hint?: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId()
  return (
    <Field label={label} hint={hint} htmlFor={id}>
      <input id={id} className={cx(CONTROL, 'h-9', className)} {...rest} />
    </Field>
  )
}

export function Textarea({
  label,
  hint,
  mono,
  className,
  ...rest
}: { label: string; hint?: ReactNode; mono?: boolean } & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId()
  return (
    <Field label={label} hint={hint} htmlFor={id}>
      <textarea
        id={id}
        className={cx(CONTROL, 'resize-y py-2 leading-relaxed', mono && 'font-mono text-xs', className)}
        {...rest}
      />
    </Field>
  )
}

export function Select({
  label,
  hint,
  children,
  className,
  ...rest
}: { label: string; hint?: ReactNode; children: ReactNode } & SelectHTMLAttributes<HTMLSelectElement>) {
  const id = useId()
  return (
    <Field label={label} hint={hint} htmlFor={id}>
      <select id={id} className={cx(CONTROL, 'h-9', className)} {...rest}>
        {children}
      </select>
    </Field>
  )
}

/* =============================================================================
   Status

   One semantic map. The old palette assigned colours per raw string at the
   point of use, so `running`, `active`, `in_loop`, `human_sensor` and the brand
   were all the same teal as `benign` — a live loop run and a healthy metric were
   indistinguishable at a glance.
   ========================================================================== */

type Tone = 'neutral' | 'brand' | 'info' | 'success' | 'warning' | 'danger'

/**
 * Every value this backend can actually put in a status-shaped field.
 *
 * It used to carry the whole lexicon of the awareness-training portal this
 * sandbox was forked from — `clicked`, `reported`, `awaiting_training`,
 * `pending_review`, `human_sensor`, `in_loop` — none of which any endpoint
 * emits. A lookup keyed on a value that never arrives is a branch that cannot
 * execute, and it tells the next reader the product has concepts it does not.
 *
 * Checked against the source, not guessed: `JobStatus` (models.py),
 * `SEVERITY_ORDER` (contracts.py), `JobSource` and `Feedback`. `benign` is
 * deliberately absent — the engine's word is `clean`, and carrying both invites
 * a badge that agrees with neither.
 *
 * An unknown value is not a crash: `Status` falls back to `neutral`.
 */
const STATUS_TONE: Record<string, Tone> = {
  // verdicts
  malicious: 'danger',
  suspicious: 'warning',
  clean: 'success',
  // severities
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'neutral',
  info: 'neutral',
  // job status
  queued: 'neutral',
  running: 'brand',
  awaiting_password: 'warning',
  completed: 'success',
  failed: 'danger',
  // analyst feedback
  false_positive: 'warning',
  true_positive: 'success',
}

const TONE_CHIP: Record<Tone, string> = {
  neutral: 'border-line text-c2',
  brand: 'border-brand/40 text-brand-fg',
  info: 'border-info/40 text-info',
  success: 'border-success/40 text-success',
  warning: 'border-warning/40 text-warning',
  danger: 'border-danger/45 text-danger',
}

const TONE_DOT: Record<Tone, string> = {
  neutral: 'bg-c3',
  brand: 'bg-brand',
  info: 'bg-info',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
}

/**
 * Human wording for the ways a sample can arrive — the single source of truth.
 *
 * `JobSource` has exactly three values. The rest of this table (`email`, `sms`,
 * `qr`, `chat`, `web`) were delivery channels of the awareness-training portal;
 * this product ingests a file, a URL, or a member found inside an archive.
 */
const CHANNEL_LABELS: Record<string, string> = {
  upload: 'Upload',
  url: 'URL',
  file: 'File',
  archive_member: 'From archive',
}

/**
 * The provenance of a job, as the backend actually recorded it.
 *
 * JobDetail used to print `job.source === 'url' ? 'From URL' : 'Uploaded'`,
 * which states a provenance the backend never claimed: 877 of the 1451 jobs on
 * the live deployment are `archive_member` — a file extracted from a submitted
 * archive, not something anyone uploaded. That is 60% of the evidence in the
 * system carrying a false origin, on a product whose exports feed a NIS2/DORA
 * incident record, where provenance is the point.
 *
 * `CHANNEL_LABELS` already held the right words. Nothing read them.
 */
export function sourceLabel(value: string | null | undefined): string {
  if (!value) return 'Unknown origin'
  return CHANNEL_LABELS[value] ?? humanise(value)
}

function humanise(value: string): string {
  return CHANNEL_LABELS[value] ?? value.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())
}

/**
 * A state, rendered as an instrument readout rather than a filled pill: a
 * coloured dot plus the word. Filled pastel pills for every value are the
 * strongest "generated dashboard" signature in the interface, and at five
 * badges per row they turned run lists into confetti.
 */
export function Status({ value, label }: { value: string; label?: string }) {
  const tone = STATUS_TONE[value] ?? 'neutral'
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-chip border px-1.5 py-0.5 text-xs font-medium',
        TONE_CHIP[tone],
      )}
    >
      <span className={cx('h-1.5 w-1.5 shrink-0 rounded-full', TONE_DOT[tone])} aria-hidden />
      {label ?? humanise(value)}
    </span>
  )
}

/** A plain descriptive tag with no state semantics (channel, IOC type, reason). */
export function Chip({ children, tone = 'neutral' }: { children: ReactNode; tone?: Tone }) {
  return (
    <span
      className={cx(
        'inline-flex items-center whitespace-nowrap rounded-chip border px-1.5 py-0.5 text-xs',
        TONE_CHIP[tone],
      )}
    >
      {children}
    </span>
  )
}

/* =============================================================================
   Numbers
   ========================================================================== */

export function Metric({
  label,
  value,
  caption,
  tone = 'neutral',
  size = 'md',
}: {
  label: string
  value: ReactNode
  caption?: ReactNode
  tone?: Tone
  size?: 'sm' | 'md'
}) {
  const valueTone: Record<Tone, string> = {
    neutral: 'text-c1',
    brand: 'text-brand-fg',
    info: 'text-info',
    success: 'text-success',
    warning: 'text-warning',
    danger: 'text-danger',
  }
  const sm = size === 'sm'
  return (
    <div className={cx('rounded-control border border-hair bg-panel', sm ? 'px-3 py-2.5' : 'px-4 py-3.5')}>
      <div className="label text-c3">{label}</div>
      <div
        className={cx(
          'mt-1 font-semibold tracking-tight',
          sm ? 'text-h' : 'text-display',
          valueTone[tone],
        )}
      >
        {value}
      </div>
      {caption && <div className="text-xs mt-1 text-c3">{caption}</div>}
    </div>
  )
}

/**
 * The engine's bands, not the interface's own.
 *
 * This used to read >=60 "High", >=40 "Elevated", else "Low". The engine's
 * scale is `contracts.RISK_BANDS`: 0-29 low, 30-59 medium, 60-79 high, 80+
 * critical. So 45 was `medium` to the engine and **Elevated** on screen — a band
 * this product does not have — while 35 was `medium` to the engine and **Low**
 * here. `critical` had no representation at all. `RiskMeter` renders on every
 * Queue row, so the main list an analyst reads was banded by thresholds nothing
 * else in the system uses.
 *
 * Keep these four numbers identical to RISK_BANDS. They are duplicated across
 * the seam because the band of a score has to be computable without a round
 * trip; every report also carries `risk_level` from the backend, and where that
 * is present it is what should be shown.
 */
export function riskBand(score: number): { tone: Tone; text: string; bar: string; label: string } {
  if (score >= 80) return { tone: 'danger', text: 'text-danger', bar: 'bg-danger', label: 'Critical' }
  if (score >= 60) return { tone: 'danger', text: 'text-danger', bar: 'bg-danger', label: 'High' }
  if (score >= 30) return { tone: 'warning', text: 'text-warning', bar: 'bg-warning', label: 'Medium' }
  return { tone: 'success', text: 'text-success', bar: 'bg-success', label: 'Low' }
}

export function RiskMeter({ score, className }: { score: number; className?: string }) {
  const band = riskBand(score)
  return (
    <span className={cx('inline-flex items-center gap-2', className)}>
      <span
        className="h-1 w-20 overflow-hidden rounded-full bg-sunken"
        role="img"
        aria-label={`Risk ${score.toFixed(0)} of 100, ${band.label.toLowerCase()}`}
      >
        <span className={cx('block h-full rounded-full', band.bar)} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
      </span>
      <span className={cx('text-sm font-semibold', band.text)}>{score.toFixed(0)}</span>
    </span>
  )
}

/* =============================================================================
   Tables
   ========================================================================== */

export function Table({ children, minWidth = 560 }: { children: ReactNode; minWidth?: number }) {
  return (
    <div className="-mx-5 overflow-x-auto px-5">
      <table className="w-full border-collapse text-body" style={{ minWidth }}>
        {children}
      </table>
    </div>
  )
}

export function TH({ children, numeric }: { children: ReactNode; numeric?: boolean }) {
  return (
    <th scope="col" className={cx('label border-b border-line pb-2 text-c3', numeric ? 'text-right' : 'text-left')}>
      {children}
    </th>
  )
}

export function TD({ children, numeric, muted }: { children: ReactNode; numeric?: boolean; muted?: boolean }) {
  return (
    <td className={cx('border-b border-hair py-2.5 pr-4 last:pr-0', numeric && 'text-right', muted && 'text-c2')}>
      {children}
    </td>
  )
}

/* =============================================================================
   Content blocks
   ========================================================================== */

/** Raw artifact / lure text. Repeated verbatim at five call sites before this. */
export function CodeBlock({ children, maxHeight = 200 }: { children: ReactNode; maxHeight?: number }) {
  return (
    <pre
      className="overflow-auto whitespace-pre-wrap rounded-control border border-hair bg-sunken p-3 font-mono text-xs leading-relaxed text-c2"
      style={{ maxHeight }}
    >
      {children}
    </pre>
  )
}

export function Callout({
  tone = 'info',
  title,
  icon,
  actions,
  children,
}: {
  tone?: Exclude<Tone, 'neutral'>
  title?: string
  icon?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  const tones: Record<Exclude<Tone, 'neutral'>, string> = {
    brand: 'border-brand/30 bg-brand/8',
    info: 'border-info/30 bg-info/8',
    success: 'border-success/30 bg-success/8',
    warning: 'border-warning/30 bg-warning/8',
    danger: 'border-danger/35 bg-danger/8',
  }
  const heads: Record<Exclude<Tone, 'neutral'>, string> = {
    brand: 'text-brand-fg',
    info: 'text-info',
    success: 'text-success',
    warning: 'text-warning',
    danger: 'text-danger',
  }
  return (
    <div className={cx('rounded-control border p-3', tones[tone])}>
      {(title || actions) && (
        <div className="mb-1.5 flex items-center justify-between gap-3">
          <span className={cx('label flex items-center gap-1.5', heads[tone])}>
            {icon}
            {title}
          </span>
          {actions}
        </div>
      )}
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  )
}

/* =============================================================================
   Async states
   ========================================================================== */

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-c2" role="status">
      <Loader2 size={18} className="animate-spin" aria-hidden />
      {label && <span className="text-body">{label}</span>}
    </div>
  )
}

/**
 * The single place a page waits for its first payload.
 *
 * `usePoll` keeps `data` at null when a request fails, so a page that only
 * checks `if (!data) return <Spinner/>` spins forever whenever the API is
 * unreachable — hiding the one actionable message the client produces. Always
 * pass the poll's `error` through here.
 */
export function LoadState({ error, label, onRetry }: { error: string | null; label?: string; onRetry?: () => void }) {
  if (!error) return <Spinner label={label} />
  return (
    <div className="rise py-12" role="alert">
      <div className="mx-auto flex max-w-md flex-col items-center gap-3 rounded-panel border border-danger/35 bg-danger/8 px-5 py-6 text-center">
        <CircleAlert size={22} className="text-danger" aria-hidden />
        <p className="text-body leading-relaxed text-danger">{error}</p>
        {onRetry && (
          <Button variant="secondary" size="sm" onClick={onRetry}>
            <RefreshCw size={13} aria-hidden /> Try again
          </Button>
        )}
      </div>
    </div>
  )
}

/**
 * The counterpart to `LoadState`: the page has data, but polling has stopped
 * working. Non-destructive on purpose — the last good payload stays on screen,
 * captioned with the fact that it is frozen and with when it froze. A silent
 * outage is the dangerous version of this: an analyst watching a queue that
 * stopped updating has no way to tell it apart from a quiet queue.
 */
export function StaleNotice({ error, onRetry }: { error: string | null; onRetry?: () => void }) {
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-control border border-warning/40 bg-warning/8 px-3 py-2"
    >
      <span className="label flex items-center gap-1.5 text-warning">
        <CircleAlert size={14} aria-hidden /> Not updating
      </span>
      <span className="text-sm min-w-0 flex-1 text-c2">
        {error || 'The connection to the API dropped.'} Everything below is the last data received.
      </span>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <RefreshCw size={13} aria-hidden /> Retry
        </Button>
      )}
    </div>
  )
}

export function Empty({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-control border border-dashed border-line px-4 py-10 text-center">
      {icon && <div className="mb-2 flex justify-center text-c3">{icon}</div>}
      <p className="text-sm text-c3">{children}</p>
    </div>
  )
}

/* =============================================================================
   Overlays
   ========================================================================== */

/* =============================================================================
   Navigation
   ========================================================================== */

/**
 * Segmented filter. Rendered as a real radiogroup rather than a `tablist`: the
 * old version claimed `role="tablist"` while owning no tabpanel and no
 * `aria-controls`, which is a broken promise to a screen reader.
 */
export function Tabs<T extends string>({
  label,
  tabs,
  value,
  onChange,
  fill,
}: {
  label: string
  tabs: readonly { key: T; label: string; count?: number }[]
  value: T
  onChange: (key: T) => void
  fill?: boolean
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cx('inline-flex gap-1 rounded-control border border-hair bg-panel p-1', fill && 'flex w-full')}
    >
      {tabs.map((t) => (
        <button
          key={t.key}
          type="button"
          role="radio"
          aria-checked={value === t.key}
          onClick={() => onChange(t.key)}
          className={cx(
            'rounded-chip px-3 py-1.5 text-sm font-medium transition-colors',
            fill && 'flex-1',
            value === t.key ? 'bg-raised text-c1' : 'text-c2 hover:text-c1',
          )}
        >
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 text-c3">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

/* =============================================================================
   Formatting
   ========================================================================== */

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return '—'
  // Backend datetimes may arrive without a timezone suffix (SQLite): treat as UTC.
  const normalized = /[zZ]$|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`
  const then = new Date(normalized).getTime()
  if (Number.isNaN(then)) return '—'
  const seconds = Math.max(0, (Date.now() - then) / 1000)
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

/** Signed number for a delta, always with an explicit sign. */
export function signed(v: number, digits = 1): string {
  return `${v > 0 ? '+' : ''}${v.toFixed(digits)}`
}
