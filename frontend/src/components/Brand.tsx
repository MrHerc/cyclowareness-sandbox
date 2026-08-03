/**
 * The wordmark. An inset containment square — the visual idea of the product:
 * something hostile held inside a boundary and inspected. Brand hue, never a
 * status hue. No emoji, no raster logo.
 *
 * It names no colour: `stroke-brand` and `fill-brand` follow the token, so the
 * repaint from blue to lime did not touch this file. The comment said "violet",
 * which the accent had not been for two revisions — a stale colour name in a
 * comment is how the next person picks the wrong one.
 */
export function Brand({ size = 22, withText = true }: { size?: number; withText?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden
        className="shrink-0"
      >
        <rect x="1.5" y="1.5" width="21" height="21" rx="4.5" className="stroke-brand" strokeWidth="1.5" />
        <rect x="6.5" y="6.5" width="11" height="11" rx="2" className="fill-brand/15 stroke-brand" strokeWidth="1.5" />
        <path d="M9.5 12.2l1.8 1.8 3.2-3.6" className="stroke-brand" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {withText && (
        <span className="text-h font-semibold tracking-tight text-c1">
          Cyclowareness <span className="text-brand-fg">Sandbox</span>
        </span>
      )}
    </span>
  )
}
