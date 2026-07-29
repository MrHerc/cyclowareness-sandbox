import { useEffect, useState } from 'react'
import { RotateCcw, SlidersHorizontal } from 'lucide-react'
import { Button, Callout, LoadState, PageHeader, Panel } from '../components/ui'
import { api } from '../lib/api'

interface Weights {
  rule: number
  model: number
}

export function Tuning() {
  const [weights, setWeights] = useState<Weights | null>(null)
  const [rulePct, setRulePct] = useState(60)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [saved, setSaved] = useState(false)

  async function load() {
    setError(null)
    try {
      const w = await api.get<Weights>('/api/admin/weights')
      setWeights(w)
      setRulePct(Math.round(w.rule * 100))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load weights')
    }
  }

  useEffect(() => {
    void load()
  }, [])

  async function save() {
    setBusy(true)
    setSaved(false)
    setError(null)
    try {
      const w = await api.put<Weights>('/api/admin/weights', {
        rule_weight: rulePct / 100,
        ai_weight: (100 - rulePct) / 100,
      })
      setWeights(w)
      setRulePct(Math.round(w.rule * 100))
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setBusy(false)
    }
  }

  async function reset() {
    setBusy(true)
    setSaved(false)
    // `save()` above catches and shows; this one had a bare try/finally, so a
    // failed reset restored nothing, said nothing, and left the slider showing
    // the value the operator was trying to abandon. Every path that can fail
    // has to say so — an API key gets 403 here, and a lost session gets 401.
    setError(null)
    try {
      const w = await api.post<Weights>('/api/admin/weights/reset')
      setWeights(w)
      setRulePct(Math.round(w.rule * 100))
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset')
    } finally {
      setBusy(false)
    }
  }

  if (!weights) {
    return (
      <div className="space-y-6">
        <PageHeader title="Score tuning" />
        <LoadState error={error} label="Loading weights" onRetry={load} />
      </div>
    )
  }

  const modelPct = 100 - rulePct

  return (
    <div className="space-y-6">
      <PageHeader
        title="Score tuning"
        lede="The final score is a weighted blend of the rule component and the model component. Adjust the split; the change applies immediately to new analyses."
      />

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Panel tone="feature" title="Aggregation split">
          <div className="space-y-5">
            <div>
              <div className="mb-2 flex items-baseline justify-between">
                <span className="label text-c3">Rule component</span>
                <span className="text-h font-semibold tabular-nums text-c1">{rulePct}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={rulePct}
                onChange={(e) => {
                  setRulePct(Number(e.target.value))
                  setSaved(false)
                }}
                className="w-full accent-[var(--color-brand)]"
                aria-label="Rule component weight"
              />
              <div className="mt-1 flex justify-between text-xs text-c3">
                <span>All model</span>
                <span>All rules</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-control border border-hair bg-raised p-3 text-center">
                <div className="label text-c3">Rule</div>
                <div className="text-title font-semibold tabular-nums text-c1">{(rulePct / 100).toFixed(2)}</div>
              </div>
              <div className="rounded-control border border-hair bg-raised p-3 text-center">
                <div className="label text-c3">Model</div>
                <div className="text-title font-semibold tabular-nums text-c1">{(modelPct / 100).toFixed(2)}</div>
              </div>
            </div>

            <p className="tech text-c3">final = {(rulePct / 100).toFixed(2)} × rule + {(modelPct / 100).toFixed(2)} × model</p>

            {error && <Callout tone="danger" title="Could not save">{error}</Callout>}
            {saved && <Callout tone="success" title="Saved">New analyses will use this split.</Callout>}

            <div className="flex flex-wrap gap-2">
              <Button variant="primary" busy={busy} onClick={save}>
                <SlidersHorizontal size={14} aria-hidden /> Apply split
              </Button>
              <Button variant="secondary" busy={busy} onClick={reset}>
                <RotateCcw size={14} aria-hidden /> Reset to 0.6 / 0.4
              </Button>
            </div>
          </div>
        </Panel>

        <Panel title="How this works" tone="quiet">
          <div className="space-y-3 text-sm text-c2">
            <p>
              The <span className="text-c1">rule component</span> is a severity-weighted sum of every signal the
              analyzers fired, saturating per band so twenty low findings never outweigh one critical.
            </p>
            <p>
              The <span className="text-c1">model component</span> is an expert-weighted logistic regression over
              eight features, each feature's contribution shown on every report.
            </p>
            <p className="text-c3">
              The override is held in memory for this running service and resets to the 0.6 / 0.4 default on
              restart — the safe direction for a tuning knob to fail.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  )
}
