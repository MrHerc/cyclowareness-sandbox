import { useRef, useState, type DragEvent, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileUp, Link2, Lock, ShieldAlert } from 'lucide-react'
import { Button, Callout, Input, PageHeader, Panel, Tabs } from '../components/ui'
import { api } from '../lib/api'
import { formatBytes } from '../lib/format'
import { useCapabilities } from '../lib/useCapabilities'
import type { JobDetailT } from '../lib/types'

type Mode = 'file' | 'url'

export function Submit() {
  const navigate = useNavigate()
  const caps = useCapabilities()
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [url, setUrl] = useState('')
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // The server's real ceiling, not a number typed in here. Hardcoding 32 meant
  // an operator who raised MAX_SAMPLE_MB got an interface that still refused on
  // the analyst's behalf — and one who lowered it got a promise the server then
  // broke with a 413. Falls back to the shipped default while capabilities load.
  // NOT `?? 32`. 32 is the shipped default, not this deployment's limit, and
  // an operator who lowered it had this page promise a size the server then
  // refused with a 413. Until /api/capabilities answers, the limit is unknown
  // and the page says nothing rather than guessing.
  const maxMb = caps?.max_sample_mb ?? null

  function onDrop(e: DragEvent) {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files?.[0]
    if (dropped) setFile(dropped)
  }

  async function submitFile(e: FormEvent) {
    e.preventDefault()
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('file', file)
      if (password) form.append('password', password)
      const job = await api.upload<JobDetailT>('/api/analyze', form)
      navigate(`/job/${job.public_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submission failed')
    } finally {
      setBusy(false)
    }
  }

  async function submitUrl(e: FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    setBusy(true)
    setError(null)
    try {
      const job = await api.post<JobDetailT>('/api/analyze/url', { url: url.trim() })
      navigate(`/job/${job.public_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submission failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="hero-glow">
        <PageHeader
          title="Submit a sample"
          lede="Upload a file or paste a URL. The sample is quarantined and analysed statically — it is never executed on this server."
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
        <Panel tone="feature" className="rise-in">
          <div className="mb-4">
            <Tabs
              label="Submission type"
              value={mode}
              onChange={setMode}
              tabs={[
                { key: 'file', label: 'File' },
                { key: 'url', label: 'URL' },
              ]}
            />
          </div>

          {mode === 'file' ? (
            <form onSubmit={submitFile} className="space-y-4">
              <div
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click()
                }}
                className={
                  'flex cursor-pointer flex-col items-center justify-center gap-3 rounded-panel border-2 border-dashed px-6 py-12 text-center transition-colors ' +
                  (dragging ? 'border-brand bg-brand/8' : 'border-line bg-raised hover:border-line-strong')
                }
              >
                <FileUp size={28} className="text-c3" aria-hidden />
                {file ? (
                  <div>
                    <p className="text-body font-medium text-c1">{file.name}</p>
                    <p className="text-xs mt-0.5 text-c3">{formatBytes(file.size)}</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-body text-c1">Drop a file here, or click to choose</p>
                    {maxMb !== null && <p className="text-xs mt-1 text-c3">Up to {maxMb} MB</p>}
                  </div>
                )}
                <input
                  ref={inputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </div>

              <Input
                label="Archive password (optional)"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Only for encrypted .zip / .rar / .7z"
                hint="If the archive is encrypted and you leave this blank, the job pauses and asks for it — the engine never guesses a password."
              />

              {error && (
                <Callout tone="danger" title="Submission failed">
                  {error}
                </Callout>
              )}

              <Button type="submit" variant="primary" size="lg" busy={busy} disabled={!file} className="w-full">
                <FileUp size={16} aria-hidden />
                Analyse file
              </Button>
            </form>
          ) : (
            <form onSubmit={submitUrl} className="space-y-4">
              <Input
                label="URL"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/suspicious.bin"
                hint="The server downloads it. Requests to private, loopback and cloud-metadata addresses are refused."
                autoFocus
              />
              {error && (
                <Callout tone="danger" title="Submission failed">
                  {error}
                </Callout>
              )}
              <Button type="submit" variant="primary" size="lg" busy={busy} disabled={!url.trim()} className="w-full">
                <Link2 size={16} aria-hidden />
                Fetch and analyse
              </Button>
            </form>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="How it is handled" tone="quiet" padded>
            <ul className="space-y-3 text-sm text-c2">
              <li className="flex gap-2.5">
                <ShieldAlert size={16} className="mt-0.5 shrink-0 text-brand-fg" aria-hidden />
                <span>Stored under its content hash, owner-read-only, never marked executable.</span>
              </li>
              <li className="flex gap-2.5">
                <Lock size={16} className="mt-0.5 shrink-0 text-brand-fg" aria-hidden />
                <span>Static analysis only here: parsers and YARA. Detonation runs off-host on an isolated worker.</span>
              </li>
              <li className="flex gap-2.5">
                <FileUp size={16} className="mt-0.5 shrink-0 text-brand-fg" aria-hidden />
                <span>You get a job id immediately and can watch each stage as it runs.</span>
              </li>
            </ul>
          </Panel>

          {caps && (
            <Panel title="Supported types" tone="quiet" padded>
              <div className="flex flex-wrap gap-1.5">
                {caps.supported_extensions.map((ext) => (
                  <span key={ext} className="tech rounded-chip border border-hair bg-raised px-1.5 py-0.5 text-c2">
                    {ext}
                  </span>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}
