import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))

/** Swap the two hooks that depend on effects/network for synchronous stubs. */
function stubHooks() {
  return {
    name: 'probe-stub-hooks',
    enforce: 'pre' as const,
    resolveId(source: string) {
      if (source.endsWith('lib/usePoll')) return path.resolve(here, 'stubPoll.ts')
      if (source.endsWith('lib/useCapabilities')) return path.resolve(here, 'stubCaps.ts')
      return null
    },
  }
}

export default defineConfig({
  plugins: [stubHooks(), react()],
  logLevel: 'error',
  build: {
    ssr: path.resolve(here, 'entry.tsx'),
    outDir: path.resolve(here, 'out'),
    emptyOutDir: true,
    minify: false,
    target: 'node20',
  },
})
