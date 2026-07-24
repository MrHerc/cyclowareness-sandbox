import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Both ports are overridable so a second checkout (git worktree) can run its own
// pair of servers without colliding with the primary one on 5173/8000.
const PORT = Number(process.env.PORT) || 5173
const API_TARGET = process.env.VITE_API_TARGET || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: PORT,
    proxy: {
      // ws: true so the /api/ws WebSocket is proxied to the backend too.
      '/api': { target: API_TARGET, ws: true },
    },
  },
})
