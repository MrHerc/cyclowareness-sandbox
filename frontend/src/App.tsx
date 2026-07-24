import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { Layout } from './components/Layout'
import { useAuth } from './lib/auth'
import { Login } from './pages/Login'
import { Submit } from './pages/Submit'
import { Queue } from './pages/Queue'
import { JobDetail } from './pages/JobDetail'
import { Integrations } from './pages/Integrations'
import { Tuning } from './pages/Tuning'

function RequireAuth({ children }: { children: ReactNode }) {
  const { session } = useAuth()
  const location = useLocation()
  if (!session) return <Navigate to="/login" replace state={{ from: location }} />
  return <>{children}</>
}

export default function App() {
  const { session } = useAuth()
  return (
    <Routes>
      <Route path="/login" element={session ? <Navigate to="/" replace /> : <Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Submit />} />
        <Route path="queue" element={<Queue />} />
        <Route path="job/:id" element={<JobDetail />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="tuning" element={<Tuning />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
