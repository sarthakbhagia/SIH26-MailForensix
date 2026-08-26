import { Routes, Route } from 'react-router-dom'
import DashboardLayout from './components/layout/DashboardLayout'
import DashboardPage from './pages/DashboardPage'
import EmailIngestPage from './pages/EmailIngestPage'
import EmailAnalysisPage from './pages/EmailAnalysisPage'
import TraceMapPage from './pages/TraceMapPage'
import AttributionGraphPage from './pages/AttributionGraphPage'
import CasesPage from './pages/CasesPage'
import ReportsPage from './pages/ReportsPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<DashboardLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="ingest" element={<EmailIngestPage />} />
        <Route path="emails/:emailId" element={<EmailAnalysisPage />} />
        <Route path="map" element={<TraceMapPage />} />
        <Route path="graph" element={<AttributionGraphPage />} />
        <Route path="cases" element={<CasesPage />} />
        <Route path="cases/:caseId" element={<CasesPage />} />
        <Route path="reports" element={<ReportsPage />} />
      </Route>
    </Routes>
  )
}

export default App
