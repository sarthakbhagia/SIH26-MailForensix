import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/auth/ProtectedRoute';
import DashboardLayout from './components/layout/DashboardLayout';
import DashboardPage from './pages/DashboardPage';
import EmailIngestPage from './pages/EmailIngestPage';
import EmailAnalysisPage from './pages/EmailAnalysisPage';
import TraceMapPage from './pages/TraceMapPage';
import AttributionGraphPage from './pages/AttributionGraphPage';
import CasesPage from './pages/CasesPage';
import ReportsPage from './pages/ReportsPage';
import LoginPage from './pages/LoginPage';

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <ProtectedRoute>
              <DashboardLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="ingest" element={<EmailIngestPage />} />
          <Route path="emails/:emailId" element={<EmailAnalysisPage />} />
          <Route path="map" element={<TraceMapPage />} />
          <Route path="graph" element={<AttributionGraphPage />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="cases/:caseId" element={<CasesPage />} />
          <Route path="reports" element={<ReportsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;
