import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/common/ProtectedRoute';
import { AppLayout } from './components/layout/AppLayout';

// Pages
import { Login } from './pages/Login';
import { ProfilePage } from './pages/ProfilePage';

// Digital Signature User Pages
import { SignatureDashboard } from './pages/signature/SignatureDashboard';
import { CreateSignaturePlaceholder } from './pages/signature/CreateSignaturePlaceholder';
import { MyDocumentsPlaceholder } from './pages/signature/MyDocumentsPlaceholder';

// Security Analyst Pages
import { SecurityDashboard } from './pages/security/SecurityDashboard';
import { AnalyzeDocumentPlaceholder } from './pages/security/AnalyzeDocumentPlaceholder';
import { ThreatIncidentsPlaceholder } from './pages/security/ThreatIncidentsPlaceholder';
import { QDSSimulationPage } from './pages/security/QDSSimulationPage';
import AttackSimulationPage from './pages/security/AttackSimulationPage';
import { ReportsPage } from './pages/security/ReportsPage';
import { ReportDetailPage } from './pages/security/ReportDetailPage';
import { PerformanceEvaluationPage } from './pages/security/PerformanceEvaluationPage';

// Super Admin Pages
import { AdminDashboard } from './pages/admin/AdminDashboard';
import { UsersManagement } from './pages/admin/UsersManagement';
import { AuditLogsPage } from './pages/admin/AuditLogsPage';

const RootRedirect: React.FC = () => {
  const { user, isAuthenticated, isLoading, getRoleDashboardPath } = useAuth();
  
  if (isLoading) return null;
  if (!isAuthenticated || !user) return <Navigate to="/login" replace />;
  return <Navigate to={getRoleDashboardPath(user.role)} replace />;
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Login Route */}
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RootRedirect />} />

          {/* Protected Application Layout */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="/profile" element={<ProfilePage />} />

              {/* Digital Signature User Routes */}
              <Route element={<ProtectedRoute allowedRoles={['DIGITAL_SIGNATURE_USER', 'SUPER_ADMIN']} />}>
                <Route path="/signature/dashboard" element={<SignatureDashboard />} />
                <Route path="/signature/create" element={<CreateSignaturePlaceholder />} />
                <Route path="/signature/documents" element={<MyDocumentsPlaceholder />} />
              </Route>

              {/* Security Analyst Routes */}
              <Route element={<ProtectedRoute allowedRoles={['SECURITY_ANALYST', 'SUPER_ADMIN']} />}>
                <Route path="/security/dashboard" element={<SecurityDashboard />} />
                <Route path="/security/analyze" element={<AnalyzeDocumentPlaceholder />} />
                <Route path="/security/qds-simulation" element={<QDSSimulationPage />} />
                <Route path="/security/simulation" element={<AttackSimulationPage />} />
                <Route path="/security/reports" element={<ReportsPage />} />
                <Route path="/security/reports/:reportReference" element={<ReportDetailPage />} />
                <Route path="/security/performance" element={<PerformanceEvaluationPage />} />
                <Route path="/security/incidents" element={<ThreatIncidentsPlaceholder />} />
                <Route path="/security/history" element={<ThreatIncidentsPlaceholder />} />
                <Route path="/security/audit-logs" element={<AuditLogsPage />} />
              </Route>

              {/* Super Admin Routes */}
              <Route element={<ProtectedRoute allowedRoles={['SUPER_ADMIN']} />}>
                <Route path="/super-admin/dashboard" element={<AdminDashboard />} />
                <Route path="/super-admin/users" element={<UsersManagement />} />
                <Route path="/super-admin/analysts" element={<UsersManagement />} />
                <Route path="/super-admin/reports" element={<ReportsPage />} />
                <Route path="/super-admin/reports/:reportReference" element={<ReportDetailPage />} />
                <Route path="/super-admin/performance" element={<PerformanceEvaluationPage />} />
                <Route path="/super-admin/activity" element={<AdminDashboard />} />
                <Route path="/super-admin/security" element={<AdminDashboard />} />
                <Route path="/super-admin/settings" element={<AdminDashboard />} />
                <Route path="/super-admin/audit-logs" element={<AuditLogsPage />} />
              </Route>
            </Route>
          </Route>

          {/* Catch-all redirect */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
