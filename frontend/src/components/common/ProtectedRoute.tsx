import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth, UserRole } from '../../context/AuthContext';

interface ProtectedRouteProps {
  allowedRoles?: UserRole[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ allowedRoles }) => {
  const { user, isAuthenticated, isLoading, getRoleDashboardPath } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-bg">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-10 h-10 border-4 border-cyan border-t-transparent rounded-full animate-spin"></div>
          <p className="text-cyber-secondary font-medium">Verifying Q-SHIELD Security Credentials...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    const targetPath = getRoleDashboardPath(user.role);
    return <Navigate to={targetPath} replace />;
  }

  return <Outlet />;
};
