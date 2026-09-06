import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

export type UserRole = 'SUPER_ADMIN' | 'DIGITAL_SIGNATURE_USER' | 'SECURITY_ANALYST';

export interface User {
  user_id: number;
  full_name: string;
  email: string;
  role: UserRole;
  status: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: { email: string; password: string }) => Promise<UserRole>;
  logout: () => Promise<void>;
  getRoleDashboardPath: (role: UserRole) => string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('qshield_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('qshield_token') || null;
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const getRoleDashboardPath = (role: UserRole): string => {
    switch (role) {
      case 'SUPER_ADMIN':
        return '/super-admin/dashboard';
      case 'DIGITAL_SIGNATURE_USER':
        return '/signature/dashboard';
      case 'SECURITY_ANALYST':
        return '/security/dashboard';
      default:
        return '/login';
    }
  };

  useEffect(() => {
    const verifyAuth = async () => {
      const storedToken = localStorage.getItem('qshield_token');
      if (storedToken) {
        try {
          const res = await api.get('/auth/me');
          setUser(res.data);
          localStorage.setItem('qshield_user', JSON.stringify(res.data));
        } catch (err) {
          console.error("Token verification failed:", err);
          setUser(null);
          setToken(null);
          localStorage.removeItem('qshield_token');
          localStorage.removeItem('qshield_user');
        }
      }
      setIsLoading(false);
    };

    verifyAuth();
  }, []);

  const login = async (credentials: { email: string; password: string }): Promise<UserRole> => {
    const res = await api.post('/auth/login', credentials);
    const { access_token, user_id, full_name, email, role, status } = res.data;
    
    const userData: User = { user_id, full_name, email, role, status };
    setToken(access_token);
    setUser(userData);

    localStorage.setItem('qshield_token', access_token);
    localStorage.setItem('qshield_user', JSON.stringify(userData));

    return role as UserRole;
  };

  const logout = async () => {
    try {
      if (token) {
        await api.post('/auth/logout');
      }
    } catch (e) {
      // Ignore API logout failure, clear local state regardless
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem('qshield_token');
      localStorage.removeItem('qshield_user');
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        logout,
        getRoleDashboardPath
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
