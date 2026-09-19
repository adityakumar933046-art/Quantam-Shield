import axios from 'axios';

// Resolve API base URL:
// In production (Vercel): uses VITE_API_URL (e.g. "https://qshield-backend.onrender.com")
// In local development: defaults to '/api' using Vite dev server proxy to localhost:8000
const rawBaseUrl = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim();

const getApiBaseUrl = (url?: string): string => {
  if (!url || url === '/api') {
    if (typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
      return 'https://qshield-backend-at7o.onrender.com/api';
    }
    return '/api';
  }
  const clean = url.replace(/\/+$/, '');
  return clean.endsWith('/api') ? clean : `${clean}/api`;
};

export const API_BASE_URL = getApiBaseUrl(rawBaseUrl);

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Interceptor to inject JWT Bearer token into all outgoing requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('qshield_token');
  if (token && token !== 'undefined' && token !== 'null' && token.trim().length > 0) {
    config.headers.Authorization = `Bearer ${token.trim()}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Interceptor to handle 401 Unauthorized responses
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear token only if this was an authenticated session request and not a failed login
      const isLoginRequest = error.config?.url?.includes('/auth/login');
      if (!isLoginRequest) {
        localStorage.removeItem('qshield_token');
        localStorage.removeItem('qshield_user');
      }
    }
    return Promise.reject(error);
  }
);
