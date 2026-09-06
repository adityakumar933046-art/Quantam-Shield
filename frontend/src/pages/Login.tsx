import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, UserRole } from '../context/AuthContext';
import { Shield, Lock, Mail, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login, getRoleDashboardPath } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const role = await login({ email, password });
      const targetPath = getRoleDashboardPath(role);
      navigate(targetPath, { replace: true });
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Authentication failed. Please check your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const fillDemoAccount = (demoEmail: string, demoRole: string) => {
    setEmail(demoEmail);
    if (demoRole === 'SUPER_ADMIN') setPassword('AdminPassword123!');
    if (demoRole === 'DIGITAL_SIGNATURE_USER') setPassword('UserPassword123!');
    if (demoRole === 'SECURITY_ANALYST') setPassword('AnalystPassword123!');
    setError(null);
  };

  return (
    <div className="min-h-screen bg-navy text-white flex flex-col justify-center py-12 px-6 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Background Cyber Grid Accent */}
      <div className="absolute inset-0 bg-[radial-gradient(#00C2FF_1px,transparent_1px)] [background-size:32px_32px] opacity-10 pointer-events-none"></div>

      <div className="sm:mx-auto sm:w-full sm:max-w-md z-10">
        {/* Brand Shield Logo */}
        <div className="flex justify-center">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan via-blue-500 to-indigo-600 flex items-center justify-center shadow-xl shadow-cyan/20">
            <Shield className="w-10 h-10 text-white" />
          </div>
        </div>

        <h1 className="mt-4 text-center text-3xl font-extrabold text-white tracking-tight">
          Q-SHIELD
        </h1>
        <p className="mt-1 text-center text-sm text-cyan uppercase tracking-widest font-semibold">
          Quantum-Inspired Digital Signature Platform
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-xl z-10">
        <div className="bg-navy-light/80 backdrop-blur-md py-8 px-6 shadow-2xl rounded-2xl border border-navy-light/80 sm:px-10">
          
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start space-x-3 text-red-400">
              <AlertCircle size={20} className="shrink-0 mt-0.5" />
              <p className="text-sm font-medium">{error}</p>
            </div>
          )}

          <form className="space-y-5" onSubmit={handleSubmit}>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Email Address
              </label>
              <div className="relative rounded-xl shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Mail size={18} />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@qshield.com"
                  className="block w-full pl-10 pr-4 py-3 bg-navy text-white placeholder-slate-500 border border-navy-light rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan focus:border-transparent text-sm transition-all"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <div className="relative rounded-xl shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Lock size={18} />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="block w-full pl-10 pr-4 py-3 bg-navy text-white placeholder-slate-500 border border-navy-light rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan focus:border-transparent text-sm transition-all"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex justify-center items-center py-3.5 px-4 border border-transparent rounded-xl shadow-lg font-semibold text-white bg-gradient-to-r from-cyan to-blue-600 hover:from-cyan-hover hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan transition-all text-sm group disabled:opacity-50"
            >
              {isSubmitting ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <span>Sign In to Platform</span>
                  <ArrowRight size={18} className="ml-2 group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          {/* Pre-Configured Demo Credentials Table */}
          <div className="mt-8 pt-6 border-t border-navy-light/60 space-y-3">
            <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center">
              <span className="mr-1.5">🔑</span> Pre-Configured Demo Credentials for All Dashboards
            </h3>
            
            <div className="overflow-x-auto rounded-xl border border-slate-700/80 bg-slate-900/90 text-xs shadow-inner">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-800/80 text-slate-300 border-b border-slate-700 text-[11px]">
                    <th className="p-2.5 font-bold">Dashboard / Role</th>
                    <th className="p-2.5 font-bold">Email (Username)</th>
                    <th className="p-2.5 font-bold">Password</th>
                    <th className="p-2.5 font-bold">Target Dashboard View</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                  <tr 
                    onClick={() => fillDemoAccount('user@qshield.com', 'DIGITAL_SIGNATURE_USER')}
                    className="hover:bg-cyan/15 cursor-pointer transition-colors group"
                  >
                    <td className="p-2.5 font-sans font-bold text-slate-200 group-hover:text-cyan">1. Digital Signature Operator</td>
                    <td className="p-2.5 text-red-400 font-bold">user@qshield.com</td>
                    <td className="p-2.5 text-red-400 font-bold">UserPassword123!</td>
                    <td className="p-2.5 font-sans text-slate-400">Document Upload & Signature Generator</td>
                  </tr>
                  <tr 
                    onClick={() => fillDemoAccount('analyst@qshield.com', 'SECURITY_ANALYST')}
                    className="hover:bg-cyan/15 cursor-pointer transition-colors group"
                  >
                    <td className="p-2.5 font-sans font-bold text-slate-200 group-hover:text-cyan">2. Security Analyst</td>
                    <td className="p-2.5 text-red-400 font-bold">analyst@qshield.com</td>
                    <td className="p-2.5 text-red-400 font-bold">AnalystPassword123!</td>
                    <td className="p-2.5 font-sans text-slate-400">Signature Inspection, Quantum Engine</td>
                  </tr>
                  <tr 
                    onClick={() => fillDemoAccount('admin@qshield.com', 'SUPER_ADMIN')}
                    className="hover:bg-cyan/15 cursor-pointer transition-colors group"
                  >
                    <td className="p-2.5 font-sans font-bold text-slate-200 group-hover:text-cyan">3. Super Admin</td>
                    <td className="p-2.5 text-red-400 font-bold">admin@qshield.com</td>
                    <td className="p-2.5 text-red-400 font-bold">AdminPassword123!</td>
                    <td className="p-2.5 font-sans text-slate-400">User Management, System Metrics & Audit Logs</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="text-[10px] text-slate-400 text-center">
              💡 Click any row above to auto-fill credentials into the login form.
            </p>
          </div>

        </div>

        <p className="mt-6 text-center text-xs text-slate-500">
          Q-SHIELD Security Platform &copy; 2026. Cryptographically Protected.
        </p>
      </div>
    </div>
  );
};
