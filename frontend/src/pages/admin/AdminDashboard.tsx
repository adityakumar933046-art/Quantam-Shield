import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import { Users, ShieldCheck, FileText, Activity, Shield, ArrowUpRight, Lock, CheckCircle2 } from 'lucide-react';

interface AdminStats {
  total_users: number;
  active_analysts: number;
  total_signed_documents: number;
  total_analyzed_documents: number;
  system_status: string;
}

export const AdminDashboard: React.FC = () => {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.get('/admin/stats')
      .then(res => setStats(res.data))
      .catch(err => console.error(err))
      .finally(() => setIsLoading(false));
  }, []);

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-cyber-primary">Super Admin Command Center</h2>
          <p className="text-cyber-secondary text-sm mt-1">
            Global management of user roles, security analyst access, platform audit logs, and system settings.
          </p>
        </div>

        <button
          onClick={() => navigate('/super-admin/users')}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-3 rounded-xl font-semibold shadow-md transition-all text-sm shrink-0 border border-cyan/20"
        >
          <Users size={18} />
          <span>Manage Platform Users</span>
        </button>
      </div>

      {/* Overview Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Total Users</p>
            <p className="metric-value mt-2">{stats?.total_users ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">Registered Accounts</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
            <Users size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Active Analysts</p>
            <p className="metric-value mt-2 text-cyan-hover">{stats?.active_analysts ?? 0}</p>
            <p className="text-xs text-cyan-hover font-medium mt-1">Security Role Active</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-cyan/10 text-cyan-hover flex items-center justify-center">
            <ShieldCheck size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Signed Docs</p>
            <p className="metric-value mt-2">{stats?.total_signed_documents ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">System Total</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
            <FileText size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Analyzed Docs</p>
            <p className="metric-value mt-2">{stats?.total_analyzed_documents ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">Evaluated Total</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center">
            <Activity size={24} />
          </div>
        </div>
      </div>

      {/* Platform Status Card */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 rounded-2xl bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold">
            <CheckCircle2 size={24} />
          </div>
          <div>
            <h3 className="text-lg font-bold text-cyber-primary">Q-SHIELD Core Services Status</h3>
            <p className="text-xs text-cyber-secondary mt-0.5">Database SQLite connected. FastAPI Backend online on localhost:8000.</p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800">
          OPERATIONAL
        </span>
      </div>
    </div>
  );
};
