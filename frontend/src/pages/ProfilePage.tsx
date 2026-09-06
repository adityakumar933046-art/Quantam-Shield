import React from 'react';
import { useAuth } from '../context/AuthContext';
import { User, Shield, Mail, Key, CheckCircle2 } from 'lucide-react';

export const ProfilePage: React.FC = () => {
  const { user } = useAuth();

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
        <h2 className="text-2xl font-bold text-cyber-primary">User Profile & Account Security</h2>
        <p className="text-cyber-secondary text-sm mt-1">
          Review your account identity, security role authorization, and active platform session parameters.
        </p>
      </div>

      <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6">
        <div className="flex items-center space-x-5 pb-6 border-b border-cyber-border">
          <div className="w-16 h-16 rounded-2xl bg-navy text-cyan flex items-center justify-center font-bold text-2xl border-2 border-cyan/30 shadow-lg">
            {user?.full_name?.charAt(0) || 'U'}
          </div>
          <div>
            <h3 className="text-xl font-bold text-cyber-primary">{user?.full_name}</h3>
            <p className="text-sm text-cyber-secondary">{user?.email}</p>
            <span className="inline-block mt-2 px-3 py-1 bg-navy text-cyan rounded-full text-xs font-bold border border-cyan/30">
              ROLE: {user?.role}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
            <p className="text-xs font-bold text-cyber-secondary uppercase">Account Status</p>
            <p className="text-sm font-bold text-emerald-600 mt-1 flex items-center">
              <CheckCircle2 size={16} className="mr-1.5" />
              ACTIVE (Cryptographically Authenticated)
            </p>
          </div>

          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
            <p className="text-xs font-bold text-cyber-secondary uppercase">Session Protection</p>
            <p className="text-sm font-bold text-cyber-primary mt-1 flex items-center">
              <Key size={16} className="mr-1.5 text-cyan-hover" />
              JWT HS256 Token (24h Expiry)
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
