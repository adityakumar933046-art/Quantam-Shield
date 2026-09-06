import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import { Users, UserPlus, Shield, CheckCircle, XCircle, AlertCircle, X } from 'lucide-react';

interface UserItem {
  user_id: number;
  full_name: string;
  email: string;
  role: string;
  status: string;
  created_at: string;
}

export const UsersManagement: React.FC = () => {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Form State
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('DIGITAL_SIGNATURE_USER');
  const [error, setError] = useState<string | null>(null);

  const fetchUsers = async () => {
    try {
      const res = await api.get('/users');
      setUsers(res.data);
    } catch (err) {
      console.error("Failed to load users:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleToggleStatus = async (user_id: number, currentStatus: string) => {
    const newStatus = currentStatus === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
    try {
      await api.patch(`/users/${user_id}/status`, { status: newStatus });
      fetchUsers();
    } catch (err) {
      console.error("Failed to update status:", err);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.post('/users', {
        full_name: fullName,
        email,
        password,
        role,
        status: 'ACTIVE'
      });
      setIsModalOpen(false);
      setFullName('');
      setEmail('');
      setPassword('');
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create user');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-cyber-primary">User Role Management</h2>
          <p className="text-cyber-secondary text-sm mt-1">
            Provision and audit accounts across Super Admin, Security Analyst, and Digital Signature User roles.
          </p>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-3 rounded-xl font-semibold shadow-md text-sm shrink-0 border border-cyan/20"
        >
          <UserPlus size={18} />
          <span>Add New User Account</span>
        </button>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading user directory...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">User ID</th>
                  <th className="py-4 px-6">Full Name</th>
                  <th className="py-4 px-6">Email Address</th>
                  <th className="py-4 px-6">Assigned Role</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {users.map((u) => (
                  <tr key={u.user_id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-4 px-6 font-mono text-xs text-cyber-secondary">#{u.user_id}</td>
                    <td className="py-4 px-6 font-semibold text-cyber-primary">{u.full_name}</td>
                    <td className="py-4 px-6 text-cyber-secondary">{u.email}</td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold bg-slate-100 text-slate-800 border border-slate-200">
                        {u.role}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${
                        u.status === 'ACTIVE' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                      }`}>
                        {u.status}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <button
                        onClick={() => handleToggleStatus(u.user_id, u.status)}
                        className={`text-xs font-bold px-3 py-1.5 rounded-lg border transition-colors ${
                          u.status === 'ACTIVE'
                            ? 'border-red-200 text-red-600 hover:bg-red-50'
                            : 'border-emerald-200 text-emerald-600 hover:bg-emerald-50'
                        }`}
                      >
                        {u.status === 'ACTIVE' ? 'Deactivate' : 'Activate'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal for Creating New User */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-navy-dark/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-cyber-border relative">
            <button
              onClick={() => setIsModalOpen(false)}
              className="absolute top-4 right-4 text-cyber-secondary hover:text-cyber-primary"
            >
              <X size={20} />
            </button>

            <h3 className="text-xl font-bold text-cyber-primary mb-4">Create New Platform User</h3>

            {error && (
              <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-xs font-medium border border-red-200">
                {error}
              </div>
            )}

            <form onSubmit={handleCreateUser} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl focus:ring-2 focus:ring-cyan focus:outline-none"
                  placeholder="John Doe"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl focus:ring-2 focus:ring-cyan focus:outline-none"
                  placeholder="analyst@qshield.com"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl focus:ring-2 focus:ring-cyan focus:outline-none"
                  placeholder="••••••••"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Assigned Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl focus:ring-2 focus:ring-cyan focus:outline-none bg-white"
                >
                  <option value="DIGITAL_SIGNATURE_USER">Digital Signature User</option>
                  <option value="SECURITY_ANALYST">Security Analyst</option>
                  <option value="SUPER_ADMIN">Super Admin</option>
                </select>
              </div>

              <div className="pt-2 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-cyber-secondary hover:bg-slate-100 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 bg-navy text-cyan rounded-xl font-semibold shadow-md hover:bg-navy-light"
                >
                  Create User
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
