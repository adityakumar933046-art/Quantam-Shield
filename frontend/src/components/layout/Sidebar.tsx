import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth, UserRole } from '../../context/AuthContext';
import {
  Shield,
  LayoutDashboard,
  FileSignature,
  FileText,
  Search,
  AlertTriangle,
  History,
  FileCheck,
  Users,
  ShieldCheck,
  Activity,
  Lock,
  Settings,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Atom,
  ShieldAlert
} from 'lucide-react';

interface SidebarProps {
  isCollapsed: boolean;
  toggleSidebar: () => void;
}

interface MenuItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

export const Sidebar: React.FC<SidebarProps> = ({ isCollapsed, toggleSidebar }) => {
  const { user, logout } = useAuth();

  const getMenuItems = (role?: UserRole): MenuItem[] => {
    switch (role) {
      case 'DIGITAL_SIGNATURE_USER':
        return [
          { label: 'Dashboard', path: '/signature/dashboard', icon: <LayoutDashboard size={20} /> },
          { label: 'Create Digital Signature', path: '/signature/create', icon: <FileSignature size={20} /> },
          { label: 'My Signed Documents', path: '/signature/documents', icon: <FileText size={20} /> },
          { label: 'Profile', path: '/profile', icon: <User size={20} /> },
        ];
      case 'SECURITY_ANALYST':
        return [
          { label: 'Dashboard', path: '/security/dashboard', icon: <LayoutDashboard size={20} /> },
          { label: 'Analyze Signed Document', path: '/security/analyze', icon: <Search size={20} /> },
          { label: 'Attack Simulation', path: '/security/simulation', icon: <ShieldAlert size={20} /> },
          { label: 'Quantum Simulation', path: '/security/qds-simulation', icon: <Atom size={20} /> },
          { label: 'Security Reports', path: '/security/reports', icon: <FileText size={20} /> },
          { label: 'Performance Evaluation', path: '/security/performance', icon: <Activity size={20} /> },
          { label: 'Threat Incidents', path: '/security/incidents', icon: <AlertTriangle size={20} /> },
          { label: 'Analysis History', path: '/security/history', icon: <History size={20} /> },
          { label: 'Security Audit Logs', path: '/security/audit-logs', icon: <FileCheck size={20} /> },
          { label: 'Profile', path: '/profile', icon: <User size={20} /> },
        ];
      case 'SUPER_ADMIN':
        return [
          { label: 'Dashboard', path: '/super-admin/dashboard', icon: <LayoutDashboard size={20} /> },
          { label: 'Users', path: '/super-admin/users', icon: <Users size={20} /> },
          { label: 'Security Analysts', path: '/super-admin/analysts', icon: <ShieldCheck size={20} /> },
          { label: 'Security Reports', path: '/super-admin/reports', icon: <FileText size={20} /> },
          { label: 'Performance Evaluation', path: '/super-admin/performance', icon: <Activity size={20} /> },
          { label: 'Platform Activity', path: '/super-admin/activity', icon: <Activity size={20} /> },
          { label: 'Platform Security', path: '/super-admin/security', icon: <Lock size={20} /> },
          { label: 'Platform Settings', path: '/super-admin/settings', icon: <Settings size={20} /> },
          { label: 'Audit Logs', path: '/super-admin/audit-logs', icon: <FileCheck size={20} /> },
          { label: 'Profile', path: '/profile', icon: <User size={20} /> },
        ];
      default:
        return [];
    }
  };

  const menuItems = getMenuItems(user?.role);

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 bg-navy z-30 transition-all duration-300 flex flex-col border-r border-navy-light text-white shadow-xl ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-navy-light">
        <div className="flex items-center space-x-3 overflow-hidden">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan to-blue-600 flex items-center justify-center shadow-lg shadow-cyan/20 shrink-0">
            <Shield className="w-6 h-6 text-white" />
          </div>
          {!isCollapsed && (
            <div className="flex flex-col whitespace-nowrap">
              <span className="font-extrabold text-lg tracking-wider text-white">Q-SHIELD</span>
              <span className="text-[10px] text-cyan uppercase tracking-widest -mt-1 font-semibold">Security Platform</span>
            </div>
          )}
        </div>

        <button
          onClick={toggleSidebar}
          className="text-slate-400 hover:text-cyan p-1.5 rounded-lg hover:bg-navy-light transition-colors"
          title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
        >
          {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>
      </div>

      {/* Role Badge Header */}
      {!isCollapsed && (
        <div className="px-4 py-3 bg-navy-dark/60 border-b border-navy-light/40">
          <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Current Role</p>
          <p className="text-xs font-bold text-cyan mt-0.5 tracking-wide">
            {user?.role.replace(/_/g, ' ')}
          </p>
        </div>
      )}

      {/* Navigation List */}
      <nav className="flex-1 py-4 px-3 overflow-y-auto space-y-1">
        {menuItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-3 py-3 rounded-lg sidebar-link transition-all duration-200 ${
                isActive
                  ? 'bg-navy-light text-cyan border-l-4 border-cyan font-semibold shadow-md'
                  : 'text-slate-300 hover:text-white hover:bg-navy-light/60'
              }`
            }

            title={isCollapsed ? item.label : undefined}
          >
            <span className="shrink-0">{item.icon}</span>
            {!isCollapsed && <span className="truncate">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Sidebar Footer Logout Action */}
      <div className="p-3 border-t border-navy-light">
        <button
          onClick={logout}
          className="w-full flex items-center space-x-3 px-3 py-3 rounded-lg text-slate-300 hover:text-red-400 hover:bg-red-500/10 transition-colors sidebar-link"
          title="Log Out"
        >
          <LogOut size={20} className="shrink-0" />
          {!isCollapsed && <span className="font-semibold">Log Out</span>}
        </button>
      </div>
    </aside>
  );
};
