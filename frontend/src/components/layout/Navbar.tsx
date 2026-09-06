import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Menu, User as UserIcon, LogOut, ShieldCheck, ChevronDown, CheckCircle2 } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';

interface NavbarProps {
  toggleSidebar: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ toggleSidebar }) => {
  const { user, logout } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Compute title based on current path
  const getPageTitle = (path: string): string => {
    if (path.includes('/super-admin/dashboard')) return 'Super Admin Platform Dashboard';
    if (path.includes('/super-admin/users')) return 'User Management';
    if (path.includes('/super-admin/analysts')) return 'Security Analysts Directory';
    if (path.includes('/super-admin/activity')) return 'Platform Activity Overview';
    if (path.includes('/super-admin/security')) return 'Platform Security Policies';
    if (path.includes('/super-admin/settings')) return 'Platform Settings';
    if (path.includes('/super-admin/audit-logs')) return 'Platform Security Audit Logs';

    if (path.includes('/signature/dashboard')) return 'Digital Signature Generator Dashboard';
    if (path.includes('/signature/create')) return 'Create Cryptographic Digital Signature';
    if (path.includes('/signature/documents')) return 'My Signed Documents';

    if (path.includes('/security/dashboard')) return 'Security Analyst Dashboard';
    if (path.includes('/security/analyze')) return 'Analyze Signed Document';
    if (path.includes('/security/incidents')) return 'Threat Incidents Monitor';
    if (path.includes('/security/history')) return 'Security Analysis History';
    if (path.includes('/security/audit-logs')) return 'Security Audit Trail';

    if (path.includes('/profile')) return 'User Profile Settings';

    return 'Q-SHIELD Security Platform';
  };

  const handleLogout = async () => {
    setDropdownOpen(false);
    await logout();
    navigate('/login');
  };

  return (
    <header className="h-16 bg-white border-b border-cyber-border sticky top-0 z-20 px-6 flex items-center justify-between shadow-sm">
      {/* Left Title & Sidebar Toggle */}
      <div className="flex items-center space-x-4">
        <button
          onClick={toggleSidebar}
          className="text-cyber-secondary hover:text-cyber-primary p-2 rounded-lg hover:bg-cyber-bg transition-colors"
          title="Toggle Sidebar Menu"
        >
          <Menu size={22} />
        </button>

        <h1 className="text-xl font-bold text-cyber-primary tracking-tight hidden sm:block">
          {getPageTitle(location.pathname)}
        </h1>
      </div>

      {/* Right User Status & Profile Dropdown */}
      <div className="flex items-center space-x-4">
        {/* System Status Pill */}
        <div className="hidden md:flex items-center space-x-2 bg-emerald-50 text-emerald-700 px-3 py-1.5 rounded-full border border-emerald-200 text-xs font-semibold">
          <CheckCircle2 size={14} className="text-emerald-600" />
          <span>System Operational</span>
        </div>

        {/* Profile Dropdown Container */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center space-x-3 p-1.5 rounded-lg hover:bg-cyber-bg border border-transparent hover:border-cyber-border transition-all"
          >
            <div className="w-9 h-9 rounded-full bg-navy text-cyan flex items-center justify-center font-bold text-sm shadow-sm border border-cyan/30">
              {user?.full_name?.charAt(0) || 'U'}
            </div>
            <div className="text-left hidden lg:block">
              <p className="text-sm font-semibold text-cyber-primary leading-tight">{user?.full_name}</p>
              <p className="text-[11px] text-cyber-secondary font-medium leading-none mt-0.5">
                {user?.role.replace(/_/g, ' ')}
              </p>
            </div>
            <ChevronDown size={16} className="text-cyber-secondary" />
          </button>

          {/* Profile Dropdown Menu */}
          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 bg-white rounded-xl shadow-xl border border-cyber-border py-2 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="px-4 py-3 border-b border-cyber-border">
                <p className="text-sm font-bold text-cyber-primary">{user?.full_name}</p>
                <p className="text-xs text-cyber-secondary truncate">{user?.email}</p>
                <div className="mt-2 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-cyan/10 text-cyan-hover border border-cyan/20">
                  {user?.role}
                </div>
              </div>

              <div className="py-1">
                <button
                  onClick={() => {
                    setDropdownOpen(false);
                    navigate('/profile');
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-cyber-primary hover:bg-cyber-bg flex items-center space-x-2 font-medium"
                >
                  <UserIcon size={16} className="text-cyber-secondary" />
                  <span>Profile & Security</span>
                </button>
              </div>

              <div className="border-t border-cyber-border pt-1">
                <button
                  onClick={handleLogout}
                  className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 flex items-center space-x-2 font-semibold"
                >
                  <LogOut size={16} className="text-red-500" />
                  <span>Log Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
