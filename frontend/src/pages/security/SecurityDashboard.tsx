import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import {
  Search,
  AlertTriangle,
  ShieldCheck,
  FileCheck,
  ArrowUpRight,
  Zap,
  ShieldAlert,
  FileText,
  Activity,
  Atom,
  TrendingUp,
  Shield
} from 'lucide-react';

interface OverviewStats {
  total_documents_analyzed: number;
  verified_documents: number;
  failed_verifications: number;
  threats_detected: number;
  high_risk_documents: number;
  critical_risk_documents: number;
  system_status: string;
}

interface QuantumMetrics {
  average_state_consistency: number;
  average_state_disturbance: number;
  average_threat_probability: number;
  average_pauli_disturbance: number;
  analyzed_sample_count: number;
}

interface IncidentItem {
  incident_id: number;
  threat_category: string;
  threat_type: string;
  severity: string;
  threat_score: number;
  description: string;
  created_at: string;
}

export const SecurityDashboard: React.FC = () => {
  const [overview, setOverview] = useState<OverviewStats | null>(null);
  const [quantumMetrics, setQuantumMetrics] = useState<QuantumMetrics | null>(null);
  const [threats, setThreats] = useState<IncidentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [ovRes, qRes, tRes] = await Promise.all([
          api.get('/dashboard/overview'),
          api.get('/dashboard/quantum-analysis'),
          api.get('/dashboard/threats')
        ]);
        setOverview(ovRes.data);
        setQuantumMetrics(qRes.data);
        setThreats(tRes.data.recent_threats || []);
      } catch (err) {
        console.error("Failed to load security analyst dashboard data:", err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const getThreatBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH':
        return 'bg-amber-100 text-amber-800 border-amber-200';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-2xl font-bold text-cyber-primary">Security Analyst Operations</h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30">
              STEP 7 VERIFIED
            </span>
          </div>
          <p className="text-cyber-secondary text-sm mt-1">
            Real-time monitoring of cryptographic verification, quantum-inspired analysis, and automated audit reports.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={() => navigate('/security/reports')}
            className="flex items-center space-x-1.5 bg-white hover:bg-slate-50 text-cyber-primary px-4 py-2.5 rounded-xl font-semibold shadow-sm text-sm border border-cyber-border transition-colors"
          >
            <FileText size={16} />
            <span>Reports</span>
          </button>
          <button
            onClick={() => navigate('/security/performance')}
            className="flex items-center space-x-1.5 bg-white hover:bg-slate-50 text-cyber-primary px-4 py-2.5 rounded-xl font-semibold shadow-sm text-sm border border-cyber-border transition-colors"
          >
            <Activity size={16} />
            <span>Benchmark</span>
          </button>
          <button
            onClick={() => navigate('/security/analyze')}
            className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-2.5 rounded-xl font-semibold shadow-md transition-all text-sm border border-cyan/20"
          >
            <Search size={16} />
            <span>Analyze Document</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Analyzed Docs</p>
            <p className="metric-value mt-2">{overview?.total_documents_analyzed ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">Total Inspected</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center">
            <FileCheck size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Verified Signatures</p>
            <p className="metric-value mt-2 text-emerald-600">{overview?.verified_documents ?? 0}</p>
            <p className="text-xs text-emerald-600 font-medium mt-1">Integrity Confirmed</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
            <ShieldCheck size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Threats Detected</p>
            <p className="metric-value mt-2 text-amber-600">{overview?.threats_detected ?? 0}</p>
            <p className="text-xs text-amber-600 font-medium mt-1">Anomalies Logged</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center">
            <AlertTriangle size={24} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">High/Critical Risk</p>
            <p className="metric-value mt-2 text-red-600">
              {(overview?.high_risk_documents ?? 0) + (overview?.critical_risk_documents ?? 0)}
            </p>
            <p className="text-xs text-red-600 font-medium mt-1">Immediate Action</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-red-50 text-red-600 flex items-center justify-center">
            <ShieldAlert size={24} />
          </div>
        </div>
      </div>

      {/* Quantum-Inspired Mathematical Metrics Banner */}
      <div className="bg-gradient-to-r from-navy via-navy to-slate-900 text-white p-6 rounded-2xl border border-navy-light shadow-md">
        <div className="flex items-center justify-between border-b border-navy-light/60 pb-4 mb-4">
          <div className="flex items-center space-x-2.5">
            <Atom className="text-cyan w-6 h-6" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-cyan">
              Quantum-Inspired Mathematical Analysis (Platform Averages)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-300">
            {quantumMetrics?.analyzed_sample_count ?? 0} Samples Evaluated
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3.5 bg-navy-light/40 rounded-xl border border-navy-light/60">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Avg State Consistency</p>
            <p className="text-xl font-mono font-bold text-cyan mt-1">
              {typeof quantumMetrics?.average_state_consistency === 'number' ? Number(quantumMetrics.average_state_consistency).toFixed(1) : '0.0'}%
            </p>
          </div>
          <div className="p-3.5 bg-navy-light/40 rounded-xl border border-navy-light/60">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Avg Disturbance D</p>
            <p className="text-xl font-mono font-bold text-white mt-1">
              {typeof quantumMetrics?.average_state_disturbance === 'number' ? Number(quantumMetrics.average_state_disturbance).toFixed(4) : '0.0000'}
            </p>
          </div>
          <div className="p-3.5 bg-navy-light/40 rounded-xl border border-navy-light/60">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Avg Pauli Anomaly</p>
            <p className="text-xl font-mono font-bold text-amber-400 mt-1">
              {typeof quantumMetrics?.average_pauli_disturbance === 'number' ? Number(quantumMetrics.average_pauli_disturbance).toFixed(1) : '0.0'}%
            </p>
          </div>
          <div className="p-3.5 bg-navy-light/40 rounded-xl border border-navy-light/60">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">P(Threat Subspace)</p>
            <p className="text-xl font-mono font-bold text-red-400 mt-1">
              {typeof quantumMetrics?.average_threat_probability === 'number' ? Number(quantumMetrics.average_threat_probability).toFixed(1) : '0.0'}%
            </p>
          </div>
        </div>
      </div>

      {/* Threat Incidents Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        <div className="p-6 border-b border-cyber-border flex items-center justify-between">
          <div>
            <h3 className="section-title">Threat Incidents Monitor</h3>
            <p className="text-xs text-cyber-secondary mt-0.5">Real-time digital signature threat and forgery analysis log</p>
          </div>
          <button
            onClick={() => navigate('/security/incidents')}
            className="text-cyan-hover hover:text-navy text-sm font-semibold flex items-center space-x-1"
          >
            <span>All Incidents</span>
            <ArrowUpRight size={16} />
          </button>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading threat intelligence data...</div>
        ) : threats.length === 0 ? (
          <div className="p-8 text-center text-cyber-secondary text-sm">No active threats detected. Platform status operational.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Incident ID</th>
                  <th className="py-4 px-6">Category</th>
                  <th className="py-4 px-6">Threat Type</th>
                  <th className="py-4 px-6">Severity</th>
                  <th className="py-4 px-6">Threat Score</th>
                  <th className="py-4 px-6">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {threats.map((inc) => (
                  <tr key={inc.incident_id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-4 px-6 font-mono text-xs font-bold text-cyber-primary">THR-{inc.incident_id}</td>
                    <td className="py-4 px-6 font-mono text-xs text-cyber-secondary">{inc.threat_category}</td>
                    <td className="py-4 px-6 font-semibold text-cyber-primary">{inc.threat_type}</td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold border ${getThreatBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-4 px-6 font-mono text-sm font-bold text-cyber-primary">
                      {Number(inc?.threat_score ?? 0).toFixed(1)}/100
                    </td>
                    <td className="py-4 px-6 text-cyber-secondary text-xs max-w-xs truncate">
                      {inc.description}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
export default SecurityDashboard;
