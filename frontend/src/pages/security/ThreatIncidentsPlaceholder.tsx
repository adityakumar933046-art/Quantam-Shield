import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Clock,
  Filter,
  Search,
  Eye,
  X,
  Shield,
  ShieldCheck,
  Layers,
  Zap,
  Lock,
  UserX,
  Copy,
  RefreshCw,
  Sliders,
  FileText
} from 'lucide-react';

interface ThreatIncident {
  incident_id: number;
  analysis_document_id?: number;
  threat_category: string;
  severity: string;
  threat_score: number;
  threat_status: string;
  description: string;
  evidence_data?: string;
  detected_at: string;
  updated_at: string;
}

interface TimeWindowStats {
  time_window: string;
  total_uploads: number;
  total_verifications: number;
  successful_verifications: number;
  failed_verifications: number;
  repeated_verifications: number;
  unique_documents: number;
  unique_signatures: number;
  avg_verification_frequency_per_min: number;
  max_verification_burst: number;
  unauthorized_attempt_count: number;
  avg_replay_suspicion_score: number;
}

interface ActivityStats {
  stats_5m: TimeWindowStats;
  stats_15m: TimeWindowStats;
  stats_1h: TimeWindowStats;
  stats_24h: TimeWindowStats;
  total_incidents_count: number;
  open_incidents_count: number;
}

export const ThreatIncidentsPlaceholder: React.FC = () => {
  const [incidents, setIncidents] = useState<ThreatIncident[]>([]);
  const [activityStats, setActivityStats] = useState<ActivityStats | null>(null);
  const [selectedWindow, setSelectedWindow] = useState<'5m' | '15m' | '1h' | '24h'>('15m');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState(true);
  
  const [selectedIncident, setSelectedIncident] = useState<ThreatIncident | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  const fetchThreatData = async () => {
    setIsLoading(true);
    try {
      const [incRes, statsRes] = await Promise.all([
        api.get('/security/threat-incidents'),
        api.get('/security/activity-stats')
      ]);
      setIncidents(incRes.data);
      setActivityStats(statsRes.data);
    } catch (err) {
      console.error("Failed to load threat detection data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, []);

  const handleUpdateStatus = async (incidentId: number, newStatus: string) => {
    setIsUpdatingStatus(true);
    try {
      const res = await api.put(`/security/threat-incidents/${incidentId}/status`, {
        threat_status: newStatus
      });
      
      setIncidents(prev => prev.map(i => i.incident_id === incidentId ? res.data : i));
      if (selectedIncident && selectedIncident.incident_id === incidentId) {
        setSelectedIncident(res.data);
      }
    } catch (err) {
      console.error("Failed to update incident status:", err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-red-400/20 text-red-300 border-red-400/30';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'LOW':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'OPEN':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'INVESTIGATING':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'RESOLVED':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'FALSE_POSITIVE':
        return 'bg-slate-100 text-slate-700 border-slate-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  const filteredIncidents = incidents.filter(i => {
    if (selectedCategory !== 'ALL' && i.threat_category !== selectedCategory) return false;
    if (selectedStatus !== 'ALL' && i.threat_status !== selectedStatus) return false;
    return true;
  });

  const getCurrentStats = (): TimeWindowStats | null => {
    if (!activityStats) return null;
    switch (selectedWindow) {
      case '5m': return activityStats.stats_5m;
      case '15m': return activityStats.stats_15m;
      case '1h': return activityStats.stats_1h;
      case '24h': return activityStats.stats_24h;
      default: return activityStats.stats_15m;
    }
  };

  const stats = getCurrentStats();

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Page Title & Refresh */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-cyber-primary">Historical Threat Detection Dashboard</h2>
          <p className="text-cyber-secondary text-sm mt-1">
            Deterministic rule-based threat incidents, replay suspicion tracking, and time-window activity metrics.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="px-3.5 py-1.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30 flex items-center space-x-1.5">
            <Zap size={14} className="text-cyan fill-cyan/20 animate-pulse" />
            <span>STEP 6: THREAT ENGINE</span>
          </div>

          <button
            onClick={fetchThreatData}
            disabled={isLoading}
            className="p-2 rounded-xl border border-slate-200 text-cyber-primary hover:bg-slate-50 transition-colors"
          >
            <RefreshCw size={18} className={isLoading ? "animate-spin text-cyan" : ""} />
          </button>
        </div>
      </div>

      {/* Time Window Activity Stats Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider flex items-center space-x-2">
            <Activity size={16} className="text-cyan-hover" />
            <span>Time-Window Activity Statistics</span>
          </h3>

          {/* Time Window Selector */}
          <div className="inline-flex bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs font-bold">
            {(['5m', '15m', '1h', '24h'] as const).map((win) => (
              <button
                key={win}
                onClick={() => setSelectedWindow(win)}
                className={`px-3 py-1 rounded-lg transition-all ${
                  selectedWindow === win ? 'bg-navy text-cyan shadow' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {win}
              </button>
            ))}
          </div>
        </div>

        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
              <span className="text-[11px] font-bold text-cyber-secondary uppercase tracking-wider block">Total Uploads / Verifs</span>
              <div className="flex items-baseline space-x-1">
                <span className="text-2xl font-black text-cyber-primary">{stats.total_uploads + stats.total_verifications}</span>
                <span className="text-xs text-cyber-secondary font-medium">({stats.total_uploads} up / {stats.total_verifications} ver)</span>
              </div>
            </div>

            <div className="p-4 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
              <span className="text-[11px] font-bold text-cyber-secondary uppercase tracking-wider block">Replay Suspicion Score</span>
              <div className="flex items-baseline space-x-1">
                <span className={`text-2xl font-black ${
                  Number(stats?.avg_replay_suspicion_score ?? 0) > 60 ? 'text-red-600' : (Number(stats?.avg_replay_suspicion_score ?? 0) > 30 ? 'text-amber-600' : 'text-emerald-600')
                }`}>
                  {Number(stats?.avg_replay_suspicion_score ?? 0).toFixed(1)}
                </span>
                <span className="text-xs text-cyber-secondary font-bold">/ 100</span>
              </div>
            </div>

            <div className="p-4 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
              <span className="text-[11px] font-bold text-cyber-secondary uppercase tracking-wider block">Active Open Threats</span>
              <div className="flex items-baseline space-x-1">
                <span className="text-2xl font-black text-red-600">
                  {activityStats?.open_incidents_count || 0}
                </span>
                <span className="text-xs text-cyber-secondary">/ {activityStats?.total_incidents_count || 0} total</span>
              </div>
            </div>

            <div className="p-4 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
              <span className="text-[11px] font-bold text-cyber-secondary uppercase tracking-wider block">Unauthorized Attempts</span>
              <div className="flex items-baseline space-x-1">
                <span className={`text-2xl font-black ${stats.unauthorized_attempt_count > 0 ? 'text-amber-600' : 'text-slate-800'}`}>
                  {stats.unauthorized_attempt_count}
                </span>
                <span className="text-xs text-cyber-secondary">in {stats.time_window}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Threat Filter Controls */}
      <div className="bg-white p-5 rounded-2xl border border-cyber-border shadow-sm space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div className="flex items-center space-x-2">
            <Filter size={18} className="text-cyan-hover" />
            <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">Threat Category Filters</h3>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {[
              { id: 'ALL', label: 'All Categories' },
              { id: 'REPLAY_SUSPECTED', label: 'Replay Activity' },
              { id: 'SUSPICIOUS_REPEATED_VERIFICATION', label: 'Repeated Verification' },
              { id: 'UNAUTHORIZED_VERIFICATION_ATTEMPT', label: 'Unauthorized Access' },
              { id: 'IMPERSONATION_SUSPECTED', label: 'Impersonation' },
              { id: 'SIGNATURE_REUSE_ANOMALY', label: 'Signature Reuse' },
              { id: 'EXCESSIVE_ANALYSIS_ACTIVITY', label: 'Excessive Activity' }
            ].map(cat => (
              <button
                key={cat.id}
                onClick={() => setSelectedCategory(cat.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all ${
                  selectedCategory === cat.id
                    ? 'bg-navy text-cyan border border-cyan/40 shadow-sm'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>

        {/* Status Filter */}
        <div className="flex items-center space-x-3 text-xs font-semibold text-cyber-secondary">
          <span>Filter by Status:</span>
          {['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(st => (
            <button
              key={st}
              onClick={() => setSelectedStatus(st)}
              className={`px-2.5 py-1 rounded-lg border transition-all ${
                selectedStatus === st ? 'bg-slate-900 text-white font-bold' : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden space-y-4">
        {isLoading ? (
          <div className="p-12 text-center text-cyber-secondary">Evaluating historical security threat incidents...</div>
        ) : filteredIncidents.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <ShieldCheck className="w-12 h-12 text-emerald-500 mx-auto" />
            <h4 className="text-lg font-bold text-cyber-primary">No Threat Incidents Detected</h4>
            <p className="text-cyber-secondary text-xs max-w-md mx-auto">
              No historical threat patterns matching the selected category filter were detected across document verifications and authorization logs.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Incident ID</th>
                  <th className="py-4 px-6">Category</th>
                  <th className="py-4 px-6">Severity</th>
                  <th className="py-4 px-6">Threat Score</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6">Detected At</th>
                  <th className="py-4 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {filteredIncidents.map((inc) => (
                  <tr key={inc.incident_id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-4 px-6 font-mono text-xs text-cyber-secondary">#{inc.incident_id}</td>
                    <td className="py-4 px-6 font-bold text-cyber-primary">
                      <span className="text-xs">{inc.threat_category.replace(/_/g, ' ')}</span>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`px-2.5 py-1 rounded-full text-[11px] font-bold border ${getSeverityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-slate-100 h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              inc.threat_score > 70 ? 'bg-red-500' : (inc.threat_score > 35 ? 'bg-amber-500' : 'bg-yellow-500')
                            }`}
                            style={{ width: `${Math.min(100, inc.threat_score)}%` }}
                          ></div>
                        </div>
                        <span className="font-mono text-xs font-bold text-slate-800">{Number(inc?.threat_score ?? 0).toFixed(1)}</span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`px-2.5 py-1 rounded-full text-[11px] font-bold border ${getStatusBadge(inc.threat_status)}`}>
                        {inc.threat_status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-xs text-cyber-secondary">
                      {new Date(inc.detected_at).toLocaleString()}
                    </td>
                    <td className="py-4 px-6 text-right">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="bg-navy hover:bg-navy-light text-cyan font-bold px-3 py-1.5 rounded-lg text-xs border border-cyan/30 shadow-sm flex items-center space-x-1.5 ml-auto"
                      >
                        <Eye size={14} />
                        <span>INSPECT EVIDENCE</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Incident Detail & Evidence Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 text-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Header */}
            <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-red-500/20 text-red-400 flex items-center justify-center border border-red-500/30">
                  <ShieldAlert size={22} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Threat Incident #{selectedIncident.incident_id}</h3>
                  <p className="text-xs text-slate-400">{selectedIncident.threat_category.replace(/_/g, ' ')}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/50 hover:bg-slate-800"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
              {/* Description Box */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-400 font-bold block text-[11px]">DETERMINISTIC THREAT FINDINGS</span>
                <p className="text-white font-medium text-xs leading-relaxed">{selectedIncident.description}</p>
              </div>

              {/* Status Update Control */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-400 font-bold block text-[11px]">INCIDENT RESOLUTION STATUS</span>
                <div className="flex flex-wrap gap-2">
                  {['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(st => (
                    <button
                      key={st}
                      disabled={isUpdatingStatus}
                      onClick={() => handleUpdateStatus(selectedIncident.incident_id, st)}
                      className={`px-3 py-1.5 rounded-lg font-bold text-xs border transition-all ${
                        selectedIncident.threat_status === st
                          ? 'bg-cyan text-navy border-cyan shadow-md'
                          : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Evidence JSON Data */}
              {selectedIncident.evidence_data && (
                <div className="space-y-2">
                  <span className="text-slate-400 font-bold block text-[11px]">EMPIRICAL EVIDENCE DATA (JSON)</span>
                  <pre className="p-4 bg-slate-950 rounded-xl font-mono text-[11px] text-cyan border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(JSON.parse(selectedIncident.evidence_data), null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setSelectedIncident(null)}
                className="bg-slate-800 hover:bg-slate-700 text-white font-bold px-5 py-2 rounded-xl text-xs"
              >
                Close Modal
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
