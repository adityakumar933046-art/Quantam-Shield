import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import {
  FileText,
  Download,
  Plus,
  Filter,
  Shield,
  AlertTriangle,
  FileCheck,
  Activity,
  ExternalLink,
  CheckCircle2,
  XCircle,
  FileCode
} from 'lucide-react';

interface SecurityReportItem {
  report_id: number;
  report_reference: string;
  report_type: string;
  document_name?: string;
  overall_status: string;
  risk_score: number;
  risk_level: string;
  summary?: string;
  generated_by: string;
  generated_at: string;
  created_at: string;
}

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<SecurityReportItem[]>([]);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [showGenerateModal, setShowGenerateModal] = useState<boolean>(false);
  const [newReportType, setNewReportType] = useState<string>('THREAT_REPORT');
  const [targetId, setTargetId] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);

  const navigate = useNavigate();

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const url = filterType === 'ALL' ? '/reports' : `/reports?report_type=${filterType}`;
      const res = await api.get(url);
      setReports(res.data);
    } catch (err) {
      console.error('Failed to load security reports:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [filterType]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsGenerating(true);
    try {
      const payload: any = {
        report_type: newReportType,
        notes: notes || undefined
      };
      if (newReportType === 'ANALYSIS_REPORT' && targetId) {
        payload.analysis_id = parseInt(targetId, 10);
      } else if (newReportType === 'SIMULATION_REPORT' && targetId) {
        payload.simulation_id = parseInt(targetId, 10);
      }

      const res = await api.post('/reports/generate', payload);
      setNotification(`Report ${res.data.report_reference} generated successfully.`);
      setShowGenerateModal(false);
      setTargetId('');
      setNotes('');
      fetchReports();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to generate report');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExport = async (reportRef: string, format: string) => {
    try {
      const response = await api.get(`/reports/${reportRef}/export?format=${format}`, {
        responseType: 'blob'
      });
      const blob = new Blob([response.data], {
        type: format === 'pdf' ? 'application/pdf' : (format === 'html' ? 'text/html' : 'application/json')
      });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `${reportRef}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      console.error('Export error:', err);
      alert('Failed to export report');
    }
  };

  const getRiskBadge = (level: string) => {
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
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-2xl font-bold text-cyber-primary">Security & Audit Reports</h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30">
              AUDIT COMPLIANT
            </span>
          </div>
          <p className="text-cyber-secondary text-sm mt-1">
            Deterministic, tamper-evident security evaluation reports synthesized across cryptographic checks and quantum-inspired analysis.
          </p>
        </div>

        <button
          onClick={() => setShowGenerateModal(true)}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-3 rounded-xl font-semibold shadow-md transition-all text-sm shrink-0 border border-cyan/20"
        >
          <Plus size={18} />
          <span>Generate Security Report</span>
        </button>
      </div>

      {notification && (
        <div className="p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-xl text-sm flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="font-bold">&times;</button>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-cyber-border pb-3">
        {['ALL', 'ANALYSIS_REPORT', 'THREAT_REPORT', 'SIMULATION_REPORT', 'AUDIT_REPORT', 'PERFORMANCE_REPORT'].map((tab) => (
          <button
            key={tab}
            onClick={() => setFilterType(tab)}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              filterType === tab
                ? 'bg-navy text-cyan shadow-sm border border-cyan/30'
                : 'bg-white text-cyber-secondary hover:text-cyber-primary border border-cyber-border'
            }`}
          >
            {tab.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Reports Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading reports catalog...</div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-cyber-secondary space-y-3">
            <FileText size={40} className="mx-auto text-slate-300" />
            <p className="font-semibold text-slate-600">No reports available</p>
            <p className="text-xs text-slate-400">Generate a report above or conduct document security analysis.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Report Reference</th>
                  <th className="py-4 px-6">Type</th>
                  <th className="py-4 px-6">Document / Target</th>
                  <th className="py-4 px-6">Overall Decision</th>
                  <th className="py-4 px-6">Risk Score</th>
                  <th className="py-4 px-6">Generated By</th>
                  <th className="py-4 px-6">Date</th>
                  <th className="py-4 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {reports.map((rpt) => (
                  <tr key={rpt.report_id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-4 px-6 font-mono text-xs font-bold text-cyber-primary">
                      <button
                        onClick={() => navigate(`/security/reports/${rpt.report_reference || rpt.report_id}`)}
                        className="text-cyan-hover hover:underline"
                      >
                        {rpt.report_reference || `QSR-${rpt.report_id}`}
                      </button>
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700">
                        {rpt.report_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-xs text-cyber-primary max-w-[180px] truncate font-medium">
                      {rpt.document_name || 'System / Batch'}
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-bold bg-blue-50 text-blue-700">
                        {rpt.overall_status}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold border ${getRiskBadge(rpt.risk_level)}`}>
                        {Number(rpt?.risk_score ?? 0).toFixed(1)}/100 ({rpt.risk_level})
                      </span>
                    </td>
                    <td className="py-4 px-6 text-xs text-cyber-secondary truncate max-w-[140px]">
                      {rpt.generated_by}
                    </td>
                    <td className="py-4 px-6 text-xs text-cyber-secondary">
                      {new Date(rpt.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-4 px-6 text-right">
                      <div className="flex items-center justify-end space-x-1">
                        <button
                          onClick={() => handleExport(rpt.report_reference || String(rpt.report_id), 'pdf')}
                          title="Export PDF"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-red-600 hover:bg-red-50 transition-colors"
                        >
                          <Download size={15} />
                        </button>
                        <button
                          onClick={() => handleExport(rpt.report_reference || String(rpt.report_id), 'html')}
                          title="Export HTML"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50 transition-colors"
                        >
                          <FileText size={15} />
                        </button>
                        <button
                          onClick={() => handleExport(rpt.report_reference || String(rpt.report_id), 'json')}
                          title="Export JSON"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-emerald-600 hover:bg-emerald-50 transition-colors"
                        >
                          <FileCode size={15} />
                        </button>
                        <button
                          onClick={() => navigate(`/security/reports/${rpt.report_reference || rpt.report_id}`)}
                          title="View Details"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-navy hover:bg-slate-100 transition-colors"
                        >
                          <ExternalLink size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-cyber-border shadow-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <h3 className="text-lg font-bold text-cyber-primary">Generate Security Report</h3>
              <button onClick={() => setShowGenerateModal(false)} className="text-slate-400 hover:text-slate-600 text-lg font-bold">&times;</button>
            </div>

            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Report Category</label>
                <select
                  value={newReportType}
                  onChange={(e) => setNewReportType(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl text-sm focus:ring-2 focus:ring-cyan focus:outline-none"
                >
                  <option value="THREAT_REPORT">Threat Intelligence Report (System-wide)</option>
                  <option value="AUDIT_REPORT">Audit Log Chain Integrity Report</option>
                  <option value="PERFORMANCE_REPORT">Defensive Performance Evaluation Report</option>
                  <option value="ANALYSIS_REPORT">Document Analysis Report (By Analysis ID)</option>
                  <option value="SIMULATION_REPORT">Attack Simulation Report (By Sim ID)</option>
                </select>
              </div>

              {(newReportType === 'ANALYSIS_REPORT' || newReportType === 'SIMULATION_REPORT') && (
                <div>
                  <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">
                    {newReportType === 'ANALYSIS_REPORT' ? 'Target Document Analysis ID' : 'Target Simulation ID'}
                  </label>
                  <input
                    type="number"
                    required
                    placeholder="e.g. 1"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    className="w-full px-3 py-2 border border-cyber-border rounded-xl text-sm focus:ring-2 focus:ring-cyan focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-bold text-cyber-secondary uppercase mb-1">Analyst Notes (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="Additional context or investigation notes..."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="w-full px-3 py-2 border border-cyber-border rounded-xl text-sm focus:ring-2 focus:ring-cyan focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowGenerateModal(false)}
                  className="px-4 py-2 border border-cyber-border rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isGenerating}
                  className="px-5 py-2 bg-navy text-cyan rounded-xl text-sm font-bold hover:bg-navy-light disabled:opacity-50"
                >
                  {isGenerating ? 'Synthesizing...' : 'Generate Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
export default ReportsPage;
