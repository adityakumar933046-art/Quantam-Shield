import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import {
  FileText,
  Download,
  ArrowLeft,
  Shield,
  AlertTriangle,
  FileCheck,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Hash,
  FileCode,
  Info
} from 'lucide-react';

export const ReportDetailPage: React.FC = () => {
  const { reportReference } = useParams<{ reportReference: string }>();
  const navigate = useNavigate();

  const [report, setReport] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'quantum' | 'threats' | 'raw'>('overview');

  useEffect(() => {
    if (!reportReference) return;
    setIsLoading(true);
    api.get(`/reports/${reportReference}`)
      .then((res) => {
        setReport(res.data);
      })
      .catch((err) => {
        console.error('Failed to load report:', err);
      })
      .finally(() => setIsLoading(false));
  }, [reportReference]);

  const handleExport = async (format: string) => {
    if (!reportReference) return;
    try {
      const response = await api.get(`/reports/${reportReference}/export?format=${format}`, {
        responseType: 'blob'
      });
      const blob = new Blob([response.data], {
        type: format === 'pdf' ? 'application/pdf' : (format === 'html' ? 'text/html' : 'application/json')
      });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `${reportReference}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      console.error('Export error:', err);
      alert('Failed to export report');
    }
  };

  if (isLoading) {
    return <div className="p-12 text-center text-cyber-secondary">Loading report data...</div>;
  }

  if (!report) {
    return (
      <div className="p-12 text-center space-y-4">
        <p className="text-red-600 font-bold">Report not found.</p>
        <button
          onClick={() => navigate('/security/reports')}
          className="px-4 py-2 bg-navy text-cyan rounded-xl text-sm font-semibold"
        >
          Back to Reports Catalog
        </button>
      </div>
    );
  }

  const rData = typeof report.report_data === 'string' ? JSON.parse(report.report_data) : (report.report_data || {});
  const docInfo = rData.document_information || {};
  const classicalInfo = rData.classical_verification || {};
  const quantumInfo = rData.quantum_inspired_analysis || {};
  const threatInfo = rData.threat_detection || {};
  const recs: string[] = rData.recommendations || [];

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
      {/* Top Bar with Navigation & Actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/security/reports')}
          className="flex items-center space-x-2 text-cyber-secondary hover:text-cyber-primary text-sm font-semibold"
        >
          <ArrowLeft size={16} />
          <span>Back to Reports Catalog</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => handleExport('pdf')}
            className="flex items-center space-x-1.5 px-3.5 py-2 bg-red-50 text-red-700 border border-red-200 rounded-xl text-xs font-bold hover:bg-red-100 transition-colors"
          >
            <Download size={14} />
            <span>PDF</span>
          </button>
          <button
            onClick={() => handleExport('html')}
            className="flex items-center space-x-1.5 px-3.5 py-2 bg-blue-50 text-blue-700 border border-blue-200 rounded-xl text-xs font-bold hover:bg-blue-100 transition-colors"
          >
            <FileText size={14} />
            <span>HTML</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            className="flex items-center space-x-1.5 px-3.5 py-2 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-xl text-xs font-bold hover:bg-emerald-100 transition-colors"
          >
            <FileCode size={14} />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Header Card */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-4">
          <div>
            <div className="flex items-center space-x-3">
              <span className="font-mono text-xl font-bold text-cyber-primary">{report.report_reference}</span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30">
                {report.report_type.replace('_', ' ')}
              </span>
            </div>
            <p className="text-xs text-cyber-secondary mt-1">
              Generated by <span className="font-semibold text-slate-700">{report.generated_by}</span> on {new Date(report.generated_at).toLocaleString()} UTC
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">Decision Status</p>
              <p className="text-base font-extrabold text-cyber-primary">{report.overall_status}</p>
            </div>
            <div className="text-right pl-4 border-l border-cyber-border">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">Risk Assessment</p>
              <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-extrabold border ${getRiskBadge(report.risk_level)}`}>
                {report.risk_score.toFixed(1)}/100 ({report.risk_level})
              </span>
            </div>
          </div>
        </div>

        {report.summary && (
          <p className="text-sm text-slate-700 bg-slate-50 p-3.5 rounded-xl border border-slate-200">
            {report.summary}
          </p>
        )}

        {/* Tab Switcher */}
        <div className="flex space-x-2 pt-2 border-t border-cyber-border">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
              activeTab === 'overview' ? 'bg-navy text-cyan' : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            Overview & Verification
          </button>
          <button
            onClick={() => setActiveTab('quantum')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
              activeTab === 'quantum' ? 'bg-navy text-cyan' : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            Quantum-Inspired Analysis
          </button>
          <button
            onClick={() => setActiveTab('threats')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
              activeTab === 'threats' ? 'bg-navy text-cyan' : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            Threat Findings ({threatInfo.threats_count ?? 0})
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
              activeTab === 'raw' ? 'bg-navy text-cyan' : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            Structured Audit Data
          </button>
        </div>
      </div>

      {/* Tab: Overview & Verification */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Document Information */}
            <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
              <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider flex items-center space-x-2">
                <FileText size={16} className="text-cyan" />
                <span>Document Information</span>
              </h3>
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">Document Name:</span>
                  <span className="font-bold text-cyber-primary">{docInfo.document_name || report.document_name || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">File Type:</span>
                  <span className="font-semibold text-slate-700">{docInfo.file_type || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">Document SHA-256:</span>
                  <span className="font-mono text-[10px] text-slate-600 max-w-[200px] truncate">{docInfo.document_hash || report.document_hash || 'N/A'}</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-cyber-secondary font-medium">Signature ID:</span>
                  <span className="font-mono text-xs font-bold text-slate-800">{docInfo.signature_id || report.signature_id || 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Classical Cryptographic Verification */}
            <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
              <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider flex items-center space-x-2">
                <Shield size={16} className="text-cyan" />
                <span>Classical Cryptographic Verification</span>
              </h3>
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">Digital Signature:</span>
                  <span className={`font-bold ${classicalInfo.digital_signature_status === 'VALID' ? 'text-emerald-600' : 'text-red-600'}`}>
                    {classicalInfo.digital_signature_status || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">Document Byte Integrity:</span>
                  <span className={`font-bold ${classicalInfo.document_integrity === 'INTACT' ? 'text-emerald-600' : 'text-amber-600'}`}>
                    {classicalInfo.document_integrity || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-100">
                  <span className="text-cyber-secondary font-medium">Algorithms:</span>
                  <span className="font-mono text-xs text-slate-700">
                    {classicalInfo.signature_algorithm || 'RSA-SHA256'} / {classicalInfo.hash_algorithm || 'SHA-256'}
                  </span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-cyber-secondary font-medium">Certificate Status:</span>
                  <span className="font-semibold text-slate-700">{classicalInfo.certificate_status || 'TRUSTED'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Recommendations */}
          {recs.length > 0 && (
            <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-3">
              <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
                Deterministic Security Recommendations
              </h3>
              <div className="space-y-2">
                {recs.map((rec, idx) => (
                  <div key={idx} className="p-3 bg-blue-50/70 border-l-4 border-blue-600 rounded-r-xl text-xs text-blue-950 font-medium">
                    &bull; {rec}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Quantum-Inspired Analysis */}
      {activeTab === 'quantum' && (
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
              Quantum-Inspired Mathematical Analysis
            </h3>
            <span className="text-xs font-mono font-bold text-cyan bg-navy px-2.5 py-1 rounded-lg">
              {quantumInfo.quantum_analysis_version || 'QIA-2.0'}
            </span>
          </div>

          <div className="p-4 bg-amber-50/80 border border-amber-200 rounded-xl text-xs text-amber-900 flex items-start space-x-2.5">
            <Info size={18} className="text-amber-700 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">Scientific & Mathematical Model Notice:</p>
              <p className="mt-0.5">
                {quantumInfo.scientific_disclaimer ||
                  'Classical digital signatures are mathematically mapped into Hilbert space state vectors for disturbance and projective anomaly analysis. No physical quantum hardware was used.'}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">State Consistency</p>
              <p className="text-xl font-mono font-extrabold text-emerald-600 mt-1">
                {quantumInfo.state_consistency_score ?? 100.0}%
              </p>
            </div>
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">State Disturbance D</p>
              <p className="text-xl font-mono font-extrabold text-slate-800 mt-1">
                {quantumInfo.state_disturbance_score ?? 0.0}
              </p>
            </div>
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">Pauli Anomaly</p>
              <p className="text-xl font-mono font-extrabold text-amber-600 mt-1">
                {quantumInfo.combined_pauli_disturbance ?? 0.0}%
              </p>
            </div>
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
              <p className="text-[11px] font-bold text-cyber-secondary uppercase">P(Secure Subspace)</p>
              <p className="text-xl font-mono font-extrabold text-blue-600 mt-1">
                {quantumInfo.secure_measurement_probability ?? 100.0}%
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab: Threats */}
      {activeTab === 'threats' && (
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
            Detected Threat Incidents ({threatInfo.threats_count ?? 0})
          </h3>

          {!threatInfo.detected_threats || threatInfo.detected_threats.length === 0 ? (
            <div className="p-8 text-center text-emerald-600 font-semibold text-sm">
              Zero structural threats, replay anomalies, or signature tampering detected.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase">
                    <th className="py-3 px-4">Threat Type</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border text-xs">
                  {threatInfo.detected_threats.map((t: any, idx: number) => (
                    <tr key={idx}>
                      <td className="py-3 px-4 font-bold text-cyber-primary">{t.threat_type}</td>
                      <td className="py-3 px-4 font-mono">{t.threat_category}</td>
                      <td className="py-3 px-4">
                        <span className="font-bold text-red-600">{t.severity}</span>
                      </td>
                      <td className="py-3 px-4 font-mono">{t.confidence}%</td>
                      <td className="py-3 px-4 text-slate-600">{t.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab: Raw JSON Audit Data */}
      {activeTab === 'raw' && (
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-cyber-primary uppercase tracking-wider">
              Sanitized Audit JSON
            </h3>
            <span className="text-xs text-slate-400">Zero sensitive secrets or private keys</span>
          </div>
          <pre className="bg-slate-900 text-slate-100 p-4 rounded-xl text-xs font-mono overflow-x-auto max-h-[500px]">
            {JSON.stringify(rData, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
export default ReportDetailPage;
