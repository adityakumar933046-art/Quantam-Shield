import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import { FileSignature, FileText, CheckCircle2, Clock, Plus, ArrowUpRight, Shield } from 'lucide-react';

interface Stats {
  total_documents: number;
  signed_documents: number;
  pending_signatures: number;
  recent_activity_count: number;
}

interface DocumentItem {
  document_id: number;
  original_filename: string;
  signed_filename: string;
  file_hash: string;
  signature_algorithm: string;
  status: string;
  created_at: string;
}

export const SignatureDashboard: React.FC = () => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, docsRes] = await Promise.all([
          api.get('/signature/stats'),
          api.get('/signature/documents'),
        ]);
        setStats(statsRes.data);
        setDocuments(docsRes.data);
      } catch (err) {
        console.error("Failed to load signature dashboard data:", err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-cyber-primary">Digital Signature Workspace</h2>
          <p className="text-cyber-secondary text-sm mt-1">
            Generate and manage tamper-proof cryptographic digital signatures for electronic documents.
          </p>
        </div>

        <button
          onClick={() => navigate('/signature/create')}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-3 rounded-xl font-semibold shadow-md transition-all text-sm shrink-0 border border-cyan/20"
        >
          <Plus size={18} />
          <span>Create Digital Signature</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Total Documents</p>
            <p className="metric-value mt-2">{stats?.total_documents ?? 0}</p>
            <p className="text-xs text-emerald-600 font-medium mt-1 flex items-center">
              <CheckCircle2 size={12} className="mr-1" /> Database Active
            </p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center">
            <FileText size={28} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Signed Documents</p>
            <p className="metric-value mt-2 text-cyan-hover">{stats?.signed_documents ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">RSA-SHA256 Encrypted</p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-cyan/10 text-cyan-hover flex items-center justify-center">
            <FileSignature size={28} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-cyber-secondary uppercase tracking-wider">Recent Activity</p>
            <p className="metric-value mt-2">{stats?.recent_activity_count ?? 0}</p>
            <p className="text-xs text-cyber-secondary font-medium mt-1">Logs Recorded</p>
          </div>
          <div className="w-14 h-14 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center">
            <Clock size={28} />
          </div>
        </div>
      </div>

      {/* Recent Signed Documents Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        <div className="p-6 border-b border-cyber-border flex items-center justify-between">
          <h3 className="section-title">Recent Signed Documents</h3>
          <button
            onClick={() => navigate('/signature/documents')}
            className="text-cyan-hover hover:text-navy text-sm font-semibold flex items-center space-x-1"
          >
            <span>View All Documents</span>
            <ArrowUpRight size={16} />
          </button>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading document repository...</div>
        ) : documents.length === 0 ? (
          <div className="p-12 text-center">
            <Shield className="w-12 h-12 text-slate-300 mx-auto mb-3" />
            <p className="text-cyber-primary font-semibold">No Signed Documents Found</p>
            <p className="text-cyber-secondary text-sm mt-1">Upload a normal document to generate your first digital signature.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Document Name</th>
                  <th className="py-4 px-6">Signed Output</th>
                  <th className="py-4 px-6">Algorithm</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {documents.map((doc) => (
                  <tr key={doc.document_id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-4 px-6 font-semibold text-cyber-primary">{doc.original_filename}</td>
                    <td className="py-4 px-6 text-cyber-secondary">{doc.signed_filename}</td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-slate-100 text-slate-800 border border-slate-200">
                        {doc.signature_algorithm}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                        {doc.status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-cyber-secondary text-xs">
                      {new Date(doc.created_at).toLocaleDateString()}
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
