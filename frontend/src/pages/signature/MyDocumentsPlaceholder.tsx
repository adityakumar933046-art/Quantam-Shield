import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import { FileText, Download, ShieldCheck, Search, Eye, X, Shield } from 'lucide-react';

interface SignatureDetails {
  signature_id: number;
  document_id: number;
  signature_algorithm: string;
  hash_algorithm: string;
  certificate_subject: string;
  certificate_issuer: string;
  certificate_serial_number: string;
  certificate_fingerprint: string;
  signature_fingerprint: string;
  signing_timestamp: string;
  verification_status: string;
}

interface DocumentItem {
  document_id: number;
  user_id: number;
  original_filename: string;
  signed_filename?: string;
  document_hash: string;
  file_size: number;
  status: string;
  created_at: string;
  signature?: SignatureDetails;
}

export const MyDocumentsPlaceholder: React.FC = () => {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedDoc, setSelectedDoc] = useState<DocumentItem | null>(null);
  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);

  const fetchDocuments = async () => {
    try {
      const res = await api.get('/documents/my-documents');
      setDocuments(res.data);
    } catch (err) {
      console.error("Failed to load documents:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const handleDownload = async (doc: DocumentItem) => {
    try {
      const response = await api.get(`/documents/${doc.document_id}/download`, {
        responseType: 'blob'
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', doc.signed_filename || `signed_${doc.original_filename}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
      alert("Failed to download signed document.");
    }
  };

  const handleViewDetails = (doc: DocumentItem) => {
    setSelectedDoc(doc);
    setIsDetailsModalOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
        <h2 className="text-2xl font-bold text-cyber-primary">My Signed Documents</h2>
        <p className="text-cyber-secondary text-sm mt-1">
          Historical repository of all cryptographically signed PDF documents issued by your user account.
        </p>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading document repository...</div>
        ) : documents.length === 0 ? (
          <div className="p-12 text-center">
            <Shield className="w-12 h-12 text-slate-300 mx-auto mb-3" />
            <p className="text-cyber-primary font-semibold">No Signed Documents Found</p>
            <p className="text-cyber-secondary text-sm mt-1">
              Upload a PDF document to generate your first digital signature.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Document Name</th>
                  <th className="py-4 px-6">SHA-256 Hash</th>
                  <th className="py-4 px-6">Algorithm</th>
                  <th className="py-4 px-6">Certificate Issuer</th>
                  <th className="py-4 px-6">Signing Date</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {documents.map((doc) => (
                  <tr key={doc.document_id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-4 px-6 font-semibold text-cyber-primary">
                      {doc.signed_filename || doc.original_filename}
                    </td>
                    <td className="py-4 px-6 font-mono text-xs text-slate-500 max-w-xs truncate">
                      {doc.document_hash}
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-100 text-slate-800 border border-slate-200">
                        {doc.signature?.signature_algorithm || "RSA-SHA256"}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-xs text-cyber-secondary truncate max-w-xs">
                      {doc.signature?.certificate_issuer || "Q-SHIELD Development CA (Demo)"}
                    </td>
                    <td className="py-4 px-6 text-cyber-secondary text-xs">
                      {new Date(doc.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${
                        doc.status === 'SIGNED' ? 'bg-emerald-100 text-emerald-800' : 'bg-yellow-100 text-yellow-800'
                      }`}>
                        {doc.status}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right space-x-2">
                      <button
                        onClick={() => handleViewDetails(doc)}
                        className="text-cyber-primary hover:text-cyan-hover font-semibold text-xs inline-flex items-center space-x-1 border border-cyber-border px-2.5 py-1.5 rounded-lg hover:bg-white shadow-sm"
                      >
                        <Eye size={14} />
                        <span>View Details</span>
                      </button>

                      <button
                        onClick={() => handleDownload(doc)}
                        className="text-cyan-hover hover:text-navy font-semibold text-xs inline-flex items-center space-x-1 bg-navy text-cyan px-3 py-1.5 rounded-lg border border-cyan/20 shadow-sm"
                      >
                        <Download size={14} />
                        <span>Download</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Signature Details Modal */}
      {isDetailsModalOpen && selectedDoc && (
        <div className="fixed inset-0 bg-navy-dark/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-cyber-border relative">
            <button
              onClick={() => setIsDetailsModalOpen(false)}
              className="absolute top-4 right-4 text-cyber-secondary hover:text-cyber-primary"
            >
              <X size={20} />
            </button>

            <h3 className="text-lg font-bold text-cyber-primary mb-4 flex items-center space-x-2">
              <ShieldCheck size={20} className="text-emerald-600" />
              <span>Signature & Certificate Details</span>
            </h3>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-lg">
                <span className="text-cyber-secondary font-bold block mb-0.5">Original File</span>
                <span className="font-semibold text-cyber-primary">{selectedDoc.original_filename}</span>
              </div>

              <div className="p-3 bg-slate-50 rounded-lg">
                <span className="text-cyber-secondary font-bold block mb-0.5">Document SHA-256 Hash</span>
                <span className="font-mono text-slate-700 break-all">{selectedDoc.document_hash}</span>
              </div>

              {selectedDoc.signature ? (
                <>
                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-cyber-secondary font-bold block mb-0.5">Certificate Subject</span>
                    <span className="font-semibold text-cyber-primary">{selectedDoc.signature.certificate_subject}</span>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-cyber-secondary font-bold block mb-0.5">Certificate Issuer</span>
                    <span className="font-semibold text-cyber-primary">{selectedDoc.signature.certificate_issuer}</span>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-cyber-secondary font-bold block mb-0.5">Certificate Fingerprint</span>
                    <span className="font-mono text-slate-700 break-all">{selectedDoc.signature.certificate_fingerprint}</span>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg">
                    <span className="text-cyber-secondary font-bold block mb-0.5">Signature Fingerprint</span>
                    <span className="font-mono text-slate-700 break-all">{selectedDoc.signature.signature_fingerprint}</span>
                  </div>
                </>
              ) : (
                <div className="p-3 bg-yellow-50 text-yellow-800 rounded-lg">
                  Signature not generated yet.
                </div>
              )}
            </div>

            <div className="mt-6 flex justify-between items-center">
              <button
                onClick={() => handleDownload(selectedDoc)}
                className="px-4 py-2 bg-navy text-cyan rounded-xl text-xs font-bold flex items-center space-x-1"
              >
                <Download size={14} />
                <span>Download PDF</span>
              </button>

              <button
                onClick={() => setIsDetailsModalOpen(false)}
                className="px-4 py-2 border border-cyber-border rounded-xl text-xs font-bold text-cyber-secondary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
