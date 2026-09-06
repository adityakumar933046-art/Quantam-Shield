import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import {
  FileCheck,
  Shield,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Link,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';

interface AuditLogDetailedItem {
  log_id: number;
  event_id?: string;
  user_email: string;
  action: string;
  resource_type?: string;
  resource_id?: string;
  result: string;
  details: string;
  previous_log_hash?: string;
  current_log_hash?: string;
  ip_address: string;
  created_at: string;
}

interface IntegrityResult {
  status: string;
  total_records_verified: number;
  chain_intact: boolean;
  verified_at: string;
  genesis_hash?: string;
  latest_hash?: string;
  corrupted_event_id?: string;
  discrepancy_details?: string;
}

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogDetailedItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [integrityResult, setIntegrityResult] = useState<IntegrityResult | null>(null);

  const fetchLogs = () => {
    setIsLoading(true);
    api.get('/admin/audit-logs/detailed')
      .then(res => setLogs(res.data))
      .catch(err => {
        console.error(err);
        // Fallback to legacy
        api.get('/admin/audit-logs').then(r => setLogs(r.data)).catch(console.error);
      })
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleVerifyIntegrity = async () => {
    setIsVerifying(true);
    try {
      const res = await api.get('/admin/audit-logs/verify-integrity');
      setIntegrityResult(res.data);
      // Refresh logs to show the verification check event
      fetchLogs();
    } catch (err) {
      console.error('Integrity verification failed:', err);
      alert('Failed to verify audit log integrity');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-2xl font-bold text-cyber-primary">Tamper-Evident Audit Trail</h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30">
              HASH-CHAIN SECURED
            </span>
          </div>
          <p className="text-cyber-secondary text-sm mt-1">
            Immutable, append-only cryptographic hash chain recording all authentication, signing, verification, and simulation events.
          </p>
        </div>

        <button
          onClick={handleVerifyIntegrity}
          disabled={isVerifying}
          className="flex items-center space-x-2 bg-navy hover:bg-navy-light text-cyan px-5 py-3 rounded-xl font-semibold shadow-md transition-all text-sm shrink-0 border border-cyan/20 disabled:opacity-50"
        >
          {isVerifying ? (
            <RefreshCw size={18} className="animate-spin" />
          ) : (
            <ShieldCheck size={18} />
          )}
          <span>Verify Audit Log Integrity</span>
        </button>
      </div>

      {/* Verification Result Banner */}
      {integrityResult && (
        <div className={`p-5 rounded-2xl border ${
          integrityResult.chain_intact
            ? 'bg-emerald-50/80 border-emerald-300 text-emerald-900'
            : 'bg-red-50/80 border-red-300 text-red-900'
        }`}>
          <div className="flex items-start justify-between">
            <div className="flex items-center space-x-3">
              {integrityResult.chain_intact ? (
                <CheckCircle2 size={24} className="text-emerald-600 shrink-0" />
              ) : (
                <ShieldAlert size={24} className="text-red-600 shrink-0" />
              )}
              <div>
                <p className="font-extrabold text-sm uppercase tracking-wide">
                  {integrityResult.status}: {integrityResult.chain_intact ? 'Chain Cryptographically Valid' : 'Integrity Discrepancy Detected'}
                </p>
                <p className="text-xs mt-0.5 opacity-90">
                  Verified {integrityResult.total_records_verified} records sequentially.
                  {integrityResult.discrepancy_details && ` Discrepancy: ${integrityResult.discrepancy_details}`}
                </p>
              </div>
            </div>

            <div className="text-right text-[11px] font-mono opacity-80">
              <p>Verified: {new Date(integrityResult.verified_at).toLocaleTimeString()}</p>
              {integrityResult.latest_hash && (
                <p className="truncate max-w-[200px]">Head: {integrityResult.latest_hash.substring(0, 16)}...</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-white rounded-2xl border border-cyber-border shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-cyber-secondary">Loading audit events...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-bg border-b border-cyber-border text-xs font-bold text-cyber-secondary uppercase tracking-wider">
                  <th className="py-4 px-6">Event ID</th>
                  <th className="py-4 px-6">User / Actor</th>
                  <th className="py-4 px-6">Action</th>
                  <th className="py-4 px-6">Result</th>
                  <th className="py-4 px-6">Description</th>
                  <th className="py-4 px-6">Hash Pointer (SHA-256)</th>
                  <th className="py-4 px-6">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-12 text-center text-cyber-secondary">
                      <Clock size={36} className="mx-auto text-slate-300 mb-2" />
                      <p className="font-semibold text-slate-600">No audit activity available</p>
                      <p className="text-xs text-slate-400 mt-0.5">Audit log records will be appended sequentially as operations occur.</p>
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.log_id} className="hover:bg-slate-50 transition-colors">
                      <td className="py-4 px-6 font-mono text-xs text-cyber-secondary">
                        {log.event_id || `#${log.log_id}`}
                      </td>
                      <td className="py-4 px-6 font-semibold text-cyber-primary text-xs">
                        {log.user_email}
                      </td>
                      <td className="py-4 px-6">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-navy text-cyan border border-cyan/20">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-4 px-6">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.result === 'SUCCESS' || log.result === 'AUDIT_LOG_VALID'
                            ? 'bg-emerald-100 text-emerald-800'
                            : (log.result === 'FAILED' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800')
                        }`}>
                          {log.result}
                        </span>
                      </td>
                      <td className="py-4 px-6 text-cyber-secondary text-xs max-w-xs truncate">
                        {log.details}
                      </td>
                      <td className="py-4 px-6 font-mono text-[11px] text-slate-500">
                        {log.current_log_hash ? (
                          <span title={`Current Hash: ${log.current_log_hash}\nPrev Hash: ${log.previous_log_hash}`}>
                            {log.current_log_hash.substring(0, 12)}...
                          </span>
                        ) : (
                          <span className="text-slate-400">LEGACY</span>
                        )}
                      </td>
                      <td className="py-4 px-6 text-cyber-secondary text-xs">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
export default AuditLogsPage;
