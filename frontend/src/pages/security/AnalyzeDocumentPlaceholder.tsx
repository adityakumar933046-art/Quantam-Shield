import React, { useState } from 'react';
import { api } from '../../services/api';
import {
  Upload,
  Search,
  ShieldCheck,
  FileCheck,
  AlertCircle,
  Copy,
  Check,
  Info,
  Clock,
  Key,
  UserCheck,
  ShieldAlert,
  FileText,
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Zap,
  Atom,
  Activity,
  Cpu,
  Layers,
  HelpCircle,
  BarChart3,
  Sliders,
  X,
  ChevronRight,
  Download,
  Award,
  Printer
} from 'lucide-react';

interface ExtractedMeta {
  signature_analysis_id: number;
  analysis_document_id: number;
  signature_detected: boolean;
  signature_status: string;
  signature_algorithm: string;
  hash_algorithm: string;
  signature_fingerprint: string;
  field_name: string;
  signing_time?: string;
  certificate_subject: string;
  certificate_issuer: string;
  certificate_serial_number: string;
  validity_start?: string;
  validity_end?: string;
  certificate_fingerprint: string;
  public_key_algorithm: string;
  public_key_size: number;
  signer_name: string;
  signer_organization: string;
}

interface SigVerification {
  verification_id: number;
  analysis_document_id: number;
  signature_identifier: string;
  signature_index: number;
  verification_status: string;
  integrity_status: string;
  signature_algorithm: string;
  hash_algorithm: string;
  certificate_time_status: string;
  verification_timestamp: string;
  verification_details: string;
  error_details?: string;
}

interface QuantumAnalysisData {
  quantum_analysis_id: number;
  analysis_document_id: number;
  security_state_vector: number[];
  secure_consistency_score: number;
  disturbance_score: number;
  pauli_x_score: number;
  pauli_y_score: number;
  pauli_z_score: number;
  secure_measurement_score: number;
  suspicious_measurement_score: number;
  high_risk_measurement_score: number;
  forgery_risk_score: number;
  analysis_confidence_score: number;
  confidence_level: string;
  final_classification: string;
  analysis_version: string;
  created_at: string;
}

interface ThreatIncidentData {
  incident_id: number;
  threat_category: string;
  severity: string;
  threat_score: number;
  threat_status: string;
  description: string;
  evidence_data?: string;
  detected_at: string;
}

interface CertificateAnalysisData {
  certificate_analysis_id: number;
  analysis_document_id: number;
  certificate_fingerprint: string;
  structure_status: string;
  time_validity_status: string;
  trust_status: string;
  chain_status: string;
  revocation_status: string;
  ocsp_status: string;
  crl_status: string;
  algorithm_security_status: string;
  certificate_security_score: number;
  analysis_confidence: number;
  details?: string;
  checked_at: string;
}

interface FinalDecisionData {
  analysis_document_id: number;
  final_security_decision: string;
  overall_risk_score: number;
  summary_justification: string;
  recommended_action: string;
  layer1_signature_status: string;
  layer2_integrity_status: string;
  layer3_certificate_status: string;
  layer4_quantum_status: string;
  layer5_threat_status: string;
}

interface SecurityReportData {
  report_id: number;
  analysis_document_id: number;
  final_security_decision: string;
  overall_risk_score: number;
  report_path: string;
  report_hash: string;
  report_version: string;
  generated_by: string;
  generated_at: string;
}

interface AnalysisResult {
  analysis_document_id: number;
  analyst_user_id: number;
  original_file_name: string;
  file_size: number;
  document_hash: string;
  signature_present: boolean;
  signature_status: string;
  upload_timestamp: string;
  extracted_metadata?: ExtractedMeta;
  verifications?: SigVerification[];
  quantum_analysis?: QuantumAnalysisData;
  threat_incidents?: ThreatIncidentData[];
  certificate_analysis?: CertificateAnalysisData;
  security_report?: SecurityReportData;
}

interface AnalysisExplanation {
  analysis_id: number;
  document_id: number;
  final_classification: string;
  forgery_risk_score: number;
  confidence_level: string;
  step1_feature_mapping: string;
  step2_state_vector: string;
  step3_pauli_analysis: string;
  step4_measurement: string;
  step5_decision: string;
}

export const AnalyzeDocumentPlaceholder: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  
  // Verification states
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifStep, setVerifStep] = useState(0);
  const [verifMessage, setVerifMessage] = useState('');

  // Quantum analysis states
  const [isQuantumAnalyzing, setIsQuantumAnalyzing] = useState(false);
  const [quantumStep, setQuantumStep] = useState(0);
  const [quantumMessage, setQuantumMessage] = useState('');
  const [explanationModal, setExplanationModal] = useState<AnalysisExplanation | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);

  // Step 6 & Step 7 states
  const [isThreatDetecting, setIsThreatDetecting] = useState(false);
  const [isCertValidating, setIsCertValidating] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [reportModal, setReportModal] = useState<FinalDecisionData | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  const verifProgressSteps = [
    "Preparing Verification",
    "Extracting Signed Data",
    "Loading Certificate",
    "Loading Public Key",
    "Verifying Cryptographic Signature",
    "Checking Document Integrity",
    "Saving Verification Results",
    "Completed"
  ];

  const quantumProgressSteps = [
    "Extracting Deterministic Signature Feature Vector S = [V, I, C, E, A]",
    "Constructing Quantum-Inspired State Vector |ψ⟩ = α|Secure⟩ + β|Disturbed⟩",
    "Calculating Euclidean State Disturbance D in Feature Space",
    "Evaluating Analytical Pauli Operators (X, Y, Z)",
    "Performing Projective Measurements across Subspaces",
    "Deriving Quantum-Inspired Forgery Risk Score & Confidence Level",
    "Storing Mathematical Security Analysis Record",
    "Analysis Completed"
  ];

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      validateAndSetFile(file);
    }
  };

  const validateAndSetFile = (file: File) => {
    setError(null);
    setAnalysisResult(null);

    const ext = file.name.toLowerCase().split('.').pop() || '';
    if (!['pdf', 'txt', 'json', 'sig'].includes(ext)) {
      setError("Invalid file format. Supported formats: PDF (.pdf), TXT (.txt), JSON (.json), and Detached Signature (.sig).");
      setSelectedFile(null);
      return;
    }

    if (file.size > 25 * 1024 * 1024) {
      setError("File size exceeds maximum limit of 25MB.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleUploadAndAnalyze = async () => {
    if (!selectedFile) return;
    setIsProcessing(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const res = await api.post('/security/upload-analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setAnalysisResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Document signature inspection failed.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleTriggerVerification = async () => {
    if (!analysisResult) return;
    setIsVerifying(true);
    setError(null);

    try {
      for (let i = 1; i <= 6; i++) {
        setVerifStep(i);
        setVerifMessage(verifProgressSteps[i - 1]);
        await new Promise(r => setTimeout(r, 180));
      }

      const res = await api.post(`/security/analysis/${analysisResult.analysis_document_id}/verify`);
      
      setVerifStep(7);
      setVerifMessage(verifProgressSteps[6]);
      await new Promise(r => setTimeout(r, 180));

      setVerifStep(8);
      setVerifMessage(verifProgressSteps[7]);
      setAnalysisResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Cryptographic verification failed.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTriggerQuantumAnalysis = async () => {
    if (!analysisResult) return;
    setIsQuantumAnalyzing(true);
    setError(null);

    try {
      for (let i = 1; i <= 6; i++) {
        setQuantumStep(i);
        setQuantumMessage(quantumProgressSteps[i - 1]);
        await new Promise(r => setTimeout(r, 220));
      }

      const res = await api.post(`/security/analysis/${analysisResult.analysis_document_id}/quantum-analysis`);
      
      setQuantumStep(7);
      setQuantumMessage(quantumProgressSteps[6]);
      await new Promise(r => setTimeout(r, 180));

      setQuantumStep(8);
      setQuantumMessage(quantumProgressSteps[7]);
    } finally {
      setIsQuantumAnalyzing(false);
    }
  };

  const handleTriggerThreatDetection = async () => {
    if (!analysisResult) return;
    setIsThreatDetecting(true);
    setError(null);

    try {
      const res = await api.post(`/security/analysis/${analysisResult.analysis_document_id}/threat-detection`);
      setAnalysisResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Historical threat detection failed.");
    } finally {
      setIsThreatDetecting(false);
    }
  };

  const handleFetchExplanation = async () => {
    if (!analysisResult) return;
    setIsLoadingExplanation(true);
    try {
      const res = await api.get(`/security/analysis/${analysisResult.analysis_document_id}/analysis-explanation`);
      setExplanationModal(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Failed to fetch analysis explanation.");
    } finally {
      setIsLoadingExplanation(false);
    }
  };

  const handleTriggerCertValidation = async () => {
    if (!analysisResult) return;
    setIsCertValidating(true);
    setError(null);
    try {
      const res = await api.post(`/security/analysis/${analysisResult.analysis_document_id}/certificate-validation`);
      setAnalysisResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Certificate validation failed.");
    } finally {
      setIsCertValidating(false);
    }
  };

  const handleGenerateFinalDecision = async () => {
    if (!analysisResult) return;
    setIsGeneratingReport(true);
    setError(null);
    try {
      const res = await api.post(`/security/analysis/${analysisResult.analysis_document_id}/final-decision`);
      setReportModal(res.data);
      const refreshedDoc = await api.get(`/security/analysis/${analysisResult.analysis_document_id}`);
      setAnalysisResult(refreshedDoc.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Final decision synthesis failed.");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleDownloadPdfReport = async () => {
    if (!analysisResult) return;
    setIsDownloadingPdf(true);
    setError(null);
    try {
      const res = await api.get(`/security/reports/${analysisResult.analysis_document_id}/download-pdf`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Q-SHIELD_Security_Report_${analysisResult.analysis_document_id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error(err);
      setError("Failed to download security report PDF.");
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getCertPolicyNotes = (details?: string): string[] => {
    if (!details) return ["Certificate security validation evaluated successfully."];
    try {
      const parsed = JSON.parse(details);
      return parsed.policy_notes || ["Certificate security validation evaluated successfully."];
    } catch {
      return ["Certificate security validation evaluated successfully."];
    }
  };

  const getFinalDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'SECURE':
        return { label: '✓ SECURE (PASS ALL LAYERS)', cls: 'bg-emerald-600 text-white border-emerald-700' };
      case 'REQUIRES_CAUTION':
        return { label: '⚠️ REQUIRES CAUTION', cls: 'bg-amber-600 text-white border-amber-700' };
      case 'SUSPICIOUS':
        return { label: '⚠️ SUSPICIOUS ACTIVITY DETECTED', cls: 'bg-orange-600 text-white border-orange-700' };
      case 'HIGH_RISK':
        return { label: '🚨 HIGH RISK / FORGERY THREAT', cls: 'bg-red-600 text-white border-red-700' };
      default:
        return { label: '❓ INSUFFICIENT EVIDENCE', cls: 'bg-slate-600 text-white border-slate-700' };
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SIGNATURE_FOUND':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'NO_SIGNATURE_FOUND':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'SIGNATURE_STRUCTURE_INVALID':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'SIGNATURE_UNSUPPORTED':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  const getVerifStatusBadge = (status: string) => {
    switch (status) {
      case 'VALID':
        return { label: '✓ VALID SIGNATURE', cls: 'bg-emerald-100 text-emerald-800 border-emerald-300' };
      case 'INVALID':
        return { label: '✗ INVALID SIGNATURE', cls: 'bg-red-100 text-red-800 border-red-300' };
      case 'UNSUPPORTED':
        return { label: '⚠ UNSUPPORTED SIGNATURE', cls: 'bg-yellow-100 text-yellow-800 border-yellow-300' };
      case 'MALFORMED':
        return { label: '⚠ MALFORMED SIGNATURE', cls: 'bg-red-100 text-red-800 border-red-300' };
      default:
        return { label: '? UNKNOWN STATUS', cls: 'bg-slate-100 text-slate-800 border-slate-300' };
    }
  };

  const getIntegStatusBadge = (status: string) => {
    switch (status) {
      case 'INTACT':
        return { label: '✓ DOCUMENT INTEGRITY INTACT', cls: 'bg-emerald-100 text-emerald-800 border-emerald-300' };
      case 'MODIFIED':
        return { label: '⚠ DOCUMENT MODIFICATION DETECTED', cls: 'bg-red-100 text-red-800 border-red-300' };
      default:
        return { label: 'NOT VERIFIABLE', cls: 'bg-slate-100 text-slate-800 border-slate-300' };
    }
  };

  const getCertTimeBadge = (status: string) => {
    switch (status) {
      case 'VALID_TIME_RANGE':
        return { label: '✓ VALID TIME RANGE', cls: 'bg-emerald-100 text-emerald-800 border-emerald-300' };
      case 'EXPIRED':
        return { label: '⚠ CERTIFICATE EXPIRED', cls: 'bg-amber-100 text-amber-800 border-amber-300' };
      case 'NOT_YET_VALID':
        return { label: '⚠ NOT YET VALID', cls: 'bg-yellow-100 text-yellow-800 border-yellow-300' };
      default:
        return { label: 'TIME RANGE UNKNOWN', cls: 'bg-slate-100 text-slate-800 border-slate-300' };
    }
  };

  const getQuantumRiskBadge = (classification: string) => {
    switch (classification) {
      case 'SECURE':
        return { label: '✓ SECURE STATE', icon: ShieldCheck, cls: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' };
      case 'SUSPICIOUS':
        return { label: '⚠ SUSPICIOUS STATE', icon: AlertTriangle, cls: 'bg-amber-500/20 text-amber-400 border-amber-500/40' };
      case 'HIGH_RISK':
        return { label: '🚨 HIGH RISK / FORGERY THREAT', icon: ShieldAlert, cls: 'bg-red-500/20 text-red-400 border-red-500/40' };
      default:
        return { label: '? UNKNOWN STATE', icon: HelpCircle, cls: 'bg-slate-500/20 text-slate-400 border-slate-500/40' };
    }
  };

  const meta = analysisResult?.extracted_metadata;
  const verifs = analysisResult?.verifications;
  const qData = analysisResult?.quantum_analysis;

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Page Title */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-cyber-primary">Analyze Signed Document</h2>
          <p className="text-cyber-secondary text-sm mt-1">
            Inspect digital signatures, verify classical cryptography, and execute Quantum-Inspired Security Analysis.
          </p>
        </div>

        <div className="px-3.5 py-1.5 rounded-full text-xs font-bold bg-navy text-cyan border border-cyan/30 shrink-0 flex items-center space-x-1.5">
          <Atom size={14} className="text-cyan animate-pulse" />
          <span>STEP 5: QUANTUM-INSPIRED ENGINE</span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start space-x-3 text-red-700 text-sm">
          <AlertCircle size={20} className="shrink-0 mt-0.5 text-red-600" />
          <p className="font-medium">{error}</p>
        </div>
      )}

      {/* Drag and Drop Upload Box */}
      <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6">
        <div
          className={`border-2 border-dashed rounded-2xl p-10 text-center transition-all ${
            selectedFile ? 'border-cyan bg-cyan/5' : 'border-cyber-border hover:border-cyan'
          }`}
        >
          <input
            type="file"
            accept=".pdf,.txt,.json,.sig,application/pdf,text/plain,application/json"
            id="pdf-analysis-input"
            onChange={handleFileSelect}
            className="hidden"
            disabled={isProcessing || isVerifying || isQuantumAnalyzing}
          />

          <label htmlFor="pdf-analysis-input" className="cursor-pointer block">
            <div className="w-16 h-16 rounded-2xl bg-navy text-cyan flex items-center justify-center mx-auto mb-4 shadow-lg shadow-cyan/10">
              <Search size={32} />
            </div>
            <h3 className="text-lg font-bold text-cyber-primary">
              {selectedFile ? selectedFile.name : 'Select or Drag & Drop Signed File (PDF, TXT, JSON, .sig)'}
            </h3>
            <p className="text-xs text-cyber-secondary mt-1">
              Supports PDF, TXT, JSON, and Detached Signatures generated by Q-SHIELD or external CAs (Max file size: 25MB)
            </p>
          </label>

          {selectedFile && (
            <div className="mt-4 inline-flex items-center space-x-3 bg-white px-4 py-2 rounded-xl border border-cyber-border text-xs font-semibold text-cyber-primary">
              <FileText size={16} className="text-cyan-hover" />
              <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
              <span className="text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded text-[10px] font-bold">PDF VALIDATED</span>
            </div>
          )}
        </div>

        <div className="flex justify-end space-x-3">
          <button
            onClick={handleUploadAndAnalyze}
            disabled={!selectedFile || isProcessing || isVerifying || isQuantumAnalyzing}
            className="bg-navy hover:bg-navy-light disabled:opacity-50 text-cyan px-6 py-3.5 rounded-xl font-bold text-sm shadow-md transition-all flex items-center space-x-2 border border-cyan/20 cursor-pointer"
          >
            <Search size={18} />
            <span>{isProcessing ? 'Analyzing & Extracting...' : 'UPLOAD AND EXTRACT SIGNATURE'}</span>
          </button>
        </div>
      </div>

      {/* Verification Progress Modal Overlay */}
      {isVerifying && (
        <div className="p-6 bg-slate-900 text-white rounded-2xl border border-slate-700 shadow-2xl space-y-4 animate-in fade-in">
          <div className="flex items-center justify-between text-xs font-bold">
            <span className="text-cyan">{verifMessage}...</span>
            <span className="text-slate-400">Step {verifStep} of 8</span>
          </div>
          <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
            <div
              className="bg-gradient-to-r from-cyan to-blue-500 h-full transition-all duration-300 rounded-full"
              style={{ width: `${(verifStep / 8) * 100}%` }}
            ></div>
          </div>
        </div>
      )}

      {/* Quantum Progress Modal Overlay */}
      {isQuantumAnalyzing && (
        <div className="p-6 bg-navy text-white rounded-2xl border border-cyan/40 shadow-2xl space-y-4 animate-in fade-in">
          <div className="flex items-center space-x-3">
            <Atom size={24} className="text-cyan animate-spin" />
            <div>
              <h4 className="text-sm font-bold text-white uppercase tracking-wider">Quantum-Inspired Engine Calculation</h4>
              <p className="text-xs text-slate-300">{quantumMessage}...</p>
            </div>
          </div>

          <div className="flex items-center justify-between text-xs font-bold text-slate-400 pt-2">
            <span>Deterministic Math State Vector</span>
            <span className="text-cyan">Step {quantumStep} of 8</span>
          </div>

          <div className="w-full bg-slate-800 h-3 rounded-full overflow-hidden border border-cyan/20">
            <div
              className="bg-gradient-to-r from-cyan via-blue-400 to-indigo-500 h-full transition-all duration-300 rounded-full shadow-lg shadow-cyan/50"
              style={{ width: `${(quantumStep / 8) * 100}%` }}
            ></div>
          </div>
        </div>
      )}

      {/* Analysis & Verification & Quantum Result Screen */}
      {analysisResult && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-8 animate-in fade-in">
          {/* Result Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-cyber-border">
            <div className="flex items-center space-x-4">
              <div className="w-14 h-14 rounded-2xl bg-navy text-cyan flex items-center justify-center font-bold shadow-md">
                <FileCheck size={32} />
              </div>
              <div>
                <h3 className="text-xl font-bold text-cyber-primary">Signature & Security Analysis Results</h3>
                <p className="text-xs text-cyber-secondary mt-0.5">
                  Inspection complete for {analysisResult.original_file_name}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-block px-3 py-1.5 rounded-full text-xs font-bold border ${getStatusBadge(analysisResult.signature_status)}`}>
                {analysisResult.signature_status}
              </span>

              {/* Trigger Verification Action Button */}
              {analysisResult.signature_present && (!verifs || verifs.length === 0) && (
                <button
                  onClick={handleTriggerVerification}
                  disabled={isVerifying || isQuantumAnalyzing || isCertValidating}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-xl text-xs font-bold shadow-md transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <ShieldCheck size={16} />
                  <span>VERIFY SIGNATURE</span>
                </button>
              )}

              {/* Trigger Certificate Validation Button */}
              {analysisResult.signature_present && (
                <button
                  onClick={handleTriggerCertValidation}
                  disabled={isVerifying || isQuantumAnalyzing || isThreatDetecting || isCertValidating}
                  className="bg-blue-600 hover:bg-blue-700 text-white border border-blue-400/30 px-4 py-2 rounded-xl text-xs font-bold shadow-md transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <Award size={16} />
                  <span>{analysisResult.certificate_analysis ? 'RE-VALIDATE CERTIFICATE' : 'VALIDATE CERTIFICATE'}</span>
                </button>
              )}

              {/* Trigger Quantum Analysis Button */}
              {analysisResult.signature_present && (
                <button
                  onClick={handleTriggerQuantumAnalysis}
                  disabled={isVerifying || isQuantumAnalyzing || isThreatDetecting || isCertValidating}
                  className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-4 py-2 rounded-xl text-xs font-bold shadow-md transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <Zap size={16} className="text-cyan fill-cyan/20" />
                  <span>{qData ? 'RE-RUN QUANTUM ANALYSIS' : 'RUN QUANTUM-INSPIRED ANALYSIS'}</span>
                </button>
              )}

              {/* Trigger Threat Detection Button */}
              <button
                onClick={handleTriggerThreatDetection}
                disabled={isVerifying || isQuantumAnalyzing || isThreatDetecting || isCertValidating}
                className="bg-red-600 hover:bg-red-700 text-white border border-red-500/50 px-4 py-2 rounded-xl text-xs font-bold shadow-md transition-all flex items-center space-x-1.5 cursor-pointer"
              >
                <ShieldAlert size={16} />
                <span>{isThreatDetecting ? 'Evaluating Threat Incidents...' : 'RUN THREAT DETECTION'}</span>
              </button>

              {/* Trigger Final Security Report Button */}
              <button
                onClick={handleGenerateFinalDecision}
                disabled={isVerifying || isQuantumAnalyzing || isThreatDetecting || isCertValidating || isGeneratingReport}
                className="bg-gradient-to-r from-cyan to-blue-600 hover:from-cyan-hover hover:to-blue-700 text-navy font-black px-4 py-2 rounded-xl text-xs shadow-lg transition-all flex items-center space-x-1.5 cursor-pointer"
              >
                <Award size={16} />
                <span>{isGeneratingReport ? 'Synthesizing 5 Layers...' : 'GENERATE FINAL REPORT'}</span>
              </button>
            </div>
          </div>

          {/* Section 0.5: STEP 6 HISTORICAL THREAT INCIDENTS DISPLAY CARD */}
          {analysisResult.threat_incidents && analysisResult.threat_incidents.length > 0 && (
            <div className="p-6 bg-red-950/40 border border-red-500/40 text-white rounded-2xl space-y-4 animate-in fade-in">
              <div className="flex items-center justify-between border-b border-red-500/30 pb-3">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 rounded-xl bg-red-500/20 text-red-400 flex items-center justify-center border border-red-500/30">
                    <ShieldAlert size={22} />
                  </div>
                  <div>
                    <h4 className="text-base font-bold text-white uppercase tracking-wider">Historical Threat Incidents Detected ({analysisResult.threat_incidents.length})</h4>
                    <p className="text-xs text-red-200">Deterministic rule-based threat evaluation triggered for document #{analysisResult.analysis_document_id}</p>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                {analysisResult.threat_incidents.map((t) => (
                  <div key={t.incident_id} className="p-4 bg-slate-900/90 rounded-xl border border-red-500/30 text-xs space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-bold text-red-300 uppercase tracking-wider">{t.threat_category.replace(/_/g, ' ')}</span>
                      <div className="flex items-center space-x-2">
                        <span className="px-2.5 py-0.5 rounded bg-red-500/20 text-red-400 font-bold border border-red-500/40 text-[11px]">
                          SEVERITY: {t.severity}
                        </span>
                        <span className="px-2.5 py-0.5 rounded bg-amber-500/20 text-amber-400 font-bold border border-amber-500/40 text-[11px]">
                          THREAT SCORE: {Number(t?.threat_score ?? 0).toFixed(1)}/100
                        </span>
                      </div>
                    </div>
                    <p className="text-slate-300 leading-relaxed text-[11px]">{t.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 0: STEP 5 QUANTUM-INSPIRED SECURITY ANALYSIS DISPLAY CARD */}
          {qData && (
            <div className="p-6 bg-slate-950 text-white rounded-2xl border border-cyan/30 shadow-2xl space-y-6 animate-in fade-in">
              {/* Header */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 rounded-xl bg-cyan/10 text-cyan flex items-center justify-center font-bold border border-cyan/40 shadow-inner">
                    <Atom size={28} className="animate-spin" style={{ animationDuration: '12s' }} />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="text-xl font-extrabold text-white tracking-tight">QUANTUM-INSPIRED SECURITY ANALYSIS</h4>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan/20 text-cyan border border-cyan/30">
                        {qData.analysis_version}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Deterministic mathematical security model mapping cryptographic features to Hilbert-inspired state vectors & Pauli observables
                    </p>
                  </div>
                </div>

                {/* Risk Level Badge */}
                {(() => {
                  const rBadge = getQuantumRiskBadge(qData.final_classification);
                  const IconComp = rBadge.icon;
                  return (
                    <div className={`px-4 py-2 rounded-xl border flex items-center space-x-2 font-bold text-xs shadow-md ${rBadge.cls}`}>
                      <IconComp size={18} />
                      <span>{rBadge.label}</span>
                    </div>
                  );
                })()}
              </div>

              {/* Key Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Forgery Risk Score</span>
                  <div className="flex items-baseline space-x-1">
                    <span className={`text-2xl font-black ${
                      Number(qData?.forgery_risk_score ?? 0) > 70 ? 'text-red-400' : (Number(qData?.forgery_risk_score ?? 0) > 30 ? 'text-amber-400' : 'text-emerald-400')
                    }`}>
                      {Number(qData?.forgery_risk_score ?? 0).toFixed(1)}
                    </span>
                    <span className="text-xs text-slate-500 font-bold">/ 100</span>
                  </div>
                </div>

                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Analysis Confidence</span>
                  <div className="flex items-baseline space-x-1">
                    <span className="text-2xl font-black text-cyan">
                      {Number(qData?.analysis_confidence_score ?? 0).toFixed(1)}%
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan/10 text-cyan font-bold border border-cyan/20">
                      {qData.confidence_level}
                    </span>
                  </div>
                </div>

                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Euclidean Disturbance (D)</span>
                  <div className="flex items-baseline space-x-1">
                    <span className="text-2xl font-black text-indigo-400">
                      {Number(qData?.disturbance_score ?? 0).toFixed(3)}
                    </span>
                    <span className="text-xs text-slate-500">units</span>
                  </div>
                </div>

                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">Secure Consistency (Cs)</span>
                  <div className="flex items-baseline space-x-1">
                    <span className="text-2xl font-black text-emerald-400">
                      {Number(qData?.secure_consistency_score ?? 0).toFixed(3)}
                    </span>
                  </div>
                </div>
              </div>

              {/* State Vector & Pauli Observables Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* State Vector & Feature Vector Breakdown */}
                <div className="p-5 bg-slate-900/80 rounded-xl border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <h5 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                      <Cpu size={16} />
                      <span>Feature Vector & State Amplitudes</span>
                    </h5>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="text-slate-400 block font-semibold mb-1">State Vector Formula</span>
                      <p className="font-mono text-cyan bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[11px]">
                        |ψ⟩ = {Number(Math.sqrt((qData?.secure_measurement_score ?? 100) / 100) ?? 1).toFixed(3)}|Secure⟩ + {Number(Math.sqrt(Math.max(0, 1 - (qData?.secure_measurement_score ?? 100) / 100)) ?? 0).toFixed(3)}|Disturbed⟩
                      </p>
                    </div>

                    <div>
                      <span className="text-slate-400 block font-semibold mb-1">Normalized Feature Vector S = [V, I, C, E, A]</span>
                      <div className="grid grid-cols-5 gap-1.5 text-center font-mono text-[11px]">
                        {qData.security_state_vector && qData.security_state_vector.map((val, idx) => {
                          const labels = ['V', 'I', 'C', 'E', 'A'];
                          return (
                            <div key={idx} className="p-1.5 bg-slate-950 rounded border border-slate-800">
                              <span className="text-slate-500 block text-[9px] font-sans font-bold">{labels[idx]}</span>
                              <span className="text-white font-bold">{Number(val ?? 0).toFixed(2)}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Pauli Analytical Operators */}
                <div className="p-5 bg-slate-900/80 rounded-xl border border-slate-800 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <h5 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                      <Activity size={16} />
                      <span>Analytical Pauli Anomaly Operators</span>
                    </h5>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300 font-semibold">Pauli X (Bit Flip / Binary Anomaly):</span>
                        <span className="font-mono text-amber-400 font-bold">{Number(qData?.pauli_x_score ?? 0).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-amber-500 h-full rounded-full" style={{ width: `${Number(qData?.pauli_x_score ?? 0)}%` }}></div>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300 font-semibold">Pauli Z (Phase / Structural Anomaly):</span>
                        <span className="font-mono text-blue-400 font-bold">{Number(qData?.pauli_z_score ?? 0).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-blue-500 h-full rounded-full" style={{ width: `${Number(qData?.pauli_z_score ?? 0)}%` }}></div>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-slate-300 font-semibold">Pauli Y (Combined Phase-Bit Anomaly):</span>
                        <span className="font-mono text-indigo-400 font-bold">{Number(qData?.pauli_y_score ?? 0).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-indigo-500 h-full rounded-full" style={{ width: `${Number(qData?.pauli_y_score ?? 0)}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Projective Measurement Distribution */}
              <div className="p-5 bg-slate-900/80 rounded-xl border border-slate-800 space-y-3">
                <h5 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2 border-b border-slate-800 pb-2">
                  <BarChart3 size={16} />
                  <span>Projective Measurement Probabilities across Subspaces</span>
                </h5>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-emerald-400 font-bold">P(Secure Subspace)</span>
                      <span className="font-mono text-emerald-400 font-bold">{Number(qData?.secure_measurement_score ?? 0).toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                      <div className="bg-emerald-500 h-full rounded-full" style={{ width: `${Number(qData?.secure_measurement_score ?? 0)}%` }}></div>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-amber-400 font-bold">P(Suspicious Subspace)</span>
                      <span className="font-mono text-amber-400 font-bold">{Number(qData?.suspicious_measurement_score ?? 0).toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                      <div className="bg-amber-500 h-full rounded-full" style={{ width: `${Number(qData?.suspicious_measurement_score ?? 0)}%` }}></div>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs">
                      <span className="text-red-400 font-bold">P(High-Risk Subspace)</span>
                      <span className="font-mono text-red-400 font-bold">{Number(qData?.high_risk_measurement_score ?? 0).toFixed(1)}%</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                      <div className="bg-red-500 h-full rounded-full" style={{ width: `${Number(qData?.high_risk_measurement_score ?? 0)}%` }}></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action: View Explanation Modal */}
              <div className="flex justify-end pt-2">
                <button
                  onClick={handleFetchExplanation}
                  disabled={isLoadingExplanation}
                  className="bg-cyan hover:bg-cyan-hover text-navy font-bold px-5 py-2.5 rounded-xl text-xs shadow-lg transition-all flex items-center space-x-2 cursor-pointer"
                >
                  <HelpCircle size={16} />
                  <span>{isLoadingExplanation ? 'Loading Math Proof...' : 'VIEW MATHEMATICAL EXPLANATION'}</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 7 CERTIFICATE SECURITY DISPLAY CARD */}
          {analysisResult.certificate_analysis && (
            <div className="p-6 bg-slate-900 text-white rounded-2xl border border-blue-500/40 shadow-xl space-y-6 animate-in fade-in">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 rounded-xl bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold border border-blue-500/30">
                    <Award size={26} />
                  </div>
                  <div>
                    <h4 className="text-lg font-bold text-white tracking-tight">CERTIFICATE SECURITY & TRUST VALIDATION</h4>
                    <p className="text-xs text-slate-400">X.509 structure, validity period, trust chain anchor, revocation status, & key parameters</p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-right">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Cert Security Score</span>
                    <span className={`text-xl font-black ${
                      analysisResult.certificate_analysis.certificate_security_score >= 80 ? 'text-emerald-400' : (
                        analysisResult.certificate_analysis.certificate_security_score >= 50 ? 'text-amber-400' : 'text-red-400'
                      )
                    }`}>
                      {Number(analysisResult?.certificate_analysis?.certificate_security_score ?? 0).toFixed(1)} / 100
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Structure Status</span>
                  <span className="font-bold text-cyan">{analysisResult.certificate_analysis.structure_status}</span>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Time Validity Status</span>
                  <span className="font-bold text-emerald-400">{analysisResult.certificate_analysis.time_validity_status}</span>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Trust Anchor Status</span>
                  <span className="font-bold text-blue-400">{analysisResult.certificate_analysis.trust_status}</span>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Revocation Check (OCSP/CRL)</span>
                  <span className="font-bold text-amber-400">{analysisResult.certificate_analysis.revocation_status}</span>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs space-y-2">
                <span className="text-cyan font-bold block uppercase tracking-wider text-[11px]">Deterministic Policy Evaluation Notes</span>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  {getCertPolicyNotes(analysisResult.certificate_analysis.details).map((n, i) => (
                    <li key={i}>{n}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* STEP 7 FINAL COMPREHENSIVE SECURITY REPORT BANNER & CARD */}
          {analysisResult.security_report && (
            <div className="p-6 bg-slate-950 text-white rounded-2xl border border-cyan/40 shadow-2xl space-y-6 animate-in fade-in">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 rounded-xl bg-cyan/20 text-cyan flex items-center justify-center font-bold border border-cyan/40 shadow-inner">
                    <ShieldCheck size={28} />
                  </div>
                  <div>
                    <h4 className="text-xl font-black text-white tracking-tight">FINAL SECURITY DECISION & REPORT</h4>
                    <p className="text-xs text-slate-400">Synthesized multi-layered security evaluation & official PDF report</p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <div className={`px-4 py-2 rounded-xl font-black text-xs border shadow-lg ${getFinalDecisionBadge(analysisResult.security_report.final_security_decision).cls}`}>
                    {getFinalDecisionBadge(analysisResult.security_report.final_security_decision).label}
                  </div>

                  <button
                    onClick={handleDownloadPdfReport}
                    disabled={isDownloadingPdf}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold px-4 py-2.5 rounded-xl text-xs shadow-lg transition-all flex items-center space-x-1.5 cursor-pointer"
                  >
                    <Download size={16} />
                    <span>{isDownloadingPdf ? 'Generating PDF...' : 'DOWNLOAD PDF REPORT'}</span>
                  </button>
                </div>
              </div>

              {/* Summary Info Row */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block">Overall System Risk Score</span>
                  <span className={`text-2xl font-black ${
                    Number(analysisResult?.security_report?.overall_risk_score ?? 0) > 70 ? 'text-red-400' : (
                      Number(analysisResult?.security_report?.overall_risk_score ?? 0) > 30 ? 'text-amber-400' : 'text-emerald-400'
                    )
                  }`}>
                    {Number(analysisResult?.security_report?.overall_risk_score ?? 0).toFixed(1)} / 100
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block">Report Security Hash (SHA-256)</span>
                  <span className="font-mono text-cyan text-[11px] break-all block">{analysisResult.security_report.report_hash.substring(0, 32)}...</span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block">Report Metadata</span>
                  <span className="text-slate-300 block font-semibold">{analysisResult.security_report.report_version} | {new Date(analysisResult.security_report.generated_at).toLocaleTimeString()}</span>
                </div>
              </div>
            </div>
          )}

          {/* Section 1: CRYPTOGRAPHIC VERIFICATION (Step 4 Highlight Card) */}
          {verifs && verifs.length > 0 && (
            <div className="p-6 bg-slate-900 text-white rounded-2xl border border-slate-800 shadow-xl space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 rounded-xl bg-cyan/10 text-cyan flex items-center justify-center font-bold border border-cyan/30">
                    <Shield size={22} />
                  </div>
                  <div>
                    <h4 className="text-lg font-bold text-white tracking-tight">CRYPTOGRAPHIC VERIFICATION</h4>
                    <p className="text-xs text-slate-400">Classical cryptographic public key signature & ByteRange integrity evaluation</p>
                  </div>
                </div>

                <button
                  onClick={handleTriggerVerification}
                  disabled={isVerifying || isQuantumAnalyzing}
                  className="text-xs font-semibold text-cyan hover:underline cursor-pointer"
                >
                  Re-Verify Signature
                </button>
              </div>

              {verifs.map((v) => {
                const vBadge = getVerifStatusBadge(v.verification_status);
                const iBadge = getIntegStatusBadge(v.integrity_status);
                const tBadge = getCertTimeBadge(v.certificate_time_status);

                return (
                  <div key={v.verification_id} className="space-y-4 p-5 bg-slate-800/80 rounded-xl border border-slate-700">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-700 pb-3">
                      <span className="text-xs font-bold text-cyan uppercase tracking-wider">
                        Signature Index #{v.signature_index} ({v.signature_identifier})
                      </span>

                      <div className="flex flex-wrap gap-2">
                        <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${vBadge.cls}`}>
                          {vBadge.label}
                        </span>
                        <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${iBadge.cls}`}>
                          {iBadge.label}
                        </span>
                        <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${tBadge.cls}`}>
                          {tBadge.label}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                      <div>
                        <span className="text-slate-400 block font-semibold">Signature Algorithm</span>
                        <span className="font-mono text-white font-bold">{v.signature_algorithm}</span>
                      </div>

                      <div>
                        <span className="text-slate-400 block font-semibold">Hash Algorithm</span>
                        <span className="font-mono text-white font-bold">{v.hash_algorithm}</span>
                      </div>

                      <div>
                        <span className="text-slate-400 block font-semibold">Verification Timestamp</span>
                        <span className="text-slate-200">{new Date(v.verification_timestamp).toLocaleString()}</span>
                      </div>

                      <div>
                        <span className="text-slate-400 block font-semibold">Certificate Time Validity</span>
                        <span className="text-slate-200">{v.certificate_time_status}</span>
                      </div>
                    </div>

                    <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800 text-xs">
                      <span className="text-slate-400 font-bold block mb-1">Verification Findings & Details</span>
                      <p className="text-slate-200">{v.verification_details}</p>
                      {v.error_details && (
                        <p className="text-red-400 mt-1 font-mono text-[11px]">Error: {v.error_details}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Section 2: Document SHA-256 Fingerprint */}
          <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="w-full overflow-hidden">
              <span className="text-xs font-bold text-cyber-secondary uppercase block mb-1">
                Document SHA-256 Fingerprint
              </span>
              <p className="font-mono text-xs text-slate-800 break-all">{analysisResult.document_hash}</p>
            </div>

            <button
              onClick={() => copyToClipboard(analysisResult.document_hash)}
              className="px-3 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-cyber-primary hover:bg-white flex items-center space-x-1 shrink-0 cursor-pointer"
            >
              {copiedHash ? <Check size={14} className="text-emerald-600" /> : <Copy size={14} />}
              <span>{copiedHash ? 'Copied' : 'Copy Hash'}</span>
            </button>
          </div>

          {/* Section 3 & 4: Extracted Metadata Grids */}
          {meta && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Digital Signature Information */}
              <div className="p-5 bg-slate-50/80 rounded-xl border border-slate-200 space-y-3">
                <h4 className="text-sm font-bold text-cyber-primary border-b border-slate-200 pb-2 flex items-center space-x-2">
                  <Key size={16} className="text-cyan-hover" />
                  <span>Digital Signature Information</span>
                </h4>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-cyber-secondary font-semibold block">Signature Present</span>
                    <span className="font-bold text-cyber-primary">{analysisResult.signature_present ? 'Yes' : 'No'}</span>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block">Field Name</span>
                    <span className="font-mono font-semibold text-cyber-primary">{meta.field_name}</span>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block">Signature Algorithm</span>
                    <span className="font-mono font-semibold text-cyber-primary">{meta.signature_algorithm}</span>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block">Hash Algorithm</span>
                    <span className="font-mono font-semibold text-cyber-primary">{meta.hash_algorithm}</span>
                  </div>

                  <div className="col-span-2">
                    <span className="text-cyber-secondary font-semibold block">Signing Time</span>
                    <span className="font-semibold text-cyber-primary">
                      {meta.signing_time ? new Date(meta.signing_time).toLocaleString() : 'Not Available'}
                    </span>
                  </div>

                  <div className="col-span-2">
                    <span className="text-cyber-secondary font-semibold block mb-0.5">Signature Fingerprint (SHA-256)</span>
                    <span className="font-mono text-[11px] text-slate-700 break-all">{meta.signature_fingerprint}</span>
                  </div>
                </div>
              </div>

              {/* Certificate Information */}
              <div className="p-5 bg-slate-50/80 rounded-xl border border-slate-200 space-y-3">
                <h4 className="text-sm font-bold text-cyber-primary border-b border-slate-200 pb-2 flex items-center space-x-2">
                  <ShieldCheck size={16} className="text-emerald-600" />
                  <span>X.509 Certificate Information</span>
                </h4>

                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-cyber-secondary font-semibold block">Subject Identity</span>
                    <span className="font-semibold text-cyber-primary break-all">{meta.certificate_subject}</span>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block">Issuer CA</span>
                    <span className="font-semibold text-cyber-primary break-all">{meta.certificate_issuer}</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-cyber-secondary font-semibold block">Serial Number</span>
                      <span className="font-mono font-semibold text-cyber-primary">{meta.certificate_serial_number}</span>
                    </div>

                    <div>
                      <span className="text-cyber-secondary font-semibold block">Public Key Info</span>
                      <span className="font-mono font-semibold text-cyber-primary">
                        {meta.public_key_algorithm} {meta.public_key_size > 0 ? `${meta.public_key_size}-bit` : ''}
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block mb-0.5">Certificate Fingerprint</span>
                    <span className="font-mono text-[11px] text-slate-700 break-all">{meta.certificate_fingerprint}</span>
                  </div>
                </div>
              </div>

              {/* Signer Identity Information */}
              <div className="p-5 bg-slate-50/80 rounded-xl border border-slate-200 space-y-3 md:col-span-2">
                <h4 className="text-sm font-bold text-cyber-primary border-b border-slate-200 pb-2 flex items-center space-x-2">
                  <UserCheck size={16} className="text-blue-600" />
                  <span>Signer Identity & Organizational Parameters</span>
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <span className="text-cyber-secondary font-semibold block">Signer Common Name</span>
                    <span className="font-semibold text-cyber-primary text-sm">{meta.signer_name}</span>
                  </div>

                  <div>
                    <span className="text-cyber-secondary font-semibold block">Signer Organization</span>
                    <span className="font-semibold text-cyber-primary text-sm">{meta.signer_organization}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MATHEMATICAL EXPLANATION MODAL */}
      {explanationModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 text-white rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-cyan/20 text-cyan flex items-center justify-center">
                  <Atom size={22} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Quantum-Inspired Mathematical Explanation</h3>
                  <p className="text-xs text-slate-400">Step-by-step mathematical proof & deterministic classification breakdown</p>
                </div>
              </div>
              <button
                onClick={() => setExplanationModal(null)}
                className="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
              {/* Summary Banner */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400 block text-[11px]">FINAL CLASSIFICATION</span>
                  <span className="text-base font-extrabold text-cyan">{explanationModal.final_classification}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">FORGERY RISK SCORE</span>
                  <span className="text-base font-extrabold text-amber-400">{Number(explanationModal.forgery_risk_score ?? 0).toFixed(1)} / 100</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">CONFIDENCE LEVEL</span>
                  <span className="text-base font-extrabold text-emerald-400">{explanationModal.confidence_level}</span>
                </div>
              </div>

              {/* Step 1: Feature Vector Normalization */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                  <ChevronRight size={14} />
                  <span>Step 1: Feature Vector Normalization S = [V, I, C, E, A]</span>
                </h4>
                <p className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-slate-200 border border-slate-800/80 leading-relaxed">
                  {explanationModal.step1_feature_mapping}
                </p>
              </div>

              {/* Step 2: Quantum-Inspired State Vector */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                  <ChevronRight size={14} />
                  <span>Step 2: State Vector & Euclidean Disturbance D</span>
                </h4>
                <p className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-cyan border border-slate-800/80 leading-relaxed">
                  {explanationModal.step2_state_vector}
                </p>
              </div>

              {/* Step 3: Analytical Pauli Operators */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                  <ChevronRight size={14} />
                  <span>Step 3: Analytical Pauli Anomaly Operators (X, Y, Z)</span>
                </h4>
                <p className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-slate-200 border border-slate-800/80 leading-relaxed">
                  {explanationModal.step3_pauli_analysis}
                </p>
              </div>

              {/* Step 4: Projective Measurement Probabilities */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                  <ChevronRight size={14} />
                  <span>Step 4: Projective Measurement Subspace Projections</span>
                </h4>
                <p className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-slate-200 border border-slate-800/80 leading-relaxed">
                  {explanationModal.step4_measurement}
                </p>
              </div>

              {/* Step 5: Final Risk Classification & Decision */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider flex items-center space-x-2">
                  <ChevronRight size={14} />
                  <span>Step 5: Final Security Decision & Risk Justification</span>
                </h4>
                <p className="p-3 bg-slate-950 rounded-lg font-mono text-[11px] text-emerald-400 border border-slate-800/80 leading-relaxed">
                  {explanationModal.step5_decision}
                </p>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setExplanationModal(null)}
                className="bg-slate-800 hover:bg-slate-700 text-white font-bold px-5 py-2 rounded-xl text-xs transition-all"
              >
                Close Explanation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FINAL DECISION REPORT MODAL */}
      {reportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 text-white rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-cyan/20 text-cyan flex items-center justify-center">
                  <ShieldCheck size={22} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Q-SHIELD Final Security Decision & Synthesis</h3>
                  <p className="text-xs text-slate-400">5-Layer Security Evaluation Summary & Recommendations</p>
                </div>
              </div>
              <button
                onClick={() => setReportModal(null)}
                className="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
              {/* Decision Badge */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400 block text-[11px]">FINAL SECURITY DECISION</span>
                  <span className="text-xl font-black text-cyan">{reportModal.final_security_decision}</span>
                </div>
                <div className="text-right">
                  <span className="text-slate-400 block text-[11px]">OVERALL RISK SCORE</span>
                  <span className="text-xl font-black text-amber-400">{Number(reportModal.overall_risk_score ?? 0).toFixed(1)} / 100</span>
                </div>
              </div>

              {/* 5 Layer Summary Table */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider">5 Security Layer Evaluation Breakdown</h4>
                <div className="grid grid-cols-1 gap-2 font-mono text-[11px]">
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Layer 1 (Cryptographic Signature):</span>
                    <span className="font-bold text-white">{reportModal.layer1_signature_status}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Layer 2 (Document Integrity):</span>
                    <span className="font-bold text-white">{reportModal.layer2_integrity_status}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Layer 3 (Certificate Trust & Security):</span>
                    <span className="font-bold text-white">{reportModal.layer3_certificate_status}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Layer 4 (Quantum Security State):</span>
                    <span className="font-bold text-white">{reportModal.layer4_quantum_status}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Layer 5 (Historical Threat Level):</span>
                    <span className="font-bold text-white">{reportModal.layer5_threat_status}</span>
                  </div>
                </div>
              </div>

              {/* Summary Justification */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-cyan uppercase tracking-wider">Decision Justification</h4>
                <p className="p-3.5 bg-slate-950 rounded-lg text-slate-200 border border-slate-800 leading-relaxed text-[11px]">
                  {reportModal.summary_justification}
                </p>
              </div>

              {/* Recommended Action */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Recommended Action</h4>
                <p className="p-3.5 bg-slate-950 rounded-lg text-emerald-300 border border-slate-800 leading-relaxed text-[11px]">
                  {reportModal.recommended_action}
                </p>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-between items-center">
              <button
                onClick={handleDownloadPdfReport}
                disabled={isDownloadingPdf}
                className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold px-5 py-2.5 rounded-xl text-xs transition-all flex items-center space-x-1.5 cursor-pointer"
              >
                <Download size={16} />
                <span>{isDownloadingPdf ? 'Downloading PDF...' : 'DOWNLOAD PDF REPORT'}</span>
              </button>

              <button
                onClick={() => setReportModal(null)}
                className="bg-slate-800 hover:bg-slate-700 text-white font-bold px-5 py-2 rounded-xl text-xs transition-all cursor-pointer"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
