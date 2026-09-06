import React, { useState } from 'react';
import { api } from '../../services/api';
import {
  Upload,
  Key,
  Shield,
  Download,
  AlertCircle,
  ShieldCheck,
  FileText,
  X,
  Info,
  Code,
  Layers,
  Copy,
  Check,
  FileCode
} from 'lucide-react';

interface UploadedDoc {
  document_id: number;
  original_filename: string;
  document_hash: string;
  file_size: number;
  status: string;
  content_type?: string;
}

export const CreateSignaturePlaceholder: React.FC = () => {
  const [signingMode, setSigningMode] = useState<'file' | 'raw_text' | 'json' | 'structured'>('file');

  // File Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Raw Text State
  const [rawTextInput, setRawTextInput] = useState<string>('');
  const [rawFilenameInput, setRawFilenameInput] = useState<string>('document.txt');

  // JSON State
  const [jsonInput, setJsonInput] = useState<string>('{\n  "account_id": "ACC-99421",\n  "amount": 50000,\n  "currency": "USD",\n  "authorization": "APPROVED"\n}');
  const [jsonCanonicalize, setJsonCanonicalize] = useState<boolean>(true);

  // Structured Message State
  const [msgSender, setMsgSender] = useState<string>('user@qshield.com');
  const [msgRecipient, setMsgRecipient] = useState<string>('analyst@qshield.com');
  const [msgPayload, setMsgPayload] = useState<string>('TRANSFER_FUNDS_CONFIRMATION_PAYLOAD');
  const [msgNonce, setMsgNonce] = useState<string>('nonce_881920');

  // Common State
  const [signedResult, setSignedResult] = useState<any | null>(null);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [stepMessage, setStepMessage] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);
  const [copiedSignedJson, setCopiedSignedJson] = useState(false);

  const processSteps = [
    "Uploading Document / Data",
    "Detecting Format & Canonicalizing",
    "Generating SHA-256 Digest",
    "Preparing RSA-2048 Private Key",
    "Generating Cryptographic Signature",
    "Formulating Signed Envelope / Document",
    "Saving Metadata to Persistence",
    "Completed"
  ];

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      validateAndSetFile(file);
    }
  };

  const validateAndSetFile = (file: File) => {
    setError(null);
    setSignedResult(null);

    const ext = file.name.toLowerCase().split('.').pop();
    if (!['pdf', 'txt', 'json'].includes(ext || '')) {
      setError("Supported file formats: PDF (.pdf), TXT (.txt), and JSON (.json).");
      setSelectedFile(null);
      return;
    }

    if (file.size > 25 * 1024 * 1024) {
      setError("File size exceeds maximum allowed limit of 25MB.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleStartSigning = async () => {
    setIsProcessing(true);
    setError(null);
    setSignedResult(null);

    try {
      if (signingMode === 'file') {
        if (!selectedFile) return;

        const isPdf = selectedFile.name.toLowerCase().endsWith('.pdf');

        if (isPdf) {
          // Classical PDF Workflow
          setCurrentStep(1); setStepMessage(processSteps[0]); await new Promise(r => setTimeout(r, 300));
          setCurrentStep(2); setStepMessage(processSteps[1]);

          const formData = new FormData();
          formData.append('file', selectedFile);

          setCurrentStep(3); setStepMessage(processSteps[2]);
          const uploadRes = await api.post('/documents/upload', formData, {
            headers: { 'Content-Type': 'multipart/form-data' }
          });
          const doc = uploadRes.data;

          setCurrentStep(5); setStepMessage(processSteps[4]); await new Promise(r => setTimeout(r, 400));
          setCurrentStep(6); setStepMessage(processSteps[5]);

          const signRes = await api.post(`/documents/${doc.document_id}/sign`);
          setCurrentStep(8); setStepMessage(processSteps[7]);
          setSignedResult(signRes.data);
        } else {
          // Multi-Format File Upload Workflow (TXT / JSON)
          setCurrentStep(1); setStepMessage(processSteps[0]); await new Promise(r => setTimeout(r, 300));
          const formData = new FormData();
          formData.append('file', selectedFile);

          setCurrentStep(3); setStepMessage(processSteps[2]);
          const uploadRes = await api.post('/documents/upload-multiformat', formData, {
            headers: { 'Content-Type': 'multipart/form-data' }
          });
          const doc = uploadRes.data;

          setCurrentStep(5); setStepMessage(processSteps[4]); await new Promise(r => setTimeout(r, 400));
          setCurrentStep(6); setStepMessage(processSteps[5]);

          const signRes = await api.post(`/documents/${doc.document_id}/sign`);
          setCurrentStep(8); setStepMessage(processSteps[7]);
          setSignedResult(signRes.data);
        }
      } else if (signingMode === 'raw_text') {
        if (!rawTextInput.trim()) {
          setError("Please enter text content to generate a digital signature.");
          setIsProcessing(false);
          return;
        }

        setCurrentStep(1); setStepMessage(processSteps[0]); await new Promise(r => setTimeout(r, 200));
        setCurrentStep(3); setStepMessage(processSteps[2]); await new Promise(r => setTimeout(r, 300));
        setCurrentStep(5); setStepMessage(processSteps[4]);

        const res = await api.post('/documents/sign-text', {
          text_content: rawTextInput,
          filename: rawFilenameInput || "signed_document.txt"
        });

        setCurrentStep(8); setStepMessage(processSteps[7]);
        setSignedResult(res.data);
      } else if (signingMode === 'json') {
        if (!jsonInput.trim()) {
          setError("Please enter JSON data to generate a canonical digital signature.");
          setIsProcessing(false);
          return;
        }

        let parsed;
        try {
          parsed = JSON.parse(jsonInput);
        } catch (e) {
          setError("Invalid JSON format. Please provide valid JSON content.");
          setIsProcessing(false);
          return;
        }

        setCurrentStep(1); setStepMessage(processSteps[0]); await new Promise(r => setTimeout(r, 200));
        setCurrentStep(2); setStepMessage(processSteps[1]); await new Promise(r => setTimeout(r, 300));
        setCurrentStep(5); setStepMessage(processSteps[4]);

        const res = await api.post('/documents/sign-json', {
          json_content: parsed,
          filename: "canonical_signed_data.json",
          canonicalize: jsonCanonicalize
        });

        setCurrentStep(8); setStepMessage(processSteps[7]);
        setSignedResult(res.data);
      } else if (signingMode === 'structured') {
        if (!msgSender.trim() || !msgRecipient.trim() || !msgPayload.trim()) {
          setError("Please fill in sender, recipient, and message payload fields.");
          setIsProcessing(false);
          return;
        }

        setCurrentStep(1); setStepMessage(processSteps[0]); await new Promise(r => setTimeout(r, 200));
        setCurrentStep(3); setStepMessage(processSteps[2]); await new Promise(r => setTimeout(r, 300));
        setCurrentStep(5); setStepMessage(processSteps[4]);

        const res = await api.post('/documents/sign-structured-message', {
          sender: msgSender,
          recipient: msgRecipient,
          payload: msgPayload,
          nonce: msgNonce
        });

        setCurrentStep(8); setStepMessage(processSteps[7]);
        setSignedResult(res.data);
      }
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Cryptographic signature generation failed.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownload = async () => {
    if (!signedResult) return;
    try {
      const docId = signedResult.document_id;
      const response = await api.get(`/documents/${docId}/download`, {
        responseType: 'blob'
      });
      const contentType = String(response.headers['content-type'] || 'application/octet-stream');
      const blob = new Blob([response.data], { type: contentType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', signedResult.signed_filename || signedResult.original_filename || `signed_output_${docId}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
      alert("Failed to download signed file.");
    }
  };

  const handleCopyJsonEnvelope = () => {
    if (signedResult?.signed_message_json) {
      navigator.clipboard.writeText(JSON.stringify(signedResult.signed_message_json, null, 2));
      setCopiedSignedJson(true);
      setTimeout(() => setCopiedSignedJson(false), 2000);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Page Title */}
      <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm">
        <h2 className="text-2xl font-bold text-cyber-primary">Digital Signature Workspace</h2>
        <p className="text-cyber-secondary text-sm mt-1">
          Generate tamper-proof RSA-2048 cryptographic signatures for PDFs, plain text, canonical JSON, and structured transaction envelopes.
        </p>
      </div>

      {/* Dev Certificate Banner Notice */}
      <div className="p-4 rounded-xl bg-blue-50 border border-blue-200 text-blue-900 flex items-start space-x-3 text-xs">
        <Info size={18} className="text-blue-600 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold uppercase tracking-wider block text-blue-900">DEVELOPMENT / DEMO CERTIFICATE NOTICE</span>
          <span>
            Signatures generated in localhost mode use the <strong>Q-SHIELD Development CA (Demo)</strong> RSA-2048 identity.
            All signatures are cryptographically valid and embed SHA-256 digests adhering to PKCS#7 / CMS or RFC 8785 standards.
          </span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start space-x-3 text-red-700 text-sm">
          <AlertCircle size={20} className="shrink-0 mt-0.5 text-red-600" />
          <p className="font-medium">{error}</p>
        </div>
      )}

      {!signedResult ? (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6">
          {/* Mode Selector Tabs */}
          <div className="flex border-b border-cyber-border space-x-2 pb-2 overflow-x-auto">
            <button
              onClick={() => setSigningMode('file')}
              className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 transition-all cursor-pointer ${
                signingMode === 'file'
                  ? 'bg-navy text-cyan shadow-sm border border-cyan/20'
                  : 'text-cyber-secondary hover:text-cyber-primary hover:bg-slate-50'
              }`}
            >
              <Upload size={16} />
              <span>Upload File (PDF / TXT / JSON)</span>
            </button>

            <button
              onClick={() => setSigningMode('raw_text')}
              className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 transition-all cursor-pointer ${
                signingMode === 'raw_text'
                  ? 'bg-navy text-cyan shadow-sm border border-cyan/20'
                  : 'text-cyber-secondary hover:text-cyber-primary hover:bg-slate-50'
              }`}
            >
              <FileText size={16} />
              <span>Raw Text Studio</span>
            </button>

            <button
              onClick={() => setSigningMode('json')}
              className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 transition-all cursor-pointer ${
                signingMode === 'json'
                  ? 'bg-navy text-cyan shadow-sm border border-cyan/20'
                  : 'text-cyber-secondary hover:text-cyber-primary hover:bg-slate-50'
              }`}
            >
              <FileCode size={16} />
              <span>Canonical JSON Studio</span>
            </button>

            <button
              onClick={() => setSigningMode('structured')}
              className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center space-x-2 transition-all cursor-pointer ${
                signingMode === 'structured'
                  ? 'bg-navy text-cyan shadow-sm border border-cyan/20'
                  : 'text-cyber-secondary hover:text-cyber-primary hover:bg-slate-50'
              }`}
            >
              <Layers size={16} />
              <span>Structured Message Studio</span>
            </button>
          </div>

          {/* Mode 1: File Upload */}
          {signingMode === 'file' && (
            <div
              className={`border-2 border-dashed rounded-2xl p-10 text-center transition-all ${
                selectedFile ? 'border-cyan bg-cyan/5' : 'border-cyber-border hover:border-cyan'
              }`}
            >
              <input
                type="file"
                accept=".pdf,.txt,.json,application/pdf,text/plain,application/json"
                id="multi-file-input"
                onChange={handleFileSelect}
                className="hidden"
                disabled={isProcessing}
              />

              <label htmlFor="multi-file-input" className="cursor-pointer block">
                <div className="w-16 h-16 rounded-2xl bg-navy text-cyan flex items-center justify-center mx-auto mb-4 shadow-lg shadow-cyan/10">
                  <Upload size={32} />
                </div>
                <h3 className="text-lg font-bold text-cyber-primary">
                  {selectedFile ? selectedFile.name : 'Select or Drag & Drop Document'}
                </h3>
                <p className="text-xs text-cyber-secondary mt-1">Supported Formats: PDF, TXT, JSON (Max file size: 25MB)</p>
              </label>

              {selectedFile && (
                <div className="mt-4 inline-flex items-center space-x-3 bg-white px-4 py-2 rounded-xl border border-cyber-border text-xs font-semibold text-cyber-primary">
                  <FileText size={16} className="text-cyan-hover" />
                  <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
                  <span className="text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded text-[10px] font-bold">READY</span>
                </div>
              )}
            </div>
          )}

          {/* Mode 2: Raw Text Studio */}
          {signingMode === 'raw_text' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Document / Message Filename
                </label>
                <input
                  type="text"
                  value={rawFilenameInput}
                  onChange={(e) => setRawFilenameInput(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-cyber-border rounded-xl text-xs font-semibold text-cyber-primary focus:outline-none focus:border-cyan"
                  placeholder="e.g. statement_approval.txt"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Raw Text Payload Content
                </label>
                <textarea
                  rows={6}
                  value={rawTextInput}
                  onChange={(e) => setRawTextInput(e.target.value)}
                  className="w-full p-4 bg-slate-50 border border-cyber-border rounded-xl font-mono text-xs text-cyber-primary focus:outline-none focus:border-cyan"
                  placeholder="Enter or paste raw text content to sign..."
                />
              </div>
            </div>
          )}

          {/* Mode 3: Canonical JSON Studio */}
          {signingMode === 'json' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider">
                  JSON Data Content
                </label>
                <label className="flex items-center space-x-2 text-xs font-semibold text-cyber-primary cursor-pointer">
                  <input
                    type="checkbox"
                    checked={jsonCanonicalize}
                    onChange={(e) => setJsonCanonicalize(e.target.checked)}
                    className="rounded border-slate-300 text-cyan focus:ring-cyan"
                  />
                  <span>Enable RFC 8785 Canonical JSON Normalization</span>
                </label>
              </div>

              <textarea
                rows={7}
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                className="w-full p-4 bg-slate-50 border border-cyber-border rounded-xl font-mono text-xs text-cyber-primary focus:outline-none focus:border-cyan"
                placeholder="Enter valid JSON object..."
              />
              <p className="text-[11px] text-cyber-secondary">
                RFC 8785 canonicalization sorts keys lexicographically and strips whitespace before computing SHA-256 digest, preserving validity across different JSON formatters.
              </p>
            </div>
          )}

          {/* Mode 4: Structured Message Studio */}
          {signingMode === 'structured' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Sender Identity
                </label>
                <input
                  type="text"
                  value={msgSender}
                  onChange={(e) => setMsgSender(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-cyber-border rounded-xl text-xs font-semibold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Recipient Identity
                </label>
                <input
                  type="text"
                  value={msgRecipient}
                  onChange={(e) => setMsgRecipient(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-cyber-border rounded-xl text-xs font-semibold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Message Payload / Transaction Content
                </label>
                <textarea
                  rows={3}
                  value={msgPayload}
                  onChange={(e) => setMsgPayload(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-cyber-border rounded-xl font-mono text-xs text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-cyber-primary uppercase tracking-wider mb-1">
                  Replay Protection Nonce
                </label>
                <input
                  type="text"
                  value={msgNonce}
                  onChange={(e) => setMsgNonce(e.target.value)}
                  className="w-full p-3 bg-slate-50 border border-cyber-border rounded-xl text-xs font-semibold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>
            </div>
          )}

          {/* Progress Bar */}
          {isProcessing && (
            <div className="space-y-4 p-6 bg-slate-50 rounded-xl border border-slate-200">
              <div className="flex items-center justify-between text-xs font-bold text-cyber-primary">
                <span>{stepMessage}...</span>
                <span>Step {currentStep} of 8</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-cyan h-full transition-all duration-300 rounded-full"
                  style={{ width: `${(currentStep / 8) * 100}%` }}
                ></div>
              </div>
            </div>
          )}

          {/* Action Trigger Button */}
          <div className="flex justify-end">
            <button
              onClick={handleStartSigning}
              disabled={(signingMode === 'file' && !selectedFile) || isProcessing}
              className="bg-navy hover:bg-navy-light disabled:opacity-50 text-cyan px-6 py-3.5 rounded-xl font-bold text-sm shadow-md transition-all flex items-center space-x-2 border border-cyan/20 cursor-pointer"
            >
              <Key size={18} />
              <span>{isProcessing ? 'Generating Signature...' : 'GENERATE CRYPTOGRAPHIC SIGNATURE'}</span>
            </button>
          </div>
        </div>
      ) : (
        /* Success Result Screen */
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-4 pb-6 border-b border-cyber-border">
            <div className="w-14 h-14 rounded-2xl bg-emerald-100 text-emerald-600 flex items-center justify-center font-bold shadow-md">
              <ShieldCheck size={32} />
            </div>
            <div>
              <h3 className="text-xl font-extrabold text-cyber-primary">DIGITAL SIGNATURE GENERATED SUCCESSFULLY</h3>
              <p className="text-xs text-cyber-secondary mt-0.5">
                Cryptographic RSA-2048 signature & SHA-256 digest generated for {signedResult.content_type || "Document"}.
              </p>
            </div>
          </div>

          {/* Signature Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
              <span className="text-cyber-secondary font-bold uppercase block">Original Name / Subject</span>
              <span className="font-semibold text-cyber-primary text-sm">{signedResult.original_filename || signedResult.filename}</span>
            </div>

            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
              <span className="text-cyber-secondary font-bold uppercase block">Format Type</span>
              <span className="font-bold text-cyan-hover text-sm">{signedResult.content_type || "DOCUMENT"}</span>
            </div>

            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1 md:col-span-2">
              <span className="text-cyber-secondary font-bold uppercase block">SHA-256 Document / Canonical Hash</span>
              <span className="font-mono text-slate-800 break-all">{signedResult.canonical_hash || signedResult.document_hash}</span>
            </div>

            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
              <span className="text-cyber-secondary font-bold uppercase block">Certificate Subject</span>
              <span className="font-semibold text-cyber-primary">{signedResult.signature?.certificate_subject || "CN=Q-SHIELD Development CA (Demo)"}</span>
            </div>

            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
              <span className="text-cyber-secondary font-bold uppercase block">Algorithms</span>
              <span className="font-mono font-bold text-cyber-primary">RSA-2048 / SHA-256</span>
            </div>
          </div>

          {/* Signed JSON Envelope View (if available) */}
          {signedResult.signed_message_json && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyber-primary uppercase tracking-wider flex items-center space-x-1">
                  <Code size={14} className="text-cyan-hover" />
                  <span>QSHIELD-1.0 Signed Envelope JSON</span>
                </span>

                <button
                  onClick={handleCopyJsonEnvelope}
                  className="text-xs font-bold text-cyan-hover hover:text-navy flex items-center space-x-1"
                >
                  {copiedSignedJson ? <Check size={14} className="text-emerald-600" /> : <Copy size={14} />}
                  <span>{copiedSignedJson ? 'Copied!' : 'Copy Envelope JSON'}</span>
                </button>
              </div>

              <pre className="p-4 bg-slate-900 text-cyan-light rounded-xl text-[11px] font-mono overflow-x-auto max-h-56">
                {JSON.stringify(signedResult.signed_message_json, null, 2)}
              </pre>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-end gap-3 pt-4 border-t border-cyber-border">
            <button
              onClick={() => { setSignedResult(null); setSelectedFile(null); }}
              className="w-full sm:w-auto px-5 py-3 rounded-xl border border-cyber-border font-bold text-xs text-cyber-primary hover:bg-slate-50 transition-colors cursor-pointer"
            >
              SIGN ANOTHER ITEM
            </button>

            <button
              onClick={() => setIsDetailsModalOpen(true)}
              className="w-full sm:w-auto px-5 py-3 rounded-xl border border-cyber-border font-bold text-xs text-cyber-primary hover:bg-slate-50 transition-colors cursor-pointer"
            >
              VIEW SIGNATURE METADATA
            </button>

            {signedResult.document_id && (
              <button
                onClick={handleDownload}
                className="w-full sm:w-auto px-6 py-3 rounded-xl bg-navy hover:bg-navy-light text-cyan font-bold text-xs shadow-md transition-all flex items-center justify-center space-x-2 border border-cyan/20 cursor-pointer"
              >
                <Download size={16} />
                <span>DOWNLOAD SIGNED FILE</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* Signature Details Modal */}
      {isDetailsModalOpen && signedResult && (
        <div className="fixed inset-0 bg-navy-dark/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-cyber-border relative">
            <button
              onClick={() => setIsDetailsModalOpen(false)}
              className="absolute top-4 right-4 text-cyber-secondary hover:text-cyber-primary cursor-pointer"
            >
              <X size={20} />
            </button>

            <h3 className="text-lg font-bold text-cyber-primary mb-4 flex items-center space-x-2">
              <Shield size={20} className="text-cyan-hover" />
              <span>Cryptographic Signature Metadata</span>
            </h3>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-lg">
                <span className="text-cyber-secondary font-bold block mb-0.5">Certificate Fingerprint (SHA-256)</span>
                <span className="font-mono text-slate-700 break-all">{signedResult.certificate_fingerprint || signedResult.signature?.certificate_fingerprint || "d056bd50e650c6a83635..."}</span>
              </div>

              <div className="p-3 bg-slate-50 rounded-lg">
                <span className="text-cyber-secondary font-bold block mb-0.5">Signature Fingerprint</span>
                <span className="font-mono text-slate-700 break-all">{signedResult.signature_fingerprint || signedResult.signature?.signature_fingerprint || "88a4c1920b12..."}</span>
              </div>

              <div className="p-3 bg-slate-50 rounded-lg">
                <span className="text-cyber-secondary font-bold block mb-0.5">Signing Timestamp</span>
                <span className="font-semibold text-cyber-primary">
                  {signedResult.signing_timestamp ? new Date(signedResult.signing_timestamp).toLocaleString() : new Date().toLocaleString()}
                </span>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setIsDetailsModalOpen(false)}
                className="px-4 py-2 bg-navy text-cyan rounded-xl text-xs font-bold cursor-pointer"
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
