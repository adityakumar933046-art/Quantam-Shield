import React, { useState, useEffect } from 'react';
import { api } from '../../services/api';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  FileText,
  Key,
  Repeat,
  UserX,
  Lock,
  Layers,
  Atom,
  Trash2,
  Sliders,
  Info
} from 'lucide-react';

interface ThreatItem {
  threat_category: string;
  threat_type?: string;
  severity: string;
  threat_score: number;
  threat_status: string;
  description: string;
}

interface BaselineState {
  signature_status?: string;
  integrity_status?: string;
  state_consistency?: number;
  state_disturbance?: number;
  threat_probability?: number;
  risk_score?: number;
  threats_detected?: string[];
}

interface SimulationResult {
  result_id: number;
  simulation_id: number;
  attack_type: string;
  detection_success: boolean;
  detection_status: string;
  signature_valid: boolean;
  integrity_valid: boolean;
  threats_detected: ThreatItem[] | any;
  state_consistency: number;
  state_disturbance: number;
  pauli_disturbance: number;
  measurement_secure_probability: number;
  measurement_threat_probability: number;
  forgery_risk_estimate: number;
  final_risk_score: number;
  final_risk_level: string;
  baseline_comparison?: {
    normal_state: BaselineState;
    simulated_attack_state: BaselineState;
  };
  explanation?: any;
  execution_time_ms: number;
  created_at: string;
}

interface SimulationRecord {
  id: number;
  simulation_id: string;
  initiated_by: string;
  attack_type: string;
  target_document_reference?: string;
  parameters?: string;
  status: string;
  started_at: string;
  completed_at: string;
  created_at: string;
  result?: SimulationResult;
}

interface MetricsSummary {
  total_simulations: number;
  threats_correctly_detected: number;
  detection_rate: number;
  missed_simulations: number;
  average_detection_time_ms: number;
  average_risk_score: number;
  attack_type_breakdown: Record<string, { total: number; detected: number; detection_rate: number }>;
  disclaimer: string;
}

const ATTACK_TYPES = [
  {
    id: 'DOCUMENT_TAMPERING',
    name: 'Document Tampering',
    icon: FileText,
    badge: 'Integrity',
    description: 'Modifies text or JSON content in temporary memory to test SHA-256 integrity and quantum disturbance detection.',
    defaultParams: {
      tamper_mode: 'CHAR_FLIP',
      content_text: 'AGREEMENT: The undersigned agrees to terms outlined in Section 12. Validated by Q-SHIELD.'
    }
  },
  {
    id: 'SIGNATURE_FORGERY',
    name: 'Signature Forgery',
    icon: Key,
    badge: 'Cryptographic',
    description: 'Substitutes invalid signature bytes or unrelated keys to test cryptographic verification failure and Pauli X bit-flip detection.',
    defaultParams: {
      forgery_mode: 'CORRUPT_BYTES'
    }
  },
  {
    id: 'REPLAY_ATTACK',
    name: 'Replay Attack',
    icon: Repeat,
    badge: 'History / Rate',
    description: 'Generates high-frequency synthetic verification events to test time-window threshold and replay attack detection.',
    defaultParams: {
      number_of_attempts: 20,
      time_window_seconds: 10
    }
  },
  {
    id: 'IMPERSONATION',
    name: 'Identity Impersonation',
    icon: UserX,
    badge: 'Identity / Trust',
    description: 'Simulates identity mismatch between claimed signer and verified certificate subject to test Pauli Z phase disturbance.',
    defaultParams: {
      claimed_signer_name: 'Chief Executive Officer (Authorized)',
      verified_signer_name: 'Untrusted External Entity (Attacker)'
    }
  },
  {
    id: 'UNAUTHORIZED_VERIFICATION',
    name: 'Unauthorized Verification',
    icon: Lock,
    badge: 'RBAC Security',
    description: 'Simulates unprivileged or unauthenticated requests to verify that RBAC guards deny access and log audit events.',
    defaultParams: {
      attempting_role: 'DIGITAL_SIGNATURE_USER',
      required_role: 'SECURITY_ANALYST'
    }
  },
  {
    id: 'SIGNATURE_MANIPULATION',
    name: 'Signature Manipulation',
    icon: Layers,
    badge: 'Structure / ASN.1',
    description: 'Truncates or corrupts signature containers to test ASN.1 parser resilience, algorithm downgrade, and structural anomaly detection.',
    defaultParams: {
      manipulation_type: 'TRUNCATED_SIGNATURE'
    }
  },
  {
    id: 'QUANTUM_CHANNEL_MANIPULATION',
    name: 'Quantum Channel Disturbance',
    icon: Atom,
    badge: 'Theoretical Math',
    description: 'Simulates decoupled Bell-state transmission, Pauli noise, and projective measurement disturbance in Hilbert space.',
    defaultParams: {
      scenario: 'PAULI_X_DISTURBANCE',
      bell_state_name: 'PHI_PLUS'
    }
  }
];

export const AttackSimulationPage: React.FC = () => {
  const [selectedAttack, setSelectedAttack] = useState<string>('DOCUMENT_TAMPERING');
  const [parameters, setParameters] = useState<Record<string, any>>(ATTACK_TYPES[0].defaultParams);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [currentResult, setCurrentResult] = useState<SimulationResult | null>(null);
  const [history, setHistory] = useState<SimulationRecord[]>([]);
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [activeTab, setActiveTab] = useState<'execute' | 'comparison' | 'metrics' | 'history'>('execute');

  useEffect(() => {
    fetchHistory();
    fetchMetrics();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await api.get('/simulations/history/');
      setHistory(res.data);
    } catch (err) {
      console.error('Failed to load simulation history:', err);
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await api.get('/simulations/metrics/summary');
      setMetrics(res.data);
    } catch (err) {
      console.error('Failed to load metrics:', err);
    }
  };

  const handleSelectAttack = (attackId: string) => {
    setSelectedAttack(attackId);
    const item = ATTACK_TYPES.find((a) => a.id === attackId);
    if (item) {
      setParameters(item.defaultParams);
    }
  };

  const handleRunSimulation = async () => {
    setIsLoading(true);
    try {
      const res = await api.post('/simulations/execute/', {
        attack_type: selectedAttack,
        target_document_reference: 'simulation_target_sample.txt',
        parameters: parameters
      });
      if (res.data.result) {
        setCurrentResult(res.data.result);
      }
      fetchHistory();
      fetchMetrics();
    } catch (err) {
      console.error('Failed to execute simulation:', err);
      alert('Simulation execution failed. Check console for details.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteSimulation = async (simId: string | number) => {
    try {
      await api.delete(`/simulations/${simId}/`);
      fetchHistory();
      fetchMetrics();
    } catch (err) {
      console.error('Failed to delete simulation:', err);
    }
  };

  const currentAttackMeta = ATTACK_TYPES.find((a) => a.id === selectedAttack);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
            <ShieldAlert size={22} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-navy">Controlled Attack Simulation Module</h1>
            <p className="text-sm text-slate-500 font-medium">
              Defensive testing environment to verify multi-layer threat detection capabilities
            </p>
          </div>
        </div>

        <div className="flex bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('execute')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'execute' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-navy'
            }`}
          >
            Simulation Lab
          </button>
          <button
            onClick={() => setActiveTab('comparison')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'comparison' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-navy'
            }`}
          >
            Visual Comparison
          </button>
          <button
            onClick={() => setActiveTab('metrics')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'metrics' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-navy'
            }`}
          >
            Detection Performance
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2 rounded-lg transition-all ${
              activeTab === 'history' ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-navy'
            }`}
          >
            History ({history.length})
          </button>
        </div>
      </div>

      {/* Defensive Safety Banner */}
      <div className="p-4 rounded-xl bg-blue-50/70 border border-blue-200 flex items-start space-x-3 text-xs text-blue-900 leading-relaxed shadow-sm">
        <ShieldCheck className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold uppercase tracking-wider text-blue-700">Controlled Defensive Simulation Sandbox: </span>
          All simulations execute exclusively on isolated in-memory buffers and synthetic identities. Real signed documents,
          cryptographic private keys, and live audit databases remain completely unchanged. Zero production attacks are generated.
        </div>
      </div>

      {/* Metrics Bar */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Total Tests</p>
            <p className="text-2xl font-black text-navy mt-1">{metrics.total_simulations}</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Threats Detected</p>
            <p className="text-2xl font-black text-emerald-600 mt-1">{metrics.threats_correctly_detected}</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Detection Rate</p>
            <p className="text-2xl font-black text-blue-600 mt-1">{metrics.detection_rate}%</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Missed Tests</p>
            <p className="text-2xl font-black text-slate-600 mt-1">{metrics.missed_simulations}</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Avg Latency</p>
            <p className="text-2xl font-black text-indigo-600 mt-1">{metrics.average_detection_time_ms} ms</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Avg Risk Score</p>
            <p className="text-2xl font-black text-amber-600 mt-1">{metrics.average_risk_score}</p>
          </div>
        </div>
      )}

      {/* TAB 1: SIMULATION LAB */}
      {activeTab === 'execute' && (
        <div className="space-y-8">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-500 mb-3 flex items-center space-x-2">
              <Sliders size={16} />
              <span>Select Attack Type Scenario</span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {ATTACK_TYPES.map((attack) => {
                const Icon = attack.icon;
                const isSelected = selectedAttack === attack.id;
                return (
                  <button
                    key={attack.id}
                    onClick={() => handleSelectAttack(attack.id)}
                    className={`p-4 rounded-xl border text-left transition-all relative overflow-hidden flex flex-col justify-between ${
                      isSelected
                        ? 'border-blue-600 bg-blue-50/50 shadow-md ring-2 ring-blue-500/20'
                        : 'border-slate-200 bg-white hover:border-slate-300 hover:shadow-sm'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <div
                          className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                            isSelected ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          <Icon size={18} />
                        </div>
                        <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">
                          {attack.badge}
                        </span>
                      </div>
                      <h3 className="font-bold text-sm text-navy mb-1">{attack.name}</h3>
                      <p className="text-xs text-slate-500 leading-relaxed line-clamp-2">{attack.description}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Configuration & Execute Panel */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div>
                <h3 className="font-bold text-base text-navy">
                  Scenario Configuration: {currentAttackMeta?.name}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">{currentAttackMeta?.description}</p>
              </div>

              <button
                onClick={handleRunSimulation}
                disabled={isLoading}
                className={`px-6 py-2.5 rounded-xl font-bold text-xs uppercase tracking-wider text-white shadow-lg transition-all flex items-center space-x-2 ${
                  isLoading
                    ? 'bg-slate-400 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700 shadow-blue-500/20'
                }`}
              >
                {isLoading ? (
                  <>
                    <RotateCcw className="w-4 h-4 animate-spin" />
                    <span>Executing Simulation...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white" />
                    <span>Run Attack Simulation</span>
                  </>
                )}
              </button>
            </div>

            {/* Dynamic Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
              {selectedAttack === 'DOCUMENT_TAMPERING' && (
                <>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Tampering Mode
                    </label>
                    <select
                      value={parameters.tamper_mode || 'CHAR_FLIP'}
                      onChange={(e) => setParameters({ ...parameters, tamper_mode: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    >
                      <option value="CHAR_FLIP">Single Byte / Character Flip</option>
                      <option value="WORD_REPLACE">Lexical Word Replacement</option>
                      <option value="JSON_VALUE_TAMPER">JSON Field Value Mutation</option>
                      <option value="CUSTOM_APPEND">Append Malicious Content</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Test Document Text
                    </label>
                    <input
                      type="text"
                      value={parameters.content_text || ''}
                      onChange={(e) => setParameters({ ...parameters, content_text: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    />
                  </div>
                </>
              )}

              {selectedAttack === 'SIGNATURE_FORGERY' && (
                <div>
                  <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                    Forgery Mode
                  </label>
                  <select
                    value={parameters.forgery_mode || 'CORRUPT_BYTES'}
                    onChange={(e) => setParameters({ ...parameters, forgery_mode: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                  >
                    <option value="CORRUPT_BYTES">Signature Byte Block Inversion (Invalid PKCS#7)</option>
                    <option value="WRONG_PUBLIC_KEY">Unrelated Attacker Public Key Substitution</option>
                    <option value="SYNTHETIC_INVALID_SIG">Synthetic Mismatched Digest Signature</option>
                  </select>
                </div>
              )}

              {selectedAttack === 'REPLAY_ATTACK' && (
                <>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Number of Rapid Attempts
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={parameters.number_of_attempts || 20}
                      onChange={(e) => setParameters({ ...parameters, number_of_attempts: parseInt(e.target.value) || 1 })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    />
                  </div>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Time Window (Seconds)
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={3600}
                      value={parameters.time_window_seconds || 10}
                      onChange={(e) => setParameters({ ...parameters, time_window_seconds: parseInt(e.target.value) || 10 })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    />
                  </div>
                </>
              )}

              {selectedAttack === 'IMPERSONATION' && (
                <>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Claimed Signer Name
                    </label>
                    <input
                      type="text"
                      value={parameters.claimed_signer_name || ''}
                      onChange={(e) => setParameters({ ...parameters, claimed_signer_name: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    />
                  </div>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Verified Certificate Subject
                    </label>
                    <input
                      type="text"
                      value={parameters.verified_signer_name || ''}
                      onChange={(e) => setParameters({ ...parameters, verified_signer_name: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    />
                  </div>
                </>
              )}

              {selectedAttack === 'UNAUTHORIZED_VERIFICATION' && (
                <div>
                  <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                    Simulated Requester Role
                  </label>
                  <select
                    value={parameters.attempting_role || 'DIGITAL_SIGNATURE_USER'}
                    onChange={(e) => setParameters({ ...parameters, attempting_role: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                  >
                    <option value="DIGITAL_SIGNATURE_USER">DIGITAL_SIGNATURE_USER (Unprivileged)</option>
                    <option value="ANONYMOUS">ANONYMOUS (Unauthenticated)</option>
                    <option value="DISABLED_ACCOUNT">DISABLED_ACCOUNT (Revoked)</option>
                  </select>
                </div>
              )}

              {selectedAttack === 'SIGNATURE_MANIPULATION' && (
                <div>
                  <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                    Manipulation Technique
                  </label>
                  <select
                    value={parameters.manipulation_type || 'TRUNCATED_SIGNATURE'}
                    onChange={(e) => setParameters({ ...parameters, manipulation_type: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                  >
                    <option value="TRUNCATED_SIGNATURE">Truncated ASN.1 Signature Stream</option>
                    <option value="CORRUPT_ENCODING">Corrupted DER Byte Sequence</option>
                    <option value="REUSE_CONFLICT">Conflicting Signature Hash Reuse</option>
                    <option value="WEAK_ALGORITHM_DOWNGRADE">Cryptographic Downgrade (MD5/SHA-1)</option>
                  </select>
                </div>
              )}

              {selectedAttack === 'QUANTUM_CHANNEL_MANIPULATION' && (
                <>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Quantum Channel Noise Scenario
                    </label>
                    <select
                      value={parameters.scenario || 'PAULI_X_DISTURBANCE'}
                      onChange={(e) => setParameters({ ...parameters, scenario: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    >
                      <option value="PAULI_X_DISTURBANCE">Pauli X Bit-Flip Disturbance (X|0⟩ = |1⟩)</option>
                      <option value="PAULI_Z_DISTURBANCE">Pauli Z Phase-Flip Disturbance (Z|1⟩ = -|1⟩)</option>
                      <option value="PAULI_Y_DISTURBANCE">Pauli Y Compound Bit-and-Phase Noise</option>
                      <option value="INTERCEPTION_SIMULATION">Eavesdropper Intercept-Resend State Collapse</option>
                      <option value="MEASUREMENT_DISTURBANCE">Detector Projective Measurement Decoherence</option>
                      <option value="NO_ATTACK">Zero Attack (Ideal Intact Channel)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-bold text-slate-700 mb-1.5 uppercase tracking-wider text-[11px]">
                      Reference Entangled Bell State
                    </label>
                    <select
                      value={parameters.bell_state_name || 'PHI_PLUS'}
                      onChange={(e) => setParameters({ ...parameters, bell_state_name: e.target.value })}
                      className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg font-medium text-navy"
                    >
                      <option value="PHI_PLUS">|Φ+⟩ = (|00⟩ + |11⟩) / √2</option>
                      <option value="PHI_MINUS">|Φ-⟩ = (|00⟩ - |11⟩) / √2</option>
                      <option value="PSI_PLUS">|Ψ+⟩ = (|01⟩ + |10⟩) / √2</option>
                      <option value="PSI_MINUS">|Ψ-⟩ = (|01⟩ - |10⟩) / √2</option>
                    </select>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Results Display */}
          {currentResult && (
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-md space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-4">
                <div className="flex items-center space-x-3">
                  <div
                    className={`w-10 h-10 rounded-xl flex items-center justify-center text-white ${
                      currentResult.detection_status === 'DETECTED'
                        ? 'bg-emerald-600'
                        : currentResult.detection_status === 'BLOCKED'
                        ? 'bg-blue-600'
                        : 'bg-rose-600'
                    }`}
                  >
                    {currentResult.detection_status === 'DETECTED' ? (
                      <CheckCircle2 size={22} />
                    ) : currentResult.detection_status === 'BLOCKED' ? (
                      <Lock size={22} />
                    ) : (
                      <XCircle size={22} />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="font-bold text-lg text-navy">
                        Simulation Result: {currentResult.attack_type}
                      </h3>
                      <span
                        className={`text-xs font-black px-2.5 py-0.5 rounded-full uppercase tracking-wider ${
                          currentResult.detection_status === 'DETECTED'
                            ? 'bg-emerald-100 text-emerald-800'
                            : currentResult.detection_status === 'BLOCKED'
                            ? 'bg-blue-100 text-blue-800'
                            : 'bg-rose-100 text-rose-800'
                        }`}
                      >
                        {currentResult.detection_status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 font-medium">
                      Latency: {currentResult.execution_time_ms} ms | Timestamp:{' '}
                      {new Date(currentResult.created_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                <div className="text-right">
                  <p className="text-slate-400 text-[10px] uppercase font-bold">Platform Risk Tier</p>
                  <p
                    className={`font-black text-sm ${
                      currentResult.final_risk_level === 'CRITICAL'
                        ? 'text-rose-600'
                        : currentResult.final_risk_level === 'HIGH'
                        ? 'text-amber-600'
                        : currentResult.final_risk_level === 'MEDIUM'
                        ? 'text-blue-600'
                        : 'text-emerald-600'
                    }`}
                  >
                    {currentResult.final_risk_level} ({currentResult.final_risk_score}/100)
                  </p>
                </div>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Signature</p>
                  <p
                    className={`text-xs font-extrabold mt-1 ${
                      currentResult.signature_valid ? 'text-emerald-600' : 'text-rose-600'
                    }`}
                  >
                    {currentResult.signature_valid ? 'VALID' : 'INVALID'}
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Integrity</p>
                  <p
                    className={`text-xs font-extrabold mt-1 ${
                      currentResult.integrity_valid ? 'text-emerald-600' : 'text-rose-600'
                    }`}
                  >
                    {currentResult.integrity_valid ? 'INTACT' : 'MODIFIED'}
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Consistency C</p>
                  <p className="text-xs font-extrabold text-navy mt-1">
                    {(currentResult.state_consistency * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Disturbance D</p>
                  <p className="text-xs font-extrabold text-rose-600 mt-1">
                    {currentResult.state_disturbance.toFixed(4)}
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Pauli Anomaly</p>
                  <p className="text-xs font-extrabold text-indigo-600 mt-1">
                    {(currentResult.pauli_disturbance * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">P(Threat)</p>
                  <p className="text-xs font-extrabold text-amber-600 mt-1">
                    {(currentResult.measurement_threat_probability * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
                  <p className="text-[10px] font-bold uppercase text-slate-400">Forgery Est.</p>
                  <p className="text-xs font-extrabold text-rose-600 mt-1">
                    {currentResult.forgery_risk_estimate.toFixed(1)}%
                  </p>
                </div>
              </div>

              {/* Identified Threats */}
              {Array.isArray(currentResult.threats_detected) && currentResult.threats_detected.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                    Identified Threats ({currentResult.threats_detected.length})
                  </h4>
                  <div className="space-y-2">
                    {currentResult.threats_detected.map((t: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-3 bg-rose-50/50 border border-rose-200 rounded-xl flex items-start justify-between text-xs"
                      >
                        <div className="flex items-start space-x-2">
                          <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold text-rose-900">{t.threat_category}</span>
                            <p className="text-rose-700 text-[11px] mt-0.5">{t.description}</p>
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded font-bold uppercase text-[10px] bg-rose-200 text-rose-800">
                          {t.severity || 'CRITICAL'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Explanation */}
              {currentResult.explanation && (
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 text-xs text-slate-700 space-y-1.5 font-mono">
                  <p className="font-bold text-navy uppercase text-[11px] font-sans">
                    Mathematical & Analytical Breakdown
                  </p>
                  {typeof currentResult.explanation === 'object' ? (
                    Object.entries(currentResult.explanation).map(([k, v]) => (
                      <div key={k} className="flex flex-col sm:flex-row sm:space-x-2">
                        <span className="font-bold text-slate-500 capitalize">{k.replace(/_/g, ' ')}:</span>
                        <span className="text-navy">{String(v)}</span>
                      </div>
                    ))
                  ) : (
                    <p>{String(currentResult.explanation)}</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: VISUAL COMPARISON */}
      {activeTab === 'comparison' && (
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-6">
          <div>
            <h2 className="text-base font-bold text-navy mb-1">Empirical Ground-Truth Comparison</h2>
            <p className="text-xs text-slate-500">
              Side-by-side comparison of nominal security metrics versus simulated adversarial states.
            </p>
          </div>

          {currentResult && currentResult.baseline_comparison ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Normal Reference State */}
              <div className="p-5 rounded-xl border-2 border-emerald-200 bg-emerald-50/20 space-y-4">
                <div className="flex items-center justify-between border-b border-emerald-100 pb-3">
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-600" />
                    <h3 className="font-bold text-sm text-emerald-950 uppercase tracking-wider">
                      Normal Reference State
                    </h3>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800">
                    SECURE
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="flex justify-between py-1 border-b border-emerald-100/60">
                    <span className="text-slate-500 font-medium">Signature Status:</span>
                    <span className="font-bold text-emerald-700">
                      {currentResult.baseline_comparison.normal_state.signature_status || 'VALID'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-emerald-100/60">
                    <span className="text-slate-500 font-medium">Integrity Status:</span>
                    <span className="font-bold text-emerald-700">
                      {currentResult.baseline_comparison.normal_state.integrity_status || 'INTACT'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-emerald-100/60">
                    <span className="text-slate-500 font-medium">State Consistency C:</span>
                    <span className="font-bold text-navy">100.0%</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-emerald-100/60">
                    <span className="text-slate-500 font-medium">Disturbance D:</span>
                    <span className="font-bold text-emerald-700">0.0000</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-emerald-100/60">
                    <span className="text-slate-500 font-medium">Threat Probability:</span>
                    <span className="font-bold text-emerald-700">0.0%</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500 font-medium">Composite Risk:</span>
                    <span className="font-bold text-emerald-700">10.0 / 100 (LOW)</span>
                  </div>
                </div>
              </div>

              {/* Simulated Attack State */}
              <div className="p-5 rounded-xl border-2 border-rose-200 bg-rose-50/20 space-y-4">
                <div className="flex items-center justify-between border-b border-rose-100 pb-3">
                  <div className="flex items-center space-x-2">
                    <ShieldAlert className="w-5 h-5 text-rose-600" />
                    <h3 className="font-bold text-sm text-rose-950 uppercase tracking-wider">
                      Simulated Attack State
                    </h3>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-800">
                    {currentResult.final_risk_level}
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="flex justify-between py-1 border-b border-rose-100/60">
                    <span className="text-slate-500 font-medium">Signature Status:</span>
                    <span className="font-bold text-rose-700">
                      {currentResult.baseline_comparison.simulated_attack_state.signature_status || 'INVALID'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-rose-100/60">
                    <span className="text-slate-500 font-medium">Integrity Status:</span>
                    <span className="font-bold text-rose-700">
                      {currentResult.baseline_comparison.simulated_attack_state.integrity_status || 'MODIFIED'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-rose-100/60">
                    <span className="text-slate-500 font-medium">State Consistency C:</span>
                    <span className="font-bold text-rose-700">
                      {(currentResult.state_consistency * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-rose-100/60">
                    <span className="text-slate-500 font-medium">Disturbance D:</span>
                    <span className="font-bold text-rose-700">
                      {currentResult.state_disturbance.toFixed(4)}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-rose-100/60">
                    <span className="text-slate-500 font-medium">Threat Probability:</span>
                    <span className="font-bold text-rose-700">
                      {(currentResult.measurement_threat_probability * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500 font-medium">Composite Risk:</span>
                    <span className="font-bold text-rose-700">
                      {currentResult.final_risk_score} / 100 ({currentResult.final_risk_level})
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-400">
              <p className="text-xs">No simulation executed in this session yet.</p>
              <button
                onClick={() => setActiveTab('execute')}
                className="mt-3 px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-bold hover:bg-blue-700"
              >
                Run a Simulation First
              </button>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DETECTION PERFORMANCE METRICS */}
      {activeTab === 'metrics' && (
        <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-6">
          <div>
            <h2 className="text-base font-bold text-navy mb-1">Defensive Detection Performance Metrics</h2>
            <p className="text-xs text-slate-500">
              Aggregated statistics across all executed test simulations.
            </p>
          </div>

          {metrics && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Detection Reliability</p>
                  <p className="text-3xl font-black text-blue-600">{metrics.detection_rate}%</p>
                  <p className="text-[11px] text-slate-500">
                    {metrics.threats_correctly_detected} of {metrics.total_simulations} simulated attacks caught
                  </p>
                </div>

                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Average Latency</p>
                  <p className="text-3xl font-black text-indigo-600">{metrics.average_detection_time_ms} ms</p>
                  <p className="text-[11px] text-slate-500">Mean cryptographic & quantum evaluation runtime</p>
                </div>

                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Average Risk Score</p>
                  <p className="text-3xl font-black text-amber-600">{metrics.average_risk_score} / 100</p>
                  <p className="text-[11px] text-slate-500">Mean composite threat risk under attack scenarios</p>
                </div>
              </div>

              {/* Breakdown List */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
                  Detection Accuracy Breakdown By Attack Scenario
                </h3>
                <div className="space-y-3">
                  {Object.entries(metrics.attack_type_breakdown).map(([atype, stats]) => (
                    <div key={atype} className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs space-y-1">
                      <div className="flex justify-between font-bold text-navy">
                        <span>{atype.replace(/_/g, ' ')}</span>
                        <span className="text-blue-600">{stats.detection_rate}% ({stats.detected}/{stats.total})</span>
                      </div>
                      <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-600 rounded-full transition-all duration-500"
                          style={{ width: `${stats.detection_rate}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-[11px] text-amber-800 flex items-start space-x-2">
                <Info className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                <span>{metrics.disclaimer}</span>
              </div>
            </>
          )}
        </div>
      )}

      {/* TAB 4: SIMULATION HISTORY */}
      {activeTab === 'history' && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-100 flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-navy">Simulation Audit History</h2>
              <p className="text-xs text-slate-500">Historical records of executed attack tests</p>
            </div>
            <button
              onClick={fetchHistory}
              className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs font-semibold text-slate-600 hover:bg-slate-50 flex items-center space-x-1"
            >
              <RotateCcw size={14} />
              <span>Refresh</span>
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-3">Simulation ID</th>
                  <th className="px-6 py-3">Attack Type</th>
                  <th className="px-6 py-3">Detection Status</th>
                  <th className="px-6 py-3">Risk Score</th>
                  <th className="px-6 py-3">Execution Time</th>
                  <th className="px-6 py-3">Timestamp</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {history.map((sim) => (
                  <tr key={sim.id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="px-6 py-4 font-mono font-bold text-navy">{sim.simulation_id}</td>
                    <td className="px-6 py-4 font-semibold text-slate-700">{sim.attack_type}</td>
                    <td className="px-6 py-4">
                      <span
                        className={`px-2 py-0.5 rounded-full font-bold text-[10px] uppercase ${
                          sim.result?.detection_status === 'DETECTED'
                            ? 'bg-emerald-100 text-emerald-800'
                            : sim.result?.detection_status === 'BLOCKED'
                            ? 'bg-blue-100 text-blue-800'
                            : 'bg-rose-100 text-rose-800'
                        }`}
                      >
                        {sim.result?.detection_status || sim.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-bold text-navy">
                      {sim.result ? `${sim.result.final_risk_score} (${sim.result.final_risk_level})` : 'N/A'}
                    </td>
                    <td className="px-6 py-4 text-slate-500">
                      {sim.result?.execution_time_ms ? `${sim.result.execution_time_ms} ms` : 'N/A'}
                    </td>
                    <td className="px-6 py-4 text-slate-500">
                      {new Date(sim.completed_at || sim.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDeleteSimulation(sim.id)}
                        className="p-1.5 rounded text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
                        title="Delete simulation record"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
                {history.length === 0 && (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-400">
                      <p className="font-semibold text-slate-600 text-sm">No simulation results available</p>
                      <p className="text-xs text-slate-400 mt-1">Execute a controlled attack simulation above to inspect detection results.</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackSimulationPage;
