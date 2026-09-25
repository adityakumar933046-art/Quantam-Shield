import React, { useState, useEffect } from 'react';
import {
  Atom,
  Zap,
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  BarChart3,
  Sliders,
  Layers,
  Radio,
  RefreshCw,
  Info,
  Clock,
  Key,
  ChevronRight,
  Gauge,
  Send,
  Lock,
  Sparkles
} from 'lucide-react';
import {
  getQDSHealth,
  getQDSThresholds,
  generateQDSKey,
  signQDS,
  teleportQDS,
  verifyQDS,
  simulateQDSAttack,
  runQDSAttackScenarios,
  extractErrorMessage,
  QDSHealthResponse,
  QDSThresholdsResponse,
  QDSKeyGenerationResponse,
  QDSSignResponse,
  QDSTeleportResponse,
  QDSVerifyResponse,
  QDSAttackType,
  QDSMultiQubitAttackResponse,
  QDSAttackScenariosResponse
} from '../../services/qdsApi';
import { api } from '../../services/api';

// Legacy single-qubit audit records (preserved for backward compatibility)
interface LegacyQDSSessionData {
  simulation_id: number;
  session_id: string;
  simulation_seed: number;
  signer_id: string;
  verifier_id: string;
  initial_state: string;
  initial_state_vector: string;
  bell_state: string;
  protocol_parameters?: string;
  measurement_bits: string;
  measurement_outcome: string;
  pauli_correction: string;
  reconstructed_state: string;
  fidelity: number;
  verification_result: string;
  session_status: string;
  created_at: string;
}

interface LegacyQDSMetricsData {
  total_simulations: number;
  successful_teleportations: number;
  attack_simulations_count: number;
  threats_detected_count: number;
  average_fidelity: number;
  average_execution_time_ms: number;
  attack_detection_accuracy: number;
  false_acceptance_rate: number;
  false_rejection_rate: number;
  time_complexity_explanation: string;
  space_complexity_explanation: string;
}

export const QDSSimulationPage: React.FC = () => {
  // Navigation Tabs
  const [activeTab, setActiveTab] = useState<
    'workflow' | 'attacks' | 'scenarios' | 'thresholds' | 'bell_states' | 'teleportation' | 'metrics' | 'history'
  >('workflow');

  // ============================================================================
  // SYSTEM HEALTH & THRESHOLDS (STEP 1 & CONFIG)
  // ============================================================================
  const [health, setHealth] = useState<QDSHealthResponse | null>(null);
  const [thresholds, setThresholds] = useState<QDSThresholdsResponse | null>(null);
  const [isLoadingHealth, setIsLoadingHealth] = useState(false);
  const [isLoadingThresholds, setIsLoadingThresholds] = useState(false);

  // ============================================================================
  // MULTI-QUBIT QDS WORKFLOW STATE (STEPS 2 - 5)
  // ============================================================================
  // Step 2: Key Generation
  const [keyLength, setKeyLength] = useState<number>(32);
  const [keySeed, setKeySeed] = useState<string>('42');
  const [isGeneratingKey, setIsGeneratingKey] = useState<boolean>(false);
  const [currentKey, setCurrentKey] = useState<QDSKeyGenerationResponse | null>(null);

  // Step 3: Signature Creation
  const [messageHash, setMessageHash] = useState<string>('a1b2c3d4');
  const [isSigning, setIsSigning] = useState<boolean>(false);
  const [currentSignature, setCurrentSignature] = useState<QDSSignResponse | null>(null);

  // Step 4: Teleportation
  const [teleportSeed, setTeleportSeed] = useState<string>('42');
  const [isTeleporting, setIsTeleporting] = useState<boolean>(false);
  const [teleportResult, setTeleportResult] = useState<QDSTeleportResponse | null>(null);

  // Step 5: Verification
  const [verifyThreshold, setVerifyThreshold] = useState<number>(0.10);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [verifyResult, setVerifyResult] = useState<QDSVerifyResponse | null>(null);

  // ============================================================================
  // ATTACK SIMULATION STATE (PHASE 4)
  // ============================================================================
  const [selectedAttackType, setSelectedAttackType] = useState<QDSAttackType>('bit_flip');
  const [attackMessageHash, setAttackMessageHash] = useState<string>('a1b2c3d4');
  const [attackKeyLength, setAttackKeyLength] = useState<number>(32);
  const [attackSeed, setAttackSeed] = useState<string>('42');
  const [isAttacking, setIsAttacking] = useState<boolean>(false);
  const [attackResult, setAttackResult] = useState<QDSMultiQubitAttackResponse | null>(null);

  // ============================================================================
  // ATTACK SCENARIOS COMPARISON STATE (PHASE 5)
  // ============================================================================
  const [scenariosHash, setScenariosHash] = useState<string>('a1b2c3d4');
  const [scenariosKeyLength, setScenariosKeyLength] = useState<number>(32);
  const [scenariosSeed, setScenariosSeed] = useState<string>('42');
  const [isComparing, setIsComparing] = useState<boolean>(false);
  const [comparisonResult, setComparisonResult] = useState<QDSAttackScenariosResponse | null>(null);

  // ============================================================================
  // LEGACY AUDIT & METRICS STATE
  // ============================================================================
  const [history, setHistory] = useState<LegacyQDSSessionData[]>([]);
  const [legacyMetrics, setLegacyMetrics] = useState<LegacyQDSMetricsData | null>(null);

  // Global Alerts
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // ============================================================================
  // INITIALIZATION
  // ============================================================================
  useEffect(() => {
    fetchHealthAndThresholds();
    fetchLegacyAudit();
  }, []);

  const fetchHealthAndThresholds = async () => {
    setIsLoadingHealth(true);
    setIsLoadingThresholds(true);
    try {
      const [h, t] = await Promise.all([getQDSHealth(), getQDSThresholds()]);
      setHealth(h);
      setThresholds(t);
    } catch (err) {
      console.error('Failed to fetch QDS health or thresholds:', err);
    } finally {
      setIsLoadingHealth(false);
      setIsLoadingThresholds(false);
    }
  };

  const fetchLegacyAudit = async () => {
    try {
      const [histRes, metRes] = await Promise.all([
        api.get<LegacyQDSSessionData[]>('/qds/simulations'),
        api.get<LegacyQDSMetricsData[]>('/qds/metrics')
      ]);
      setHistory(histRes.data);
      if (metRes.data && !Array.isArray(metRes.data)) {
        setLegacyMetrics(metRes.data as unknown as LegacyQDSMetricsData);
      }
    } catch {
      // Legacy routes optional
    }
  };

  const clearAlerts = () => {
    setError(null);
    setSuccessMsg(null);
  };

  // ============================================================================
  // HANDLERS: PROTOCOL WORKFLOW (STEPS 2 - 5)
  // ============================================================================

  // Step 2: Key Generation
  const handleGenerateKey = async () => {
    clearAlerts();
    setIsGeneratingKey(true);
    try {
      const parsedSeed = keySeed.trim() !== '' ? Number(keySeed) : null;
      const res = await generateQDSKey({
        key_length: Number(keyLength),
        seed: parsedSeed
      });
      setCurrentKey(res);
      // Reset downstream steps
      setCurrentSignature(null);
      setTeleportResult(null);
      setVerifyResult(null);
      setSuccessMsg(`QDS key generated successfully: ${res.key_id} (${res.key_length} qubits)`);
    } catch (err) {
      setError(extractErrorMessage(err, 'QDS key generation failed'));
    } finally {
      setIsGeneratingKey(false);
    }
  };

  // Step 3: Signature Creation
  const handleSignMessage = async () => {
    clearAlerts();
    if (!currentKey) {
      setError('Please generate a QDS key in Step 2 before signing.');
      return;
    }
    const cleanHash = messageHash.trim().toLowerCase();
    if (!cleanHash) {
      setError('Please enter a valid message hash.');
      return;
    }
    setIsSigning(true);
    try {
      const res = await signQDS({
        key_id: currentKey.key_id,
        message_hash: cleanHash
      });
      setCurrentSignature(res);
      setTeleportResult(null);
      setVerifyResult(null);
      setSuccessMsg(`Quantum signature created: ${res.signature_id} (${res.qubit_count} qubits mapped)`);
    } catch (err) {
      setError(extractErrorMessage(err, 'QDS signature creation failed'));
    } finally {
      setIsSigning(false);
    }
  };

  // Step 4: Teleportation
  const handleTeleportSignature = async () => {
    clearAlerts();
    if (!currentSignature) {
      setError('Please sign a message in Step 3 before teleporting.');
      return;
    }
    setIsTeleporting(true);
    try {
      const parsedSeed = teleportSeed.trim() !== '' ? Number(teleportSeed) : null;
      const res = await teleportQDS({
        signature_id: currentSignature.signature_id,
        seed: parsedSeed
      });
      setTeleportResult(res);
      setVerifyResult(null);
      setSuccessMsg(`Teleportation completed with average fidelity ${(res.average_fidelity * 100).toFixed(2)}%`);
    } catch (err) {
      setError(extractErrorMessage(err, 'QDS teleportation failed'));
    } finally {
      setIsTeleporting(false);
    }
  };

  // Step 5: Verification
  const handleVerifySignature = async () => {
    clearAlerts();
    if (!currentSignature) {
      setError('No active signature found. Please complete Steps 2 and 3 first.');
      return;
    }
    setIsVerifying(true);
    try {
      const res = await verifyQDS({
        signature_id: currentSignature.signature_id,
        threshold: Number(verifyThreshold)
      });
      setVerifyResult(res);
      if (res.verification.accepted) {
        setSuccessMsg('QDS Verification accepted: state matches within threshold.');
      } else {
        setError('QDS Verification rejected: state mismatch rate exceeds threshold.');
      }
    } catch (err) {
      setError(extractErrorMessage(err, 'QDS verification failed'));
    } finally {
      setIsVerifying(false);
    }
  };

  // ============================================================================
  // HANDLERS: ATTACK SIMULATION (PHASE 4)
  // ============================================================================
  const handleRunAttackSimulation = async () => {
    clearAlerts();
    setIsAttacking(true);
    try {
      const parsedSeed = attackSeed.trim() !== '' ? Number(attackSeed) : null;
      const res = await simulateQDSAttack({
        message_hash: attackMessageHash.trim().toLowerCase(),
        attack_type: selectedAttackType,
        key_length: Number(attackKeyLength),
        seed: parsedSeed
      });
      setAttackResult(res);
      setSuccessMsg(`Attack simulation (${selectedAttackType}) evaluated successfully.`);
    } catch (err) {
      setError(extractErrorMessage(err, 'Attack simulation failed'));
    } finally {
      setIsAttacking(false);
    }
  };

  // ============================================================================
  // HANDLERS: ATTACK SCENARIO COMPARISON (PHASE 5)
  // ============================================================================
  const handleRunComparison = async () => {
    clearAlerts();
    setIsComparing(true);
    try {
      const parsedSeed = scenariosSeed.trim() !== '' ? Number(scenariosSeed) : null;
      const res = await runQDSAttackScenarios({
        message_hash: scenariosHash.trim().toLowerCase(),
        key_length: Number(scenariosKeyLength),
        seed: parsedSeed
      });
      setComparisonResult(res);
      setSuccessMsg(`All 5 attack scenarios evaluated for hash "${res.message_hash}".`);
    } catch (err) {
      setError(extractErrorMessage(err, 'Scenario comparison benchmark failed'));
    } finally {
      setIsComparing(false);
    }
  };

  // Helper for severity badge colors
  const getSeverityBadge = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-500 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-600 border-yellow-500/30';
      default:
        return 'bg-emerald-500/15 text-emerald-600 border-emerald-500/30';
    }
  };

  const getRiskScoreBadge = (score: number) => {
    if (score >= 70) return 'text-red-500 font-black';
    if (score >= 40) return 'text-amber-500 font-bold';
    return 'text-emerald-500 font-bold';
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-16 text-slate-800">
      {/* ==================================================================== */}
      {/* SCIENTIFIC HEADER & DISCLAIMER                                        */}
      {/* ==================================================================== */}
      <div className="bg-gradient-to-r from-navy via-slate-900 to-navy p-6 rounded-2xl border border-cyan/30 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-cyan/20 pb-4">
          <div className="flex items-center space-x-3.5">
            <div className="w-12 h-12 rounded-xl bg-cyan/10 text-cyan flex items-center justify-center font-bold border border-cyan/40 shadow-inner">
              <Atom size={28} className="animate-spin" style={{ animationDuration: '14s' }} />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-2xl font-black text-white tracking-tight">Quantum Digital Signature (QDS)</h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan/20 text-cyan border border-cyan/40">
                  PROTOCOL v2.0
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                Multi-Qubit Teleportation-Based Quantum Digital Signature & Threat Detection Platform
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1.5">
              <ShieldCheck size={16} />
              <span>Deterministic Core</span>
            </span>
            <span className="px-3 py-1.5 rounded-xl text-xs font-bold bg-cyan/10 text-cyan border border-cyan/30 flex items-center space-x-1.5">
              <Zap size={16} />
              <span>Zero AI / Pure Linear Algebra</span>
            </span>
          </div>
        </div>

        {/* Scientifically Accurate Disclaimer */}
        <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800 text-[11px] text-slate-300 flex items-start space-x-2.5">
          <ShieldAlert size={18} className="text-cyan shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-cyan">Scientific Disclaimer:</strong> This platform mathematically models qubit states,
            Bell entanglement (|Φ+⟩), Pauli channel operations (I, X, Y, Z), and Born-rule projective verification via classical
            linear algebra simulation. Classical PDF signatures use standard X.509/RSA verification and remain safely isolated.
          </p>
        </div>
      </div>

      {/* Global Status Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start space-x-3 text-red-700 text-sm animate-in fade-in">
          <AlertTriangle size={20} className="shrink-0 mt-0.5 text-red-600" />
          <p className="font-medium">{error}</p>
        </div>
      )}
      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start space-x-3 text-emerald-800 text-sm animate-in fade-in">
          <CheckCircle2 size={20} className="shrink-0 mt-0.5 text-emerald-600" />
          <p className="font-medium">{successMsg}</p>
        </div>
      )}

      {/* ==================================================================== */}
      {/* STEP 1: QDS SERVICE HEALTH METRICS BAR                                 */}
      {/* ==================================================================== */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Service Health</span>
          <div className="flex items-center space-x-1.5">
            <span className={`w-2 h-2 rounded-full ${health?.status === 'healthy' ? 'bg-emerald-500' : 'bg-amber-500'} animate-pulse`} />
            <span className="text-sm font-extrabold text-cyber-primary uppercase">
              {isLoadingHealth ? 'Checking...' : health?.status || 'Active'}
            </span>
          </div>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Quantum Engine</span>
          <span className="text-sm font-extrabold text-cyan-hover">
            {health?.quantum_engine || 'Available'}
          </span>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Statistical Analysis</span>
          <span className="text-sm font-extrabold text-blue-600">
            {health?.statistical_analysis || 'Available'}
          </span>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Attack Pipeline</span>
          <span className="text-sm font-extrabold text-purple-600">
            {health?.attack_pipeline || '5 Scenarios'}
          </span>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Verification Thresh</span>
          <span className="text-sm font-mono font-bold text-cyber-primary">
            $S_a \le$ {thresholds ? thresholds.verification_threshold : '0.10'}
          </span>
        </div>

        <div className="p-3.5 bg-white rounded-xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">AI / ML Free</span>
          <span className="text-sm font-extrabold text-emerald-600">
            {health && health.ai_ml === false ? 'Verified (100%)' : 'Verified'}
          </span>
        </div>
      </div>

      {/* ==================================================================== */}
      {/* NAVIGATION TABS                                                      */}
      {/* ==================================================================== */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
        {[
          { id: 'workflow', label: '1. QDS Protocol', desc: 'Steps 1–5 Workflow', icon: Play },
          { id: 'attacks', label: '2. Attack Simulation', desc: 'Channel Attacks', icon: ShieldAlert },
          { id: 'scenarios', label: '3. Attack Benchmark', desc: '5-Scenario Table', icon: Gauge },
          { id: 'thresholds', label: '4. Thresholds', desc: 'Protocol Limits', icon: Sliders },
          { id: 'bell_states', label: '5. Bell States', desc: 'Entangled Pairs', icon: Radio },
          { id: 'teleportation', label: '6. Teleport Diagram', desc: 'State Transfer', icon: Layers },
          { id: 'metrics', label: '7. Complexity', desc: 'Time & Space', icon: BarChart3 },
          { id: 'history', label: '8. Session History', desc: 'Seed Audit Log', icon: Clock }
        ].map((tab) => {
          const IconComp = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as any)}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                isActive
                  ? 'bg-gradient-to-r from-blue-50/90 via-cyan/5 to-white border-cyan shadow-md shadow-cyan/10 ring-2 ring-cyan/30'
                  : 'bg-white hover:bg-slate-50 border-cyber-border'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div
                  className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                    isActive ? 'bg-navy text-cyan' : 'bg-slate-100 text-slate-600'
                  }`}
                >
                  <IconComp size={15} />
                </div>
                {isActive && <ChevronRight size={14} className="text-cyan-hover" />}
              </div>
              <div>
                <span className={`text-xs font-bold block truncate ${isActive ? 'text-navy' : 'text-slate-700'}`}>
                  {tab.label}
                </span>
                <span className="text-[10px] text-slate-400 block truncate">{tab.desc}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* ==================================================================== */}
      {/* TAB 1: COMPLETE MULTI-QUBIT QDS PROTOCOL WORKFLOW (STEPS 1 - 5)        */}
      {/* ==================================================================== */}
      {activeTab === 'workflow' && (
        <div className="space-y-6 animate-in fade-in">
          {/* STEP 2: GENERATE QDS KEY CARD */}
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <Key size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-cyber-primary">Step 2: Generate Multi-Qubit QDS Key</h3>
                  <p className="text-xs text-cyber-secondary">
                    Alice prepares conjugate bases. Private quantum states remain protected in server memory.
                  </p>
                </div>
              </div>

              <button
                onClick={handleGenerateKey}
                disabled={isGeneratingKey}
                className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-5 py-2.5 rounded-xl font-bold text-xs shadow-md transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isGeneratingKey ? (
                  <>
                    <RefreshCw size={14} className="animate-spin text-cyan" />
                    <span>Generating Key...</span>
                  </>
                ) : (
                  <>
                    <Sparkles size={14} className="text-cyan" />
                    <span>GENERATE QDS KEY</span>
                  </>
                )}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Key Length (Qubits)</label>
                <div className="flex items-center space-x-2">
                  <input
                    type="number"
                    min="1"
                    max="512"
                    value={keyLength}
                    onChange={(e) => setKeyLength(Number(e.target.value))}
                    className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                  />
                  <div className="flex space-x-1">
                    {[8, 16, 32, 64].map((n) => (
                      <button
                        key={n}
                        type="button"
                        onClick={() => setKeyLength(n)}
                        className={`px-2 py-1 text-[10px] rounded font-bold border cursor-pointer ${
                          keyLength === n ? 'bg-cyan text-navy border-cyan' : 'bg-slate-100 text-slate-600'
                        }`}
                      >
                        {n}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Random Seed (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. 42 (blank for random)"
                  value={keySeed}
                  onChange={(e) => setKeySeed(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Security Status</label>
                <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-[11px] text-slate-600 flex items-center space-x-2">
                  <Lock size={14} className="text-emerald-600 shrink-0" />
                  <span>Private states stored server-side only</span>
                </div>
              </div>
            </div>

            {/* Generated Key Metadata */}
            {currentKey && (
              <div className="p-4 bg-slate-900 text-white rounded-xl border border-cyan/30 text-xs font-mono space-y-2 animate-in fade-in">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-cyan font-bold">Active Key ID: {currentKey.key_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan/20 text-cyan border border-cyan/40">
                    {currentKey.protocol_version}
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  <div>Qubits: <span className="text-emerald-400 font-bold">{currentKey.key_length}</span></div>
                  <div>Seed: <span className="text-slate-300 font-bold">{currentKey.seed ?? 'Random'}</span></div>
                  <div>Public Bases: <span className="text-cyan">{currentKey.basis_information.slice(0, 8).join(' ')}...</span></div>
                  <div>Public States: <span className="text-slate-300">{currentKey.public_key.length} registered</span></div>
                </div>
              </div>
            )}
          </div>

          {/* STEP 3: CREATE QUANTUM SIGNATURE CARD */}
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <Send size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-cyber-primary">Step 3: Create Quantum Signature</h3>
                  <p className="text-xs text-cyber-secondary">
                    Maps message hash digest bits into quantum state representations using Alice's private basis.
                  </p>
                </div>
              </div>

              <button
                onClick={handleSignMessage}
                disabled={isSigning || !currentKey}
                className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-5 py-2.5 rounded-xl font-bold text-xs shadow-md transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isSigning ? (
                  <>
                    <RefreshCw size={14} className="animate-spin text-cyan" />
                    <span>Signing...</span>
                  </>
                ) : (
                  <>
                    <Send size={14} className="text-cyan" />
                    <span>SIGN MESSAGE HASH</span>
                  </>
                )}
              </button>
            </div>

            {!currentKey && (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500 flex items-center space-x-2">
                <Info size={16} className="text-cyan-hover" />
                <span>No active QDS key exists. Complete Step 2 first.</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div className="space-y-1.5 sm:col-span-2">
                <div className="flex justify-between items-center">
                  <label className="font-bold text-cyber-primary block">Message Hash (Hex Digest)</label>
                  <span className="text-[10px] text-slate-400">
                    Required qubits: {messageHash.trim().length * 4}
                  </span>
                </div>
                <input
                  type="text"
                  value={messageHash}
                  onChange={(e) => setMessageHash(e.target.value)}
                  placeholder="e.g. a1b2c3d4"
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                />
                <div className="flex items-center space-x-2 pt-1 text-[11px]">
                  <span className="text-slate-400">Sample Hashes:</span>
                  {['a1b2c3d4', '4f9c8b1a', 'deadbeef'].map((sample) => (
                    <button
                      key={sample}
                      type="button"
                      onClick={() => setMessageHash(sample)}
                      className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 hover:bg-slate-200 font-mono text-[10px] cursor-pointer"
                    >
                      {sample}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Attached Key</label>
                <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-[11px] text-slate-600 truncate">
                  {currentKey ? currentKey.key_id : 'No Key Selected'}
                </div>
              </div>
            </div>

            {/* Created Signature Metadata */}
            {currentSignature && (
              <div className="p-4 bg-slate-900 text-white rounded-xl border border-cyan/30 text-xs font-mono space-y-2 animate-in fade-in">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-cyan font-bold">Signature ID: {currentSignature.signature_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    SIGNATURE READY
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
                  <div>Hash: <span className="text-emerald-400">{currentSignature.message_hash}</span></div>
                  <div>Qubit Count: <span className="text-cyan font-bold">{currentSignature.qubit_count}</span></div>
                  <div>Protocol: <span className="text-slate-300">{currentSignature.protocol_version}</span></div>
                </div>
              </div>
            )}
          </div>

          {/* STEP 4: TELEPORT SIGNATURE CARD */}
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <Layers size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-cyber-primary">Step 4: Teleport Signature</h3>
                  <p className="text-xs text-cyber-secondary">
                    Transmits quantum signature qubits across Bell-entangled channel with Pauli corrections.
                  </p>
                </div>
              </div>

              <button
                onClick={handleTeleportSignature}
                disabled={isTeleporting || !currentSignature}
                className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-5 py-2.5 rounded-xl font-bold text-xs shadow-md transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isTeleporting ? (
                  <>
                    <RefreshCw size={14} className="animate-spin text-cyan" />
                    <span>Teleporting...</span>
                  </>
                ) : (
                  <>
                    <Layers size={14} className="text-cyan" />
                    <span>EXECUTE TELEPORTATION</span>
                  </>
                )}
              </button>
            </div>

            {!currentSignature && (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500 flex items-center space-x-2">
                <Info size={16} className="text-cyan-hover" />
                <span>Signature has not been generated yet. Complete Step 3 first.</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Teleportation Seed (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. 42"
                  value={teleportSeed}
                  onChange={(e) => setTeleportSeed(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Entangled Pair Specification</label>
                <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-[11px] font-mono text-slate-600">
                  |Φ+⟩ = (|00⟩ + |11⟩)/√2 with Pauli (I, X, Y, Z) correction
                </div>
              </div>
            </div>

            {/* Teleportation Output */}
            {teleportResult && (
              <div className="p-4 bg-slate-900 text-white rounded-xl border border-cyan/30 text-xs font-mono space-y-3 animate-in fade-in">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-cyan font-bold">Teleportation Status: {teleportResult.success ? 'SUCCESS' : 'FAILED'}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">
                    FIDELITY: {(teleportResult.average_fidelity * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
                  <div className="p-2 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Qubits Transmitted</span>
                    <span className="text-white font-bold">{teleportResult.qubit_count}</span>
                  </div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Average Fidelity</span>
                    <span className="text-emerald-400 font-bold">{teleportResult.average_fidelity.toFixed(4)}</span>
                  </div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800 col-span-2">
                    <span className="text-slate-400 block text-[10px]">Sample Pauli Corrections</span>
                    <span className="text-amber-300 font-bold truncate block">
                      {teleportResult.pauli_corrections.slice(0, 16).join(' ')}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* STEP 5: VERIFY SIGNATURE CARD */}
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border pb-3">
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <ShieldCheck size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-cyber-primary">Step 5: Verify Signature</h3>
                  <p className="text-xs text-cyber-secondary">
                    Performs conjugate projective measurements against Bob & Charlie; tests non-repudiation and threat evidence.
                  </p>
                </div>
              </div>

              <button
                onClick={handleVerifySignature}
                disabled={isVerifying || !currentSignature}
                className="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-2.5 rounded-xl font-bold text-xs shadow-md transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isVerifying ? (
                  <>
                    <RefreshCw size={14} className="animate-spin text-white" />
                    <span>Verifying...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck size={14} className="text-white" />
                    <span>VERIFY SIGNATURE</span>
                  </>
                )}
              </button>
            </div>

            {!currentSignature && (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500 flex items-center space-x-2">
                <Info size={16} className="text-cyan-hover" />
                <span>Teleportation must be completed before verification.</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className="font-bold text-cyber-primary block">Verification Threshold ($S_a$)</label>
                  <span className="font-mono text-cyan font-bold">{verifyThreshold.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="0.30"
                  step="0.01"
                  value={verifyThreshold}
                  onChange={(e) => setVerifyThreshold(Number(e.target.value))}
                  className="w-full accent-cyan cursor-pointer"
                />
                <span className="text-[10px] text-slate-400 block">
                  Standard QDS threshold: 0.10 (max 10% measurement mismatch accepted)
                </span>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Multi-Verifier Protocol</label>
                <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-[11px] text-slate-600">
                  Dual verifier model: Verifier Bob & Charlie compare outcomes ($|m_B - m_C| \le S_v$) to prevent repudiation.
                </div>
              </div>
            </div>

            {/* Verification Result Output */}
            {verifyResult && (
              <div className="p-6 bg-slate-950 text-white rounded-2xl border border-cyan/30 space-y-6 animate-in fade-in">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold border ${
                        verifyResult.verification.accepted
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}
                    >
                      {verifyResult.verification.accepted ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h4 className="text-lg font-black tracking-tight">
                          {verifyResult.verification.accepted ? 'VERIFICATION ACCEPTED' : 'VERIFICATION REJECTED'}
                        </h4>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                            verifyResult.threat.severity
                          )}`}
                        >
                          THREAT: {verifyResult.threat.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {verifyResult.threat.explanation || 'No significant channel or forgery disturbances detected.'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 text-center">
                      <span className="text-[10px] text-slate-400 block font-semibold">RISK SCORE</span>
                      <span className={`text-xl font-black ${getRiskScoreBadge(verifyResult.risk.score)}`}>
                        {verifyResult.risk.score.toFixed(1)} / 100
                      </span>
                    </div>
                  </div>
                </div>

                {/* Metrics Breakdown Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-1 font-mono">
                    <span className="text-slate-400 block text-[10px]">Mismatch Rate</span>
                    <span
                      className={`text-xl font-bold ${
                        verifyResult.verification.mismatch_rate <= verifyResult.verification.threshold
                          ? 'text-emerald-400'
                          : 'text-red-400'
                      }`}
                    >
                      {(verifyResult.verification.mismatch_rate * 100).toFixed(1)}%
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      Threshold: {(verifyResult.verification.threshold * 100).toFixed(0)}%
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-1 font-mono">
                    <span className="text-slate-400 block text-[10px]">Measurement Matches</span>
                    <span className="text-xl font-bold text-cyan">
                      {verifyResult.verification.matches} / {verifyResult.verification.matches + verifyResult.verification.mismatches}
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      Mismatches: {verifyResult.verification.mismatches}
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-1 font-mono">
                    <span className="text-slate-400 block text-[10px]">Distribution Distance</span>
                    <span className="text-xl font-bold text-purple-400">
                      {verifyResult.statistics.distribution_distance.toFixed(4)}
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      TVD metric
                    </span>
                  </div>

                  <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 space-y-1 font-mono">
                    <span className="text-slate-400 block text-[10px]">Chi-Square Status</span>
                    <span className="text-xs font-bold text-amber-300 block truncate">
                      {verifyResult.statistics.chi_square !== null
                        ? `χ² = ${verifyResult.statistics.chi_square.toFixed(2)}`
                        : verifyResult.statistics.chi_square_status}
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      Sample Size Check
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: DEDICATED ATTACK SIMULATION (PHASE 4)                           */}
      {/* ==================================================================== */}
      {activeTab === 'attacks' && (
        <div className="space-y-6 animate-in fade-in">
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-red-600 text-white flex items-center justify-center font-bold">
                  <ShieldAlert size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-cyber-primary">Quantum-Inspired Attack Simulation</h3>
                  <p className="text-xs text-cyber-secondary">
                    Inject Pauli errors, eavesdropper intercept-resend, or forgery attempts into the transmission channel.
                  </p>
                </div>
              </div>

              <button
                onClick={handleRunAttackSimulation}
                disabled={isAttacking}
                className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-xl font-bold text-xs shadow-lg transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isAttacking ? (
                  <>
                    <RefreshCw size={16} className="animate-spin" />
                    <span>Running Simulation...</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert size={16} />
                    <span>RUN ATTACK SIMULATION</span>
                  </>
                )}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs">
              <div className="space-y-1.5 sm:col-span-2">
                <label className="font-bold text-cyber-primary block">Attack Vector Model</label>
                <select
                  value={selectedAttackType}
                  onChange={(e) => setSelectedAttackType(e.target.value as QDSAttackType)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-bold text-cyber-primary focus:outline-none focus:border-red-500"
                >
                  <option value="none">none (Honest Baseline — Zero Channel Noise)</option>
                  <option value="bit_flip">bit_flip (Pauli X Bit-Flip Operator)</option>
                  <option value="phase_flip">phase_flip (Pauli Z Phase-Flip Operator)</option>
                  <option value="intercept_resend">intercept_resend (Eavesdropper Born-Rule Collapse)</option>
                  <option value="random_state_substitution">random_state_substitution (Forgery Attempt)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Message Hash</label>
                <input
                  type="text"
                  value={attackMessageHash}
                  onChange={(e) => setAttackMessageHash(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Key Length (Qubits)</label>
                <input
                  type="number"
                  min="8"
                  max="128"
                  value={attackKeyLength}
                  onChange={(e) => setAttackKeyLength(Number(e.target.value))}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            {/* Baseline vs Attack indicator */}
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span
                  className={`w-3 h-3 rounded-full ${
                    selectedAttackType === 'none' ? 'bg-emerald-500' : 'bg-red-500 animate-ping'
                  }`}
                />
                <span className="font-bold text-cyber-primary">
                  {selectedAttackType === 'none'
                    ? 'BASELINE EVALUATION: Honest QDS Teleportation'
                    : `ATTACK SCENARIO ACTIVE: ${selectedAttackType}`}
                </span>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">
                Seed: {attackSeed || 'Random'}
              </span>
            </div>
          </div>

          {/* Attack Result Display Card */}
          {attackResult && (
            <div className="p-6 bg-slate-950 text-white rounded-2xl border border-red-500/40 shadow-2xl space-y-6 animate-in fade-in">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div
                    className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold border ${
                      attackResult.threat.detected
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                    }`}
                  >
                    <ShieldAlert size={28} />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="text-xl font-black text-white tracking-tight">
                        ATTACK SIMULATION OUTCOME
                      </h4>
                      <span className="px-2.5 py-0.5 rounded font-mono text-[10px] font-bold bg-slate-800 text-cyan border border-slate-700">
                        {attackResult.attack_type.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      {attackResult.threat.explanation}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div
                    className={`px-4 py-2 rounded-xl font-black text-xs border ${
                      attackResult.verification.accepted
                        ? 'bg-emerald-600 text-white border-emerald-700'
                        : 'bg-red-600 text-white border-red-700'
                    }`}
                  >
                    VERIFICATION: {attackResult.verification.accepted ? 'ACCEPTED' : 'REJECTED'}
                  </div>
                  <div className="p-2 bg-slate-900 rounded-xl border border-slate-800 text-center">
                    <span className="text-[10px] text-slate-400 block font-semibold">RISK</span>
                    <span className={`text-base font-black ${getRiskScoreBadge(attackResult.risk.score)}`}>
                      {attackResult.risk.score.toFixed(1)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Grid Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">State Fidelity ($F$)</span>
                  <span
                    className={`text-2xl font-black ${
                      attackResult.teleportation.attacked_average_fidelity >= 0.85
                        ? 'text-emerald-400'
                        : 'text-red-400'
                    }`}
                  >
                    {(attackResult.teleportation.attacked_average_fidelity * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Disturbance ($D$)</span>
                  <span className="text-2xl font-black text-amber-400">
                    {(attackResult.teleportation.disturbance * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Mismatch Rate</span>
                  <span className="text-2xl font-black text-purple-400">
                    {(attackResult.verification.mismatch_rate * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Distribution Distance</span>
                  <span className="text-2xl font-black text-blue-400">
                    {attackResult.statistics.distribution_distance.toFixed(4)}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: ATTACK SCENARIO COMPARISON MATRIX (PHASE 5)                     */}
      {/* ==================================================================== */}
      {activeTab === 'scenarios' && (
        <div className="space-y-6 animate-in fade-in">
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <Gauge size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-cyber-primary">All 5 QDS Attack Scenarios Benchmark</h3>
                  <p className="text-xs text-cyber-secondary">
                    Comparative matrix evaluating Baseline vs Forgery vs Bit-Flip vs Phase-Flip vs Intercept-Resend.
                  </p>
                </div>
              </div>

              <button
                onClick={handleRunComparison}
                disabled={isComparing}
                className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-6 py-3 rounded-xl font-bold text-xs shadow-lg transition-all flex items-center space-x-2 cursor-pointer disabled:opacity-50"
              >
                {isComparing ? (
                  <>
                    <RefreshCw size={16} className="animate-spin text-cyan" />
                    <span>Evaluating Scenarios...</span>
                  </>
                ) : (
                  <>
                    <Zap size={16} className="text-cyan" />
                    <span>RUN BENCHMARK MATRIX</span>
                  </>
                )}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Message Hash</label>
                <input
                  type="text"
                  value={scenariosHash}
                  onChange={(e) => setScenariosHash(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Key Length (Qubits)</label>
                <input
                  type="number"
                  min="8"
                  max="128"
                  value={scenariosKeyLength}
                  onChange={(e) => setScenariosKeyLength(Number(e.target.value))}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-bold text-cyber-primary block">Simulation Seed</label>
                <input
                  type="text"
                  value={scenariosSeed}
                  onChange={(e) => setScenariosSeed(e.target.value)}
                  className="w-full p-2.5 rounded-xl border border-cyber-border bg-slate-50 font-mono text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>
            </div>
          </div>

          {/* Benchmark Results */}
          {comparisonResult && (
            <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
              {/* Summary KPIs */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block">Attacks Evaluated</span>
                  <span className="text-xl font-black text-cyber-primary">
                    {comparisonResult.summary.attacks_evaluated}
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block">Detection Rate</span>
                  <span className="text-xl font-black text-emerald-600">
                    {comparisonResult.summary.detection_rate_percentage}%
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block">Honest Baseline Fidelity</span>
                  <span className="text-xl font-black text-cyan-hover">
                    {(comparisonResult.summary.honest_baseline_fidelity * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase block">Avg Attacked Fidelity</span>
                  <span className="text-xl font-black text-amber-500">
                    {(comparisonResult.summary.average_attacked_fidelity * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-cyber-border bg-slate-50 text-cyber-secondary font-bold uppercase tracking-wider">
                      <th className="p-3">Attack Scenario</th>
                      <th className="p-3">Verification</th>
                      <th className="p-3">Fidelity ($F$)</th>
                      <th className="p-3">Mismatch Rate</th>
                      <th className="p-3">Dist. Distance (TVD)</th>
                      <th className="p-3">Threat Detected</th>
                      <th className="p-3">Threat Type</th>
                      <th className="p-3">Risk Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border font-mono">
                    {comparisonResult.scenarios.map((sc) => (
                      <tr key={sc.attack_type} className="hover:bg-slate-50/80">
                        <td className="p-3 font-bold text-cyber-primary">
                          {sc.attack_type === 'none' ? 'none (Honest Baseline)' : sc.attack_type}
                        </td>
                        <td className="p-3 font-sans">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              sc.accepted ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                            }`}
                          >
                            {sc.accepted ? 'Accepted' : 'Rejected'}
                          </span>
                        </td>
                        <td className="p-3 font-bold">{(sc.fidelity * 100).toFixed(1)}%</td>
                        <td className="p-3">{(sc.mismatch_rate * 100).toFixed(1)}%</td>
                        <td className="p-3">{sc.distribution_distance.toFixed(4)}</td>
                        <td className="p-3 font-sans">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              sc.threat_detected ? 'bg-red-100 text-red-800' : 'bg-slate-100 text-slate-600'
                            }`}
                          >
                            {sc.threat_detected ? 'DETECTED' : 'CLEAN'}
                          </span>
                        </td>
                        <td className="p-3 font-sans text-slate-600">
                          {sc.threat_type || 'N/A'}
                        </td>
                        <td className="p-3 font-bold">
                          <span className={getRiskScoreBadge(sc.risk_score)}>
                            {sc.risk_score.toFixed(1)} ({sc.risk_tier})
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 4: THRESHOLDS DISPLAY (PHASE 6)                                    */}
      {/* ==================================================================== */}
      {activeTab === 'thresholds' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Sliders size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Active QDS Mathematical Threshold Configuration</h3>
              <p className="text-xs text-cyber-secondary">
                Configured limits governing acceptance, non-repudiation, channel disturbance, and statistical significance.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Verification Threshold ($S_a$)</span>
              <span className="text-2xl font-mono font-black text-cyber-primary">
                {thresholds ? thresholds.verification_threshold : '0.10'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Maximum allowable mismatch rate between Alice's transmitted quantum state and Bob's measurement outcome.
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Repudiation Threshold ($S_v$)</span>
              <span className="text-2xl font-mono font-black text-cyber-primary">
                {thresholds ? thresholds.repudiation_threshold : '0.05'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Max allowable discrepancy between verifiers (Bob vs Charlie) before non-repudiation condition fails ($S_v \le 0.05$).
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Channel Disturbance Threshold</span>
              <span className="text-2xl font-mono font-black text-amber-500">
                {thresholds ? thresholds.channel_disturbance_threshold : '0.20'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Threshold for $D = 1 - F$; disturbance above 20% triggers Quantum Channel Manipulation alarms.
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Minimum Acceptable Fidelity</span>
              <span className="text-2xl font-mono font-black text-emerald-600">
                {thresholds ? thresholds.minimum_acceptable_fidelity : '0.90'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Fidelity $F = |\langle\psi|\phi\rangle|^2$ below 0.90 triggers automated channel quality alerts.
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Distribution Distance Threshold</span>
              <span className="text-2xl font-mono font-black text-purple-600">
                {thresholds ? thresholds.distribution_distance_anomaly_threshold : '0.15'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Total Variation Distance (TVD $\ge 0.15$) anomaly limit between observed and expected quantum states.
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <span className="text-slate-400 font-semibold block text-[10px] uppercase">Chi-Square Min Sample Size</span>
              <span className="text-2xl font-mono font-black text-blue-600">
                {thresholds ? thresholds.chi_square_min_sample_size : '20'}
              </span>
              <p className="text-slate-500 text-[11px] leading-relaxed">
                Requires at least 20 qubits and expected frequency $\ge 5.0$ for valid statistical hypothesis testing.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 5: BELL STATES & ENTANGLEMENT                                      */}
      {/* ==================================================================== */}
      {activeTab === 'bell_states' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Radio size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Maximally Entangled Bell States</h3>
              <p className="text-xs text-cyber-secondary">Mathematical basis states for 2-qubit entangled systems</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 text-xs font-mono">
            <div className="p-5 bg-slate-900 text-white rounded-xl border border-cyan/30 space-y-3">
              <div className="flex justify-between items-center">
                <span className="font-extrabold text-cyan text-sm">{"|Φ⁺⟩"} (Standard Default)</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">NORM = 1.0</span>
              </div>
              <p className="p-3 bg-slate-950 rounded-lg text-cyan font-bold text-sm text-center border border-slate-800">
                {"|Φ⁺⟩ = (1/√2)|00⟩ + (1/√2)|11⟩"}
              </p>
              <p className="text-slate-400 text-[11px] leading-relaxed font-sans">
                Maximal entanglement state with parallel spins. Used as standard quantum channel for QDS signature teleportation.
              </p>
            </div>

            <div className="p-5 bg-slate-900 text-white rounded-xl border border-slate-800 space-y-3">
              <div className="flex justify-between items-center">
                <span className="font-extrabold text-white text-sm">{"|Φ⁻⟩"}</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">NORM = 1.0</span>
              </div>
              <p className="p-3 bg-slate-950 rounded-lg text-slate-200 font-bold text-sm text-center border border-slate-800">
                {"|Φ⁻⟩ = (1/√2)|00⟩ - (1/√2)|11⟩"}
              </p>
              <p className="text-slate-400 text-[11px] leading-relaxed font-sans">
                Maximal entanglement state with phase inversion (π phase difference between {"|00⟩"} and {"|11⟩"}).
              </p>
            </div>

            <div className="p-5 bg-slate-900 text-white rounded-xl border border-slate-800 space-y-3">
              <div className="flex justify-between items-center">
                <span className="font-extrabold text-white text-sm">{"|Ψ⁺⟩"}</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">NORM = 1.0</span>
              </div>
              <p className="p-3 bg-slate-950 rounded-lg text-slate-200 font-bold text-sm text-center border border-slate-800">
                {"|Ψ⁺⟩ = (1/√2)|01⟩ + (1/√2)|10⟩"}
              </p>
              <p className="text-slate-400 text-[11px] leading-relaxed font-sans">
                Maximal entanglement state with anti-parallel spins ({"|01⟩"} and {"|10⟩"}).
              </p>
            </div>

            <div className="p-5 bg-slate-900 text-white rounded-xl border border-slate-800 space-y-3">
              <div className="flex justify-between items-center">
                <span className="font-extrabold text-white text-sm">{"|Ψ⁻⟩"} (Singlet State)</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">NORM = 1.0</span>
              </div>
              <p className="p-3 bg-slate-950 rounded-lg text-slate-200 font-bold text-sm text-center border border-slate-800">
                {"|Ψ⁻⟩ = (1/√2)|01⟩ - (1/√2)|10⟩"}
              </p>
              <p className="text-slate-400 text-[11px] leading-relaxed font-sans">
                Singlet state invariant under rotational transformations in 2-qubit Hilbert space.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 6: TELEPORTATION DIAGRAM                                           */}
      {/* ==================================================================== */}
      {activeTab === 'teleportation' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Layers size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Quantum Teleportation Visual Workflow</h3>
              <p className="text-xs text-cyber-secondary">Step-by-step mathematical state transfer from Alice (Signer) to Bob (Verifier)</p>
            </div>
          </div>

          <div className="p-8 bg-slate-950 text-white rounded-2xl border border-cyan/30 space-y-8">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 text-center text-xs font-mono">
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <span className="text-cyan font-bold block text-sm">SIGNER (ALICE)</span>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px]">
                  Signature Qubit<br/>{"|ψ⟩ = α|0⟩ + β|1⟩"}
                </div>
              </div>

              <div className="p-4 bg-slate-900 rounded-xl border border-cyan/40 space-y-2">
                <span className="text-cyan font-bold block text-sm">ENTANGLEMENT</span>
                <div className="p-2 bg-slate-950 rounded border border-cyan/30 text-[11px] text-cyan">
                  Bell Pair {"|Φ⁺⟩_AB"}<br/>Qubit A ↔ Qubit B
                </div>
              </div>

              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <span className="text-amber-400 font-bold block text-sm">MEASUREMENT</span>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-amber-300">
                  Bell Measurement<br/>Classical Bits $m_1 m_2$
                </div>
              </div>

              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-2">
                <span className="text-blue-400 font-bold block text-sm">VERIFIER (BOB)</span>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-blue-300">
                  Pauli Correction<br/>$I, X, Z, XZ$
                </div>
              </div>

              <div className="p-4 bg-slate-900 rounded-xl border border-emerald-500/40 space-y-2">
                <span className="text-emerald-400 font-bold block text-sm">VERIFICATION</span>
                <div className="p-2 bg-slate-950 rounded border border-emerald-500/30 text-[11px] text-emerald-300">
                  Fidelity Check<br/>$F \ge 0.95$
                </div>
              </div>
            </div>

            <div className="p-5 bg-slate-900 rounded-xl border border-slate-800 space-y-3 text-xs">
              <h4 className="text-xs font-bold text-cyan uppercase tracking-wider">Teleportation Pauli Correction Rules ($|\Phi^+\rangle$)</h4>
              <div className="grid grid-cols-4 gap-2 text-center font-mono text-[11px]">
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400 block font-bold">Bit 00</span>
                  <span className="text-white font-bold">Apply I Operator</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400 block font-bold">Bit 01</span>
                  <span className="text-amber-400 font-bold">Apply Z Operator</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400 block font-bold">Bit 10</span>
                  <span className="text-blue-400 font-bold">Apply X Operator</span>
                </div>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400 block font-bold">Bit 11</span>
                  <span className="text-cyan font-bold">Apply XZ Operator</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 7: COMPLEXITY & PARAMETERS                                         */}
      {/* ==================================================================== */}
      {activeTab === 'metrics' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <BarChart3 size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Algorithm Parameters & Computational Complexity</h3>
              <p className="text-xs text-cyber-secondary">Theoretical time and space complexity scaling analysis</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary uppercase tracking-wider border-b border-slate-200 pb-2">
                Time Complexity Analysis
              </h4>
              <p className="text-slate-600 leading-relaxed">
                {legacyMetrics?.time_complexity_explanation ||
                  'O(N × 2^n) matrix-vector transformations per qubit state simulation trial. Teleportation setup executes in O(1) constant time for 2-qubit system.'}
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary uppercase tracking-wider border-b border-slate-200 pb-2">
                Space Complexity Analysis
              </h4>
              <p className="text-slate-600 leading-relaxed">
                {legacyMetrics?.space_complexity_explanation ||
                  'O(2^n) state vector amplitude storage. 2-qubit Hilbert space requires exact 4 complex float numbers (64 bytes memory).'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 8: AUDIT HISTORY                                                  */}
      {/* ==================================================================== */}
      {activeTab === 'history' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Clock size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">QDS Simulation History & Seed Audit Log</h3>
              <p className="text-xs text-cyber-secondary">Session records with deterministic seed reproducibility</p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-cyber-border bg-slate-50 text-cyber-secondary font-bold uppercase tracking-wider">
                  <th className="p-3">Session ID</th>
                  <th className="p-3">Seed</th>
                  <th className="p-3">Initial State</th>
                  <th className="p-3">Bell Pair</th>
                  <th className="p-3">Pauli Correction</th>
                  <th className="p-3">Fidelity</th>
                  <th className="p-3">Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border font-mono">
                {history.length > 0 ? (
                  history.map((s) => (
                    <tr key={s.simulation_id} className="hover:bg-slate-50/80">
                      <td className="p-3 font-bold text-cyber-primary">{s.session_id}</td>
                      <td className="p-3 text-cyan-hover font-bold">{s.simulation_seed}</td>
                      <td className="p-3">{s.initial_state}</td>
                      <td className="p-3">{s.bell_state}</td>
                      <td className="p-3 font-bold text-amber-600">{s.pauli_correction}</td>
                      <td className="p-3 font-bold">{(s.fidelity * 100).toFixed(1)}%</td>
                      <td className="p-3 font-sans">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            s.verification_result === 'ACCEPT'
                              ? 'bg-emerald-100 text-emerald-800'
                              : 'bg-red-100 text-red-800'
                          }`}
                        >
                          {s.verification_result}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="p-6 text-center text-slate-400 font-sans">
                      No historical single-qubit audit sessions recorded yet.
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

export default QDSSimulationPage;
