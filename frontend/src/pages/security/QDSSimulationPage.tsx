import React, { useState, useEffect } from 'react';
import { api } from '../../services/api';
import {
  Atom,
  Zap,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Cpu,
  BarChart3,
  Sliders,
  Layers,
  Radio,
  FileCheck,
  RefreshCw,
  Info,
  Clock,
  Key,
  UserCheck,
  ChevronRight,
  TrendingUp,
  Gauge
} from 'lucide-react';

interface QDSSessionData {
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

interface QDSAttackData {
  attack_simulation_id: number;
  attack_type: string;
  number_of_trials: number;
  expected_distribution?: string;
  observed_distribution?: string;
  mean_fidelity: number;
  measurement_error_rate: number;
  acceptance_rate: number;
  rejection_rate: number;
  detection_rate: number;
  false_acceptance_rate: number;
  execution_time_ms: number;
  created_at: string;
}

interface QDSMetricsData {
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
  const [activeTab, setActiveTab] = useState<'overview' | 'simulation' | 'bell_states' | 'teleportation' | 'attacks' | 'measurement' | 'metrics' | 'history'>('overview');

  // Simulation Form Controls
  const [initialState, setInitialState] = useState('|+>');
  const [bellState, setBellState] = useState('|Phi+>');
  const [simulationSeed, setSimulationSeed] = useState(42);
  const [signerId, setSignerId] = useState('Alice (Signer)');
  const [verifierId, setVerifierId] = useState('Bob (Verifier)');
  const [acceptanceThreshold, setAcceptanceThreshold] = useState(0.95);

  // Simulation State & Progress
  const [isSimulating, setIsSimulating] = useState(false);
  const [simStep, setSimStep] = useState(0);
  const [simMessage, setSimMessage] = useState('');
  const [currentSession, setCurrentSession] = useState<QDSSessionData | null>(null);

  // Attack Form Controls
  const [attackType, setAttackType] = useState('BIT_FLIP');
  const [attackProbability, setAttackProbability] = useState(0.5);
  const [numberOfTrials, setNumberOfTrials] = useState(100);
  const [isAttacking, setIsAttacking] = useState(false);
  const [currentAttackResult, setCurrentAttackResult] = useState<QDSAttackData | null>(null);

  // Data History & Metrics
  const [history, setHistory] = useState<QDSSessionData[]>([]);
  const [metrics, setMetrics] = useState<QDSMetricsData | null>(null);
  const [selectedSessionModal, setSelectedSessionModal] = useState<QDSSessionData | null>(null);

  const [error, setError] = useState<string | null>(null);

  const simulationProgressSteps = [
    "Preparing Quantum State Representation",
    "Generating Bell-State Entanglement Pair (|Φ+⟩)",
    "Distributing Quantum Public Verification Parameters",
    "Performing Joint Bell-Basis Measurement",
    "Transmitting Classical Bits (m1 m2) to Verifier",
    "Applying Pauli Correction (I, X, Y, Z)",
    "Reconstructing Quantum State",
    "Performing Born-Rule Projective Measurement & Fidelity Check"
  ];

  useEffect(() => {
    fetchHistoryAndMetrics();
  }, []);

  const fetchHistoryAndMetrics = async () => {
    try {
      const [histRes, metRes] = await Promise.all([
        api.get('/qds/simulations'),
        api.get('/qds/metrics')
      ]);
      setHistory(histRes.data);
      setMetrics(metRes.data);
    } catch (err: any) {
      console.error("Failed to fetch QDS history/metrics:", err);
    }
  };

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    setError(null);

    try {
      for (let i = 1; i <= 7; i++) {
        setSimStep(i);
        setSimMessage(simulationProgressSteps[i - 1]);
        await new Promise(r => setTimeout(r, 180));
      }

      const res = await api.post('/qds/simulate', {
        initial_state: initialState,
        bell_state: bellState,
        simulation_seed: Number(simulationSeed),
        signer_id: signerId,
        verifier_id: verifierId,
        acceptance_threshold: Number(acceptanceThreshold)
      });

      setSimStep(8);
      setSimMessage(simulationProgressSteps[7]);
      await new Promise(r => setTimeout(r, 150));

      setCurrentSession(res.data);
      await fetchHistoryAndMetrics();
    } catch (err: any) {
      console.error(err);
      const detail = err.response?.data?.detail;
      const errorMsg = typeof detail === 'string'
        ? detail
        : (Array.isArray(detail)
            ? detail.map((d: any) => `${d.loc?.slice(-1)[0] || 'field'}: ${d.msg}`).join('; ')
            : (err.message || "QDS Simulation execution failed."));
      setError(errorMsg);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleRunAttackSimulation = async () => {
    setIsAttacking(true);
    setError(null);

    try {
      const res = await api.post('/qds/attack-simulation', {
        attack_type: attackType,
        number_of_trials: Number(numberOfTrials),
        attack_probability: Number(attackProbability),
        initial_state: initialState,
        simulation_seed: Number(simulationSeed),
        detection_threshold: Number(acceptanceThreshold),
        signer_id: signerId,
        verifier_id: verifierId
      });

      setCurrentAttackResult(res.data);
      await fetchHistoryAndMetrics();
    } catch (err: any) {
      console.error(err);
      const detail = err.response?.data?.detail;
      const errorMsg = typeof detail === 'string'
        ? detail
        : (Array.isArray(detail)
            ? detail.map((d: any) => `${d.loc?.slice(-1)[0] || 'field'}: ${d.msg}`).join('; ')
            : (err.message || "Attack simulation execution failed."));
      setError(errorMsg);
    } finally {
      setIsAttacking(false);
    }
  };

  const handleRerunSession = async (simulationId: number) => {
    setError(null);
    try {
      const res = await api.post(`/qds/simulations/${simulationId}/rerun`);
      setCurrentSession(res.data);
      setActiveTab('simulation');
      await fetchHistoryAndMetrics();
    } catch (err: any) {
      console.error(err);
      const detail = err.response?.data?.detail;
      const errorMsg = typeof detail === 'string'
        ? detail
        : (Array.isArray(detail)
            ? detail.map((d: any) => `${d.loc?.slice(-1)[0] || 'field'}: ${d.msg}`).join('; ')
            : (err.message || "Failed to re-run session."));
      setError(errorMsg);
    }
  };

  const parseStateVector = (jsonStr: string) => {
    try {
      return JSON.parse(jsonStr);
    } catch {
      return { alpha_real: 0.7071, alpha_imag: 0, beta_real: 0.7071, beta_imag: 0, prob_0: 0.5, prob_1: 0.5 };
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Scientific Accuracy & Disclaimer Header Banner */}
      <div className="bg-gradient-to-r from-navy via-slate-900 to-navy p-6 rounded-2xl border border-cyan/30 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-cyan/20 pb-4">
          <div className="flex items-center space-x-3">
            <div className="w-12 h-12 rounded-xl bg-cyan/10 text-cyan flex items-center justify-center font-bold border border-cyan/40 shadow-inner">
              <Atom size={28} className="animate-spin" style={{ animationDuration: '10s' }} />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-2xl font-black text-white tracking-tight">Teleportation-Based QDS Simulation</h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan/20 text-cyan border border-cyan/40">
                  QDS PROTOCOL v2.0
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                Quantum-Inspired / Mathematical Simulation Environment modeling Bell-State Entanglement, Teleportation & Pauli Corrections
              </p>
            </div>
          </div>

          <div className="px-3.5 py-1.5 rounded-xl text-xs font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30 shrink-0 flex items-center space-x-1.5">
            <Info size={16} />
            <span>Mathematical Software Simulation</span>
          </div>
        </div>

        {/* Explicit Non-Overclaiming Disclaimer Box */}
        <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800 text-[11px] text-slate-300 flex items-start space-x-2.5">
          <ShieldAlert size={18} className="text-cyan shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-cyan">Scientific Disclaimer:</strong> This module mathematically simulates qubit states ({"|ψ⟩ = α|0⟩ + β|1⟩"}), Bell entanglement, and Pauli matrix transformations using classical software algorithms. It does not perform physical quantum hardware communication or claim information-theoretic security for classical PDF operations.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-start space-x-3 text-red-700 text-sm">
          <AlertTriangle size={20} className="shrink-0 mt-0.5 text-red-600" />
          <p className="font-medium">{error}</p>
        </div>
      )}

      {/* Top Metrics Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <div className="p-4 bg-white rounded-2xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Total Simulations</span>
          <span className="text-2xl font-black text-cyber-primary">{metrics?.total_simulations || 0}</span>
        </div>

        <div className="p-4 bg-white rounded-2xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Teleportation Success</span>
          <span className="text-2xl font-black text-emerald-600">{metrics?.successful_teleportations || 0}</span>
        </div>

        <div className="p-4 bg-white rounded-2xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Attack Experiments</span>
          <span className="text-2xl font-black text-blue-600">{metrics?.attack_simulations_count || 0}</span>
        </div>

        <div className="p-4 bg-white rounded-2xl border border-cyber-border shadow-sm space-y-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Threats Detected</span>
          <span className="text-2xl font-black text-red-600">{metrics?.threats_detected_count || 0}</span>
        </div>

        <div className="p-4 bg-white rounded-2xl border border-cyber-border shadow-sm space-y-1 col-span-2 sm:col-span-1">
          <span className="text-[10px] font-bold text-cyber-secondary uppercase tracking-wider block">Average State Fidelity</span>
          <span className="text-2xl font-black text-cyan-hover">
            {metrics?.average_fidelity ? (metrics.average_fidelity * 100).toFixed(1) : '100.0'}%
          </span>
        </div>
      </div>

      {/* Modern Compact Dashboard Navigation Cards Grid */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 rounded-full bg-cyan animate-pulse" />
            <span className="text-[11px] font-bold text-cyber-secondary uppercase tracking-wider">
              Simulation Modules & Protocol Workflow
            </span>
          </div>
          <span className="text-[11px] font-medium text-slate-400 hidden sm:inline">
            Click any module box to view its interactive interface
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            {
              id: 'overview',
              title: '1. QDS Overview',
              description: 'Project introduction and basic concepts',
              icon: Info
            },
            {
              id: 'simulation',
              title: '2. Protocol Simulation',
              description: 'Configure and run QDS simulations',
              icon: Play
            },
            {
              id: 'bell_states',
              title: '3. Bell States',
              description: 'Analyze entangled quantum states',
              icon: Radio
            },
            {
              id: 'teleportation',
              title: '4. Teleportation Diagram',
              description: 'Visualize quantum teleportation process',
              icon: Layers
            },
            {
              id: 'attacks',
              title: '5. Attack Simulation',
              description: 'Test security threats and attack scenarios',
              icon: ShieldAlert
            },
            {
              id: 'measurement',
              title: '6. Measurement Analysis',
              description: 'Analyze measurement results and state fidelity',
              icon: BarChart3
            },
            {
              id: 'metrics',
              title: '7. Parameters',
              description: 'Configure simulation parameters',
              icon: Sliders
            },
            {
              id: 'history',
              title: '8. Simulation History',
              description: 'Audit historical sessions and replay seeds',
              icon: Clock
            }
          ].map((item) => {
            const IconComp = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id as any)}
                className={`group relative text-left p-4 rounded-xl border transition-all duration-200 cursor-pointer flex items-center justify-between ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-50/90 via-cyan/5 to-white border-cyan shadow-md shadow-cyan/15 ring-2 ring-cyan/40 -translate-y-0.5'
                    : 'bg-white hover:bg-slate-50 border-cyber-border hover:border-slate-300 hover:shadow-md hover:-translate-y-0.5'
                }`}
              >
                <div className="flex items-center space-x-3.5 min-w-0 pr-2">
                  <div
                    className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all ${
                      isActive
                        ? 'bg-navy text-cyan shadow-md shadow-navy/20 border border-cyan/40'
                        : 'bg-slate-100 text-slate-600 group-hover:bg-cyan/10 group-hover:text-cyan-hover'
                    }`}
                  >
                    <IconComp size={20} className={isActive ? 'text-cyan' : ''} />
                  </div>
                  <div className="min-w-0">
                    <span
                      className={`text-xs block font-bold truncate ${
                        isActive ? 'text-navy font-black' : 'text-cyber-primary group-hover:text-navy'
                      }`}
                    >
                      {item.title}
                    </span>
                    <p
                      className={`text-[11px] leading-snug mt-0.5 truncate ${
                        isActive ? 'text-slate-600 font-medium' : 'text-slate-500 group-hover:text-slate-600'
                      }`}
                    >
                      {item.description}
                    </p>
                  </div>
                </div>

                <div className="shrink-0 pl-1">
                  <ChevronRight
                    size={16}
                    className={`transition-transform duration-200 ${
                      isActive
                        ? 'text-cyan-hover translate-x-1'
                        : 'text-slate-300 group-hover:text-slate-400 group-hover:translate-x-0.5'
                    }`}
                  />
                </div>

                {/* Active Accent Line on Top */}
                {isActive && (
                  <span className="absolute top-0 left-4 right-4 h-0.5 bg-gradient-to-r from-cyan via-blue-500 to-cyan rounded-full" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* SECTION 1: QDS OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Info size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Teleportation-Based QDS Protocol Overview</h3>
              <p className="text-xs text-cyber-secondary">Quantum digital signatures utilizing Bell state entanglement & classical channel teleportation</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-600 leading-relaxed">
            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary flex items-center space-x-2">
                <Atom size={16} className="text-cyan-hover" />
                <span>Quantum Public Verification Information</span>
              </h4>
              <p>
                Unlike classical RSA public keys, Quantum Digital Signature schemes utilize <strong>Quantum Public Verification Information</strong> — reference commitments, Bell state configurations, and measurement parameters distributed prior to verification.
              </p>
              <ul className="list-disc list-inside space-y-1 text-slate-500 font-mono text-[11px]">
                <li>Quantum State Commitment Vector</li>
                <li>Bell Pair Configuration ({"|Φ⁺⟩"})</li>
                <li>Protocol Acceptance Threshold (F ≥ 0.95)</li>
              </ul>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary flex items-center space-x-2">
                <Key size={16} className="text-blue-600" />
                <span>Private Signing Parameters</span>
              </h4>
              <p>
                The signer (Alice) prepares secret quantum signature state parameters {"|ψ⟩ = α|0⟩ + β|1⟩"}. Classical private keys remain part of the separate Classical Digital Signature module.
              </p>
              <ul className="list-disc list-inside space-y-1 text-slate-500 font-mono text-[11px]">
                <li>Complex Amplitudes (α, β)</li>
                <li>Alice's Entangled Qubit A</li>
                <li>Deterministic Simulation Seed</li>
              </ul>
            </div>
          </div>

          {/* Teleportation Steps Summary */}
          <div className="p-6 bg-navy text-white rounded-xl border border-cyan/30 space-y-4">
            <h4 className="text-sm font-bold text-cyan uppercase tracking-wider">Teleportation Protocol Execution Steps</h4>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-center text-xs font-mono">
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-cyan block font-bold mb-1">1. State Prep</span>
                <span className="text-slate-300">Alice prepares {"|ψ⟩"}</span>
              </div>
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-cyan block font-bold mb-1">2. Bell Meas</span>
                <span className="text-slate-300">Joint Alice measurement</span>
              </div>
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-cyan block font-bold mb-1">3. Pauli Apply</span>
                <span className="text-slate-300">Bob applies Pauli correction</span>
              </div>
              <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-cyan block font-bold mb-1">4. Fidelity Check</span>
                <span className="text-slate-300">Calculate {"F = |⟨ψ|ϕ⟩|²"}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: PROTOCOL SIMULATION */}
      {activeTab === 'simulation' && (
        <div className="space-y-6 animate-in fade-in">
          {/* Simulation Controls Form */}
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
                  <Play size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-cyber-primary">Configure Teleportation QDS Simulation</h3>
                  <p className="text-xs text-cyber-secondary">Set initial qubit state, Bell pair state, reproducible seed, & acceptance threshold</p>
                </div>
              </div>

              <button
                onClick={handleRunSimulation}
                disabled={isSimulating}
                className="bg-navy hover:bg-navy-light text-cyan border border-cyan/40 px-6 py-3 rounded-xl font-bold text-xs shadow-lg transition-all flex items-center space-x-2 cursor-pointer"
              >
                <Zap size={16} className="text-cyan" />
                <span>{isSimulating ? 'Simulating Teleportation...' : 'START QDS SIMULATION'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 text-xs">
              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Initial Signature Qubit State {"|ψ⟩"}</label>
                <select
                  value={initialState}
                  onChange={(e) => setInitialState(e.target.value)}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                >
                  <option value="|+>">|+⟩ = (|0⟩ + |1⟩)/√2 (Default Superposition)</option>
                  <option value="|0>">|0⟩ = Computational Basis 0</option>
                  <option value="|1>">|1⟩ = Computational Basis 1</option>
                  <option value="|->">|-⟩ = (|0⟩ - |1⟩)/√2 (Minus Phase State)</option>
                  <option value="|R>">|R⟩ = (|0⟩ + i|1⟩)/√2 (Right Circular)</option>
                  <option value="|L>">|L⟩ = (|0⟩ - i|1⟩)/√2 (Left Circular)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Bell Entanglement Pair State</label>
                <select
                  value={bellState}
                  onChange={(e) => setBellState(e.target.value)}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                >
                  <option value="|Phi+>">|Φ+⟩ = (|00⟩ + |11⟩)/√2 (Standard Default)</option>
                  <option value="|Phi->">|Φ-⟩ = (|00⟩ - |11⟩)/√2</option>
                  <option value="|Psi+>">|Ψ+⟩ = (|01⟩ + |10⟩)/√2</option>
                  <option value="|Psi->">|Ψ-⟩ = (|01⟩ - |10⟩)/√2</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Simulation Seed (Reproducibility)</label>
                <input
                  type="number"
                  value={simulationSeed}
                  onChange={(e) => setSimulationSeed(Number(e.target.value))}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Signer Identifier (Alice)</label>
                <input
                  type="text"
                  value={signerId}
                  onChange={(e) => setSignerId(e.target.value)}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Verifier Identifier (Bob)</label>
                <input
                  type="text"
                  value={verifierId}
                  onChange={(e) => setVerifierId(e.target.value)}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-bold text-cyber-primary focus:outline-none focus:border-cyan"
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between">
                  <label className="font-bold text-cyber-primary block">Acceptance Threshold ($F$)</label>
                  <span className="font-mono text-cyan font-bold">{acceptanceThreshold}</span>
                </div>
                <input
                  type="range"
                  min="0.5"
                  max="1.0"
                  step="0.01"
                  value={acceptanceThreshold}
                  onChange={(e) => setAcceptanceThreshold(Number(e.target.value))}
                  className="w-full accent-cyan cursor-pointer"
                />
              </div>
            </div>
          </div>

          {/* Simulation Progress Overlay */}
          {isSimulating && (
            <div className="p-6 bg-navy text-white rounded-2xl border border-cyan/40 shadow-2xl space-y-4 animate-in fade-in">
              <div className="flex items-center space-x-3">
                <Atom size={24} className="text-cyan animate-spin" />
                <div>
                  <h4 className="text-sm font-bold text-white uppercase tracking-wider">Teleportation Protocol Calculation</h4>
                  <p className="text-xs text-slate-300">{simMessage}...</p>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs font-bold text-slate-400 pt-1">
                <span>Mathematical Qubit Transformations</span>
                <span className="text-cyan">Step {simStep} of 8</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden border border-cyan/20">
                <div
                  className="bg-gradient-to-r from-cyan to-blue-500 h-full transition-all duration-300 rounded-full"
                  style={{ width: `${(simStep / 8) * 100}%` }}
                ></div>
              </div>
            </div>
          )}

          {/* Current Session Output Card */}
          {currentSession && (
            <div className="p-6 bg-slate-950 text-white rounded-2xl border border-cyan/30 shadow-2xl space-y-6 animate-in fade-in">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 rounded-xl bg-cyan/10 text-cyan flex items-center justify-center font-bold border border-cyan/40 shadow-inner">
                    <ShieldCheck size={28} />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="text-xl font-extrabold text-white tracking-tight">QDS TELEPORTATION SIMULATION RESULT</h4>
                      <span className="px-2.5 py-0.5 rounded font-mono text-[10px] font-bold bg-cyan/20 text-cyan border border-cyan/30">
                        {currentSession.session_id}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Seed: {currentSession.simulation_seed} | Signer: {currentSession.signer_id} | Verifier: {currentSession.verifier_id}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className={`px-4 py-2 rounded-xl font-black text-xs border shadow-lg ${
                    currentSession.verification_result === 'ACCEPT' ? 'bg-emerald-600 text-white border-emerald-700' : 'bg-red-600 text-white border-red-700'
                  }`}>
                    {currentSession.verification_result === 'ACCEPT' ? '✓ ACCEPTED (FIDELITY MATCH)' : '🚨 REJECTED (DISTURBANCE)'}
                  </div>

                  <button
                    onClick={() => handleRerunSession(currentSession.simulation_id)}
                    className="p-2 bg-slate-800 hover:bg-slate-700 text-cyan rounded-xl transition-colors border border-slate-700 cursor-pointer"
                    title="Re-run Simulation with Same Seed"
                  >
                    <RotateCcw size={18} />
                  </button>
                </div>
              </div>

              {/* Simulation Result Key Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">State Fidelity ($F$)</span>
                  <span className={`text-2xl font-black ${currentSession.fidelity >= 0.95 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {(currentSession.fidelity * 100).toFixed(2)}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Bell Classical Bits</span>
                  <span className="text-2xl font-mono font-black text-cyan">
                    {currentSession.measurement_bits}
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Pauli Correction Applied</span>
                  <span className="text-base font-bold text-amber-400">
                    {currentSession.pauli_correction}
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Bell Measurement Outcome</span>
                  <span className="text-xs font-bold text-slate-200">
                    {currentSession.measurement_outcome}
                  </span>
                </div>
              </div>

              {/* State Vector Amplitudes Comparison */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs font-mono">
                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-cyan font-bold block uppercase tracking-wider text-[11px]">Initial State {"|ψ⟩"} Amplitudes</span>
                  {(() => {
                    const vec = parseStateVector(currentSession.initial_state_vector);
                    return (
                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] space-y-1">
                        <div>α = {vec.alpha_real} + {vec.alpha_imag}i</div>
                        <div>β = {vec.beta_real} + {vec.beta_imag}i</div>
                        <div className="text-emerald-400 font-bold">P(0) = {vec.prob_0.toFixed(4)}, P(1) = {vec.prob_1.toFixed(4)}</div>
                      </div>
                    );
                  })()}
                </div>

                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-cyan font-bold block uppercase tracking-wider text-[11px]">Reconstructed State {"|ϕ⟩"} Amplitudes</span>
                  {(() => {
                    const vec = parseStateVector(currentSession.reconstructed_state);
                    return (
                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] space-y-1">
                        <div>α = {vec.alpha_real} + {vec.alpha_imag}i</div>
                        <div>β = {vec.beta_real} + {vec.beta_imag}i</div>
                        <div className="text-emerald-400 font-bold">P(0) = {vec.prob_0.toFixed(4)}, P(1) = {vec.prob_1.toFixed(4)}</div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 3: BELL STATES SIMULATION */}
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

      {/* SECTION 4: TELEPORTATION VISUALIZATION DIAGRAM */}
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
            {/* Visual Workflow Steps */}
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
                  Bell Measurement<br/>Classical Bits m₁ m₂
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
                  Fidelity Check<br/>$F = |\langle\psi|\phi\rangle|^2 \ge 0.95$
                </div>
              </div>
            </div>

            {/* Teleportation Pauli Correction Table */}
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

      {/* SECTION 5: ATTACK SIMULATION UI */}
      {activeTab === 'attacks' && (
        <div className="space-y-6 animate-in fade-in">
          <div className="bg-white p-6 rounded-2xl border border-cyber-border shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-xl bg-red-600 text-white flex items-center justify-center font-bold">
                  <ShieldAlert size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-cyber-primary">Configure Quantum Channel & Forgery Attack Experiments</h3>
                  <p className="text-xs text-cyber-secondary">Simulate multi-trial channel disturbance, forgery, impersonation, & replay attacks</p>
                </div>
              </div>

              <button
                onClick={handleRunAttackSimulation}
                disabled={isAttacking}
                className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-xl font-bold text-xs shadow-lg transition-all flex items-center space-x-2 cursor-pointer"
              >
                <ShieldAlert size={16} />
                <span>{isAttacking ? 'Simulating Attack Trials...' : 'RUN ATTACK SIMULATION'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 text-xs">
              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Attack Simulation Model</label>
                <select
                  value={attackType}
                  onChange={(e) => setAttackType(e.target.value)}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-bold text-cyber-primary focus:outline-none focus:border-red-500"
                >
                  <option value="BIT_FLIP">BIT_FLIP (Pauli X Channel Noise)</option>
                  <option value="PHASE_FLIP">PHASE_FLIP (Pauli Z Phase Noise)</option>
                  <option value="BIT_PHASE_FLIP">BIT_PHASE_FLIP (Pauli Y Noise)</option>
                  <option value="DEPOLARIZING_CHANNEL">DEPOLARIZING_CHANNEL (Random I/X/Y/Z)</option>
                  <option value="INTERCEPT_MEASURE_RESEND">INTERCEPT_MEASURE_RESEND (Eavesdropper Collapse)</option>
                  <option value="RANDOM_STATE_FORGERY">RANDOM_STATE_FORGERY (Random Attacker Qubit)</option>
                  <option value="BASIS_STATE_FORGERY">BASIS_STATE_FORGERY (Guessed Computational State)</option>
                  <option value="REPLAY_ATTEMPT">REPLAY_ATTEMPT (Session Reuse Attack)</option>
                  <option value="IMPERSONATION_ATTEMPT">IMPERSONATION_ATTEMPT (Signer ID Mismatch)</option>
                </select>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between">
                  <label className="font-bold text-cyber-primary block">Attack Probability ($p$)</label>
                  <span className="font-mono text-red-600 font-bold">{(attackProbability * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={attackProbability}
                  onChange={(e) => setAttackProbability(Number(e.target.value))}
                  className="w-full accent-red-600 cursor-pointer"
                />
              </div>

              <div className="space-y-2">
                <label className="font-bold text-cyber-primary block">Number of Simulation Trials ($N$)</label>
                <input
                  type="number"
                  min="10"
                  max="1000"
                  value={numberOfTrials}
                  onChange={(e) => setNumberOfTrials(Number(e.target.value))}
                  className="w-full p-3 rounded-xl border border-cyber-border bg-slate-50 font-mono font-bold text-cyber-primary focus:outline-none focus:border-red-500"
                />
              </div>
            </div>
          </div>

          {/* Attack Result Display */}
          {currentAttackResult && (
            <div className="p-6 bg-slate-950 text-white rounded-2xl border border-red-500/40 shadow-2xl space-y-6 animate-in fade-in">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-12 h-12 rounded-xl bg-red-500/20 text-red-400 flex items-center justify-center font-bold border border-red-500/30">
                    <ShieldAlert size={28} />
                  </div>
                  <div>
                    <h4 className="text-xl font-black text-white tracking-tight">ATTACK SIMULATION EXPERIMENT RESULTS</h4>
                    <p className="text-xs text-slate-400">
                      Model: {currentAttackResult.attack_type} | Trials: {currentAttackResult.number_of_trials} | Exec Time: {currentAttackResult.execution_time_ms} ms
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="px-4 py-2 rounded-xl font-black text-xs bg-red-600 text-white border border-red-700 shadow-lg">
                    DETECTION RATE: {currentAttackResult.detection_rate}%
                  </div>
                </div>
              </div>

              {/* Attack Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Mean State Fidelity</span>
                  <span className="text-2xl font-black text-cyan">
                    {(currentAttackResult.mean_fidelity * 100).toFixed(1)}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Simulated Forgery / FAR</span>
                  <span className="text-2xl font-black text-amber-400">
                    {currentAttackResult.false_acceptance_rate}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Rejection Rate</span>
                  <span className="text-2xl font-black text-red-400">
                    {currentAttackResult.rejection_rate}%
                  </span>
                </div>

                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-semibold block text-[10px]">Measurement Error Rate</span>
                  <span className="text-2xl font-black text-blue-400">
                    {currentAttackResult.measurement_error_rate}%
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 6: MEASUREMENT & STATISTICAL ANALYSIS */}
      {activeTab === 'measurement' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <BarChart3 size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Born-Rule Measurement & Statistical Distributions</h3>
              <p className="text-xs text-cyber-secondary">Expected vs observed computational basis measurement outcome probabilities</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            <div className="p-5 bg-slate-900 text-white rounded-xl border border-slate-800 space-y-3 font-mono">
              <span className="text-cyan font-bold block text-sm border-b border-slate-800 pb-2">Theoretical Born-Rule Probabilities</span>
              <div className="space-y-2 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">$P(0) = |\alpha|^2$:</span>
                  <span className="font-bold text-emerald-400">50.0%</span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div className="bg-emerald-500 h-full rounded-full" style={{ width: '50%' }}></div>
                </div>

                <div className="flex justify-between pt-2">
                  <span className="text-slate-400">$P(1) = |\beta|^2$:</span>
                  <span className="font-bold text-cyan">50.0%</span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div className="bg-cyan h-full rounded-full" style={{ width: '50%' }}></div>
                </div>
              </div>
            </div>

            <div className="p-5 bg-slate-900 text-white rounded-xl border border-slate-800 space-y-3 font-mono">
              <span className="text-cyan font-bold block text-sm border-b border-slate-800 pb-2">Observed Trial Measurements</span>
              <div className="space-y-2 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Observed State $|0\rangle$ Frequency:</span>
                  <span className="font-bold text-emerald-400">
                    {currentAttackResult ? (currentAttackResult.observed_distribution ? `${(JSON.parse(currentAttackResult.observed_distribution).prob_0 * 100).toFixed(1)}%` : '50.0%') : '50.0%'}
                  </span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div className="bg-emerald-500 h-full rounded-full" style={{ width: '50%' }}></div>
                </div>

                <div className="flex justify-between pt-2">
                  <span className="text-slate-400">Observed State $|1\rangle$ Frequency:</span>
                  <span className="font-bold text-cyan">
                    {currentAttackResult ? (currentAttackResult.observed_distribution ? `${(JSON.parse(currentAttackResult.observed_distribution).prob_1 * 100).toFixed(1)}%` : '50.0%') : '50.0%'}
                  </span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div className="bg-cyan h-full rounded-full" style={{ width: '50%' }}></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 7: PARAMETERS & PERFORMANCE METRICS */}
      {activeTab === 'metrics' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Sliders size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">Algorithm Parameters, Performance & Computational Complexity</h3>
              <p className="text-xs text-cyber-secondary">Simulation protocol parameters, execution time benchmarks, detection accuracy, & theoretical complexity analysis</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary uppercase tracking-wider border-b border-slate-200 pb-2">Time Complexity Analysis</h4>
              <p className="text-slate-600 leading-relaxed">
                {metrics?.time_complexity_explanation || "O(N × 2^n) matrix-vector transformations per qubit state simulation trial."}
              </p>
            </div>

            <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
              <h4 className="text-sm font-bold text-cyber-primary uppercase tracking-wider border-b border-slate-200 pb-2">Space Complexity Analysis</h4>
              <p className="text-slate-600 leading-relaxed">
                {metrics?.space_complexity_explanation || "O(2^n) state vector amplitude storage. 2-qubit Hilbert space requires exact 4 complex float numbers."}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 8: SIMULATION HISTORY & REPRODUCIBILITY */}
      {activeTab === 'history' && (
        <div className="bg-white p-8 rounded-2xl border border-cyber-border shadow-sm space-y-6 animate-in fade-in">
          <div className="flex items-center space-x-3 border-b border-cyber-border pb-4">
            <div className="w-10 h-10 rounded-xl bg-navy text-cyan flex items-center justify-center font-bold">
              <Clock size={22} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-cyber-primary">QDS Simulation History & Seed Reproducibility Log</h3>
              <p className="text-xs text-cyber-secondary">Historical session records with exact seed re-running for 100% mathematical reproducibility</p>
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
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border">
                {history.length > 0 ? (
                  history.map((s) => (
                    <tr key={s.simulation_id} className="hover:bg-slate-50/80 font-mono">
                      <td className="p-3 font-bold text-cyber-primary">{s.session_id}</td>
                      <td className="p-3 text-cyan-hover font-bold">{s.simulation_seed}</td>
                      <td className="p-3">{s.initial_state}</td>
                      <td className="p-3">{s.bell_state}</td>
                      <td className="p-3 font-bold text-amber-600">{s.pauli_correction}</td>
                      <td className="p-3 font-bold">{(s.fidelity * 100).toFixed(1)}%</td>
                      <td className="p-3 font-sans">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          s.verification_result === 'ACCEPT' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                        }`}>
                          {s.verification_result}
                        </span>
                      </td>
                      <td className="p-3 text-right font-sans">
                        <button
                          onClick={() => handleRerunSession(s.simulation_id)}
                          className="px-3 py-1 bg-navy hover:bg-navy-light text-cyan rounded-lg font-bold text-[11px] border border-cyan/30 transition-all cursor-pointer"
                        >
                          Re-run with Seed
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-slate-400">
                      No QDS simulation sessions recorded yet. Start a simulation from tab 2.
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
