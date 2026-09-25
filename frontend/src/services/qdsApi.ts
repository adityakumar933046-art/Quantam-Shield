import { api } from './api';

// ==============================================================================
// TYPES & INTERFACES FOR MULTI-QUBIT QDS REST API
// ==============================================================================

export interface QDSHealthResponse {
  status: string;
  protocol: string;
  quantum_engine: string;
  statistical_analysis: string;
  attack_pipeline: string;
  ai_ml: boolean;
}

export interface QDSThresholdsResponse {
  verification_threshold: number;
  repudiation_threshold: number;
  channel_disturbance_threshold: number;
  minimum_acceptable_fidelity: number;
  distribution_distance_anomaly_threshold: number;
  chi_square_min_sample_size: number;
  chi_square_min_expected_count: number;
}

export interface QDSKeyGenerationRequest {
  key_length: number;
  seed?: number | null;
}

export interface QDSKeyGenerationResponse {
  key_id: string;
  key_length: number;
  protocol_version: string;
  public_key: number[][]; // [Re(alpha), Im(alpha), Re(beta), Im(beta)] for each qubit
  basis_information: string[]; // e.g. ["Z", "X", "Z", ...]
  seed?: number | null;
}

export interface QDSSignRequest {
  key_id: string;
  message_hash: string;
  seed?: number | null;
}

export interface QDSSignResponse {
  signature_id: string;
  message_hash: string;
  qubit_count: number;
  protocol_version: string;
}

export interface QDSTeleportRequest {
  signature_id: string;
  seed?: number | null;
}

export interface QDSTeleportResponse {
  signature_id: string;
  qubit_count: number;
  average_fidelity: number;
  fidelities: number[];
  measurement_bits: string[];
  pauli_corrections: string[];
  success: boolean;
}

export interface QDSVerifyRequest {
  signature_id: string;
  threshold?: number;
}

export interface QDSVerificationMetrics {
  accepted: boolean;
  mismatch_rate: number;
  threshold: number;
  matches: number;
  mismatches: number;
}

export interface QDSStatisticsMetrics {
  accuracy: number;
  distribution_distance: number;
  chi_square: number | null;
  chi_square_status: string;
}

export interface QDSThreatInfo {
  detected: boolean;
  type: string | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
}

export interface QDSRiskInfo {
  score: number;
  tier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  contributing_factors?: string[];
}

export interface QDSVerifyResponse {
  verification: QDSVerificationMetrics;
  statistics: QDSStatisticsMetrics;
  threat: QDSThreatInfo;
  risk: QDSRiskInfo;
}

export type QDSAttackType =
  | 'none'
  | 'random_state_substitution'
  | 'bit_flip'
  | 'phase_flip'
  | 'intercept_resend';

export interface QDSMultiQubitAttackRequest {
  message_hash: string;
  attack_type: QDSAttackType;
  key_length: number;
  seed?: number | null;
}

export interface QDSMultiQubitAttackResponse {
  protocol: string;
  attack_type: QDSAttackType;
  message_hash: string;
  key_length: number;
  seed_used: number | null;
  teleportation: {
    initial_average_fidelity: number;
    attacked_average_fidelity: number;
    disturbance: number;
  };
  verification: QDSVerificationMetrics;
  statistics: QDSStatisticsMetrics;
  threat: QDSThreatInfo;
  risk: QDSRiskInfo;
  evidence?: {
    anomaly_detected: boolean;
    statistical_anomaly: boolean;
    channel_disturbance: boolean;
    forgery_risk: number;
    chi_square_p_value?: number | null;
  };
}

export interface QDSAttackScenarioItem {
  attack_type: QDSAttackType;
  fidelity: number;
  mismatch_rate: number;
  distribution_distance: number;
  accepted: boolean;
  threat_detected: boolean;
  threat_type: string | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  risk_tier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface QDSAttackScenariosSummary {
  total_scenarios: number;
  attacks_evaluated: number;
  attacks_detected: number;
  detection_rate_percentage: number;
  honest_baseline_fidelity: number;
  average_attacked_fidelity: number;
  thresholds: QDSThresholdsResponse;
}

export interface QDSAttackScenarioRequest {
  message_hash?: string;
  key_length?: number;
  seed?: number | null;
}

export interface QDSAttackScenariosResponse {
  protocol: string;
  message_hash: string;
  key_length: number;
  seed_used: number | null;
  scenarios: QDSAttackScenarioItem[];
  summary: QDSAttackScenariosSummary;
}

// ==============================================================================
// ERROR UTILITY
// ==============================================================================

export const extractErrorMessage = (err: unknown, fallback = 'Operation failed'): string => {
  if (!err) return fallback;
  const anyErr = err as {
    response?: { data?: { detail?: string | Array<{ loc?: string[]; msg?: string }> } };
    message?: string;
  };

  const detail = anyErr.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => `${d.loc?.slice(-1)[0] || 'field'}: ${d.msg}`).join('; ');
  }
  return anyErr.message || fallback;
};

// ==============================================================================
// API SERVICE METHODS
// ==============================================================================

export const getQDSHealth = async (): Promise<QDSHealthResponse> => {
  const res = await api.get<QDSHealthResponse>('/qds/health');
  return res.data;
};

export const getQDSThresholds = async (): Promise<QDSThresholdsResponse> => {
  const res = await api.get<QDSThresholdsResponse>('/qds/thresholds');
  return res.data;
};

export const generateQDSKey = async (req: QDSKeyGenerationRequest): Promise<QDSKeyGenerationResponse> => {
  const res = await api.post<QDSKeyGenerationResponse>('/qds/key-generation', req);
  return res.data;
};

export const signQDS = async (req: QDSSignRequest): Promise<QDSSignResponse> => {
  const res = await api.post<QDSSignResponse>('/qds/sign', req);
  return res.data;
};

export const teleportQDS = async (req: QDSTeleportRequest): Promise<QDSTeleportResponse> => {
  const res = await api.post<QDSTeleportResponse>('/qds/teleport', req);
  return res.data;
};

export const verifyQDS = async (req: QDSVerifyRequest): Promise<QDSVerifyResponse> => {
  const res = await api.post<QDSVerifyResponse>('/qds/verify', req);
  return res.data;
};

export const simulateQDSAttack = async (
  req: QDSMultiQubitAttackRequest
): Promise<QDSMultiQubitAttackResponse> => {
  const res = await api.post<QDSMultiQubitAttackResponse>('/qds/attack-simulation', req);
  return res.data;
};

export const runQDSAttackScenarios = async (
  req: QDSAttackScenarioRequest
): Promise<QDSAttackScenariosResponse> => {
  const res = await api.post<QDSAttackScenariosResponse>('/qds/attack-scenarios', req);
  return res.data;
};
