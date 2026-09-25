"""
Deterministic Threat Detection Rule Engine and Quantum Channel Simulation.

Module: quantum_engine.threat_detector
Implements deterministic, rule-based threat evaluation across 8 categories:
1. DIGITAL_SIGNATURE_FORGERY
2. DOCUMENT_TAMPERING
3. REPLAY_ATTACK
4. IMPERSONATION
5. UNAUTHORIZED_VERIFICATION
6. SIGNATURE_MANIPULATION
7. CERTIFICATE_PROBLEM
8. QUANTUM_CHANNEL_SIMULATION (Isolated Simulation Mode)

Contains NO AI, NO ML, NO random production security decisions.
"""

from typing import Dict, Any, List, Optional, Sequence, Union
import numpy as np

from quantum_engine.bell_states import (
    BELL_PHI_PLUS,
    BELL_PHI_MINUS,
    BELL_PSI_PLUS,
    BELL_PSI_MINUS,
    get_bell_state,
    bell_state_fidelity
)
from quantum_engine.pauli_operations import (
    apply_x,
    apply_y,
    apply_z,
    calculate_state_change
)
from quantum_engine.states import STATE_0, STATE_1, normalize_state, state_fidelity
from quantum_engine.metrics import calculate_deviation, calculate_state_disturbance
from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    QDS_REPUDIATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD
)


def evaluate_deterministic_threats(
    security_parameters: Dict[str, float],
    state_disturbance: float = 0.0,
    pauli_disturbances: Optional[Dict[str, float]] = None,
    forgery_risk: Optional[Dict[str, Any]] = None,
    metadata_details: Optional[Dict[str, Any]] = None,
    audit_events: Optional[List[str]] = None,
    qds_evidence: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates rule-based threat categories from verified cryptographic data,
    state disturbance, and Pauli operators.
    Returns a list of detected threat dictionaries.
    """
    threats: List[Dict[str, Any]] = []

    sig_val = security_parameters.get("signature_validity", 1.0)
    hash_integ = security_parameters.get("hash_integrity", 1.0)
    pk_val = security_parameters.get("public_key_validity", 1.0)
    cert_val = security_parameters.get("certificate_validity", 1.0)
    meta_val = security_parameters.get("metadata_consistency", 1.0)
    sig_cons = security_parameters.get("signature_consistency", 1.0)
    replay_safe = security_parameters.get("replay_safety", 1.0)
    act_safe = security_parameters.get("activity_safety", 1.0)

    p_dict = pauli_disturbances or {}
    dist_x = p_dict.get("pauli_x_disturbance", 0.0)
    dist_z = p_dict.get("pauli_z_disturbance", 0.0)
    f_dict = forgery_risk or {}
    f_score = f_dict.get("forgery_risk_percentage", 0.0)

    # -------------------------------------------------------------------------
    # 1. DIGITAL_SIGNATURE_FORGERY
    # Condition: Mathematical verification failed AND signature was present
    # (Do NOT flag if document is simply untracked/unsigned, where sig_val == 0.5)
    # -------------------------------------------------------------------------
    if sig_val < 0.2 and dist_x >= 0.50:
        threats.append({
            "threat_category": "DIGITAL_SIGNATURE_FORGERY",
            "threat_type": "DIGITAL_SIGNATURE_FORGERY",
            "severity": "CRITICAL",
            "threat_score": min(100.0, max(85.0, f_score)),
            "confidence": 0.95,
            "threat_status": "OPEN",
            "description": (
                "Cryptographic signature mathematical verification failed. "
                f"Pauli X state inversion disturbance D_X={dist_x*100:.1f}%. "
                "The signature does not decrypt to the expected document digest."
            ),
            "evidence": {
                "signature_validity": sig_val,
                "pauli_x_disturbance": dist_x,
                "forgery_risk_score": f_score
            }
        })

    # -------------------------------------------------------------------------
    # 2. DOCUMENT_TAMPERING
    # Condition: Content hash differs from original signed hash
    # -------------------------------------------------------------------------
    if hash_integ < 0.2:
        threats.append({
            "threat_category": "DOCUMENT_TAMPERING",
            "threat_type": "DOCUMENT_TAMPERING",
            "severity": "CRITICAL",
            "threat_score": 95.0,
            "confidence": 0.98,
            "threat_status": "OPEN",
            "description": (
                "Document content modification detected after digital signature creation. "
                "The current SHA-256 digest does not match the canonical signed digest."
            ),
            "evidence": {
                "hash_integrity": hash_integ,
                "state_disturbance": state_disturbance
            }
        })

    # -------------------------------------------------------------------------
    # 3. REPLAY_ATTACK
    # Condition: Replay safety indicator is 0.0 (high-frequency verification bursts)
    # -------------------------------------------------------------------------
    if replay_safe < 0.3:
        threats.append({
            "threat_category": "REPLAY_ATTACK",
            "threat_type": "REPLAY_ATTACK",
            "severity": "HIGH",
            "threat_score": 80.0,
            "confidence": 0.90,
            "threat_status": "OPEN",
            "description": (
                "Suspicious document verification replay pattern detected. Rapid verification requests "
                "exceeded the platform security threshold within the active observation window."
            ),
            "evidence": {
                "replay_safety": replay_safe
            }
        })

    # -------------------------------------------------------------------------
    # 4. IMPERSONATION
    # Condition: Signer name and certificate identity mismatch
    # -------------------------------------------------------------------------
    if meta_val < 0.5:
        threats.append({
            "threat_category": "IMPERSONATION",
            "threat_type": "IMPERSONATION",
            "severity": "HIGH",
            "threat_score": 75.0,
            "confidence": 0.85,
            "threat_status": "OPEN",
            "description": (
                "Signer identity impersonation anomaly detected. Signer claimed identity "
                "or metadata differs from certificate Subject Distinguished Name."
            ),
            "evidence": {
                "metadata_consistency": meta_val,
                "pauli_z_disturbance": dist_z
            }
        })

    # -------------------------------------------------------------------------
    # 5. UNAUTHORIZED_VERIFICATION
    # Condition: Audit trail violations or unauthorized access attempts
    # -------------------------------------------------------------------------
    if act_safe < 0.5:
        threats.append({
            "threat_category": "UNAUTHORIZED_VERIFICATION",
            "threat_type": "UNAUTHORIZED_VERIFICATION",
            "severity": "HIGH",
            "threat_score": 70.0,
            "confidence": 0.88,
            "threat_status": "OPEN",
            "description": (
                "Unauthorized verification or policy access violation detected in audit logs."
            ),
            "evidence": {
                "activity_safety": act_safe
            }
        })

    # -------------------------------------------------------------------------
    # 6. SIGNATURE_MANIPULATION
    # Condition: Conflicting reuse of same signature across different content hashes
    # -------------------------------------------------------------------------
    if sig_cons < 0.3:
        threats.append({
            "threat_category": "SIGNATURE_MANIPULATION",
            "threat_type": "SIGNATURE_MANIPULATION",
            "severity": "CRITICAL",
            "threat_score": 90.0,
            "confidence": 0.92,
            "threat_status": "OPEN",
            "description": (
                "Signature reuse anomaly detected. This cryptographic signature fingerprint is attached "
                "to distinct document hashes across separate analysis records."
            ),
            "evidence": {
                "signature_consistency": sig_cons
            }
        })

    # -------------------------------------------------------------------------
    # 7. CERTIFICATE_PROBLEM
    # Condition: Certificate expired, untrusted, or revoked
    # -------------------------------------------------------------------------
    if cert_val < 0.4:
        threats.append({
            "threat_category": "CERTIFICATE_PROBLEM",
            "threat_type": "CERTIFICATE_PROBLEM",
            "severity": "MEDIUM",
            "threat_score": 60.0,
            "confidence": 0.90,
            "threat_status": "OPEN",
            "description": (
                "Certificate security validation problem. Certificate has expired, is untrusted, "
                "or exhibits chain verification issues."
            ),
            "evidence": {
                "certificate_validity": cert_val
            }
        })

    # -------------------------------------------------------------------------
    # 8. QDS PROTOCOL THREAT INTEGRATION (If QDS Evidence Provided)
    # -------------------------------------------------------------------------
    if qds_evidence is not None:
        qds_eval = evaluate_qds_threats(qds_evidence, replay_safe=replay_safe, act_safe=act_safe)
        if qds_eval["threat_detected"]:
            cat = qds_eval["threat_type"]
            # Avoid duplicate category if already flagged by classical rules
            if not any(t.get("threat_category") == cat for t in threats):
                threats.append({
                    "threat_category": cat,
                    "threat_type": cat,
                    "severity": qds_eval["severity"],
                    "threat_score": 90.0 if qds_eval["severity"] == "CRITICAL" else 75.0,
                    "confidence": 0.95,
                    "threat_status": "OPEN",
                    "description": qds_eval["explanation"],
                    "evidence": qds_eval["confidence_evidence"]
                })

    return threats


# ==============================================================================
# 8. QUANTUM CHANNEL SIMULATION (STRICTLY SEPARATED SIMULATION MODE)
# ==============================================================================

def simulate_quantum_channel(
    scenario: str = "NO_ATTACK",
    bell_state_name: str = "phi_plus"
) -> Dict[str, Any]:
    """
    SIMULATION-ONLY MODULE:
    Simulates a mathematical Quantum Channel transmission of a Bell State.
    Models Pauli noise, eavesdropper interception, and detector disturbance.

    Scientific Rule:
    Strictly decoupled from classical document verification. This simulates
    theoretical quantum communication channel behavior in software.

    Supported Scenarios:
    - NO_ATTACK
    - PAULI_X_DISTURBANCE
    - PAULI_Y_DISTURBANCE
    - PAULI_Z_DISTURBANCE
    - INTERCEPTION_SIMULATION
    - MEASUREMENT_DISTURBANCE
    """
    scen_upper = scenario.upper()
    expected_bell = get_bell_state(bell_state_name)

    # 2-qubit basis representations
    if scen_upper == "NO_ATTACK":
        observed_bell = expected_bell.copy()
        attack_type = "NONE"
        explanation = "Ideal quantum channel. Bell state transmitted with zero disturbance (F=1.0)."
        threat_detected = False
    elif scen_upper == "PAULI_X_DISTURBANCE":
        # Apply Pauli X to qubit 1: (X x I)|Phi+> = |Psi+>
        op_matrix = np.kron(np.array([[0, 1], [1, 0]], dtype=np.complex128), np.eye(2, dtype=np.complex128))
        observed_bell = np.dot(op_matrix, expected_bell)
        attack_type = "BIT_FLIP"
        explanation = "Pauli X bit-flip noise detected on channel qubit 1 (transforms |Phi+> to |Psi+>)."
        threat_detected = True
    elif scen_upper == "PAULI_Z_DISTURBANCE":
        # Apply Pauli Z to qubit 1: (Z x I)|Phi+> = |Phi->
        op_matrix = np.kron(np.array([[1, 0], [0, -1]], dtype=np.complex128), np.eye(2, dtype=np.complex128))
        observed_bell = np.dot(op_matrix, expected_bell)
        attack_type = "PHASE_FLIP"
        explanation = "Pauli Z phase-flip noise detected on channel (transforms |Phi+> to |Phi->)."
        threat_detected = True
    elif scen_upper == "PAULI_Y_DISTURBANCE":
        # Apply Pauli Y to qubit 1: (Y x I)|Phi+> = -i|Psi->
        op_matrix = np.kron(np.array([[0, -1j], [1j, 0]], dtype=np.complex128), np.eye(2, dtype=np.complex128))
        observed_bell = np.dot(op_matrix, expected_bell)
        attack_type = "BIT_AND_PHASE_FLIP"
        explanation = "Pauli Y compound bit-and-phase noise detected on channel."
        threat_detected = True
    elif scen_upper == "INTERCEPTION_SIMULATION":
        # Intercept-resend collapse onto computational basis |00>
        observed_bell = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.complex128)
        attack_type = "EAVESDROPPER_INTERCEPTION"
        explanation = "Eavesdropper projective measurement collapsed entangled Bell pair to pure classical state |00>."
        threat_detected = True
    elif scen_upper == "MEASUREMENT_DISTURBANCE":
        # Partial dephasing
        observed_bell = normalize_state(expected_bell * 0.707 + np.array([0, 0.5, 0.5, 0], dtype=np.complex128))
        attack_type = "MEASUREMENT_DECOHERENCE"
        explanation = "Decoherence and detector measurement disturbance observed on quantum channel."
        threat_detected = True
    else:
        observed_bell = expected_bell.copy()
        attack_type = "UNKNOWN"
        explanation = f"Unrecognized simulation scenario '{scenario}', defaulting to intact channel."
        threat_detected = False

    # Fidelity and Disturbance
    fid = bell_state_fidelity(expected_bell, observed_bell)
    disturbance = max(0.0, min(1.0, 1.0 - fid))

    return {
        "simulation_mode": True,
        "scenario": scen_upper,
        "attack_type": attack_type,
        "bell_state": bell_state_name,
        "fidelity": round(float(fid), 6),
        "disturbance_score": round(float(disturbance), 6),
        "threat_detected": threat_detected,
        "explanation": explanation,
        "scientific_disclaimer": "This is a theoretical software mathematical simulation of a quantum channel; no real quantum hardware was used."
    }


# ==============================================================================
# 9. QDS THREAT EVIDENCE & STATISTICAL CLASSIFICATION
# ==============================================================================

def build_qds_threat_evidence(
    teleportation_average_fidelity: float,
    mismatch_rate: float,
    measurement_accuracy: float,
    distribution_distance: float,
    chi_square_statistic: Optional[float] = None,
    intercept_resend_indicator: bool = False,
    pauli_error_indicator: bool = False,
    non_repudiation_result: Optional[Dict[str, Any]] = None,
    verification_threshold: float = QDS_VERIFICATION_THRESHOLD,
    repudiation_threshold: float = QDS_REPUDIATION_THRESHOLD,
    channel_disturbance_threshold: float = QDS_CHANNEL_DISTURBANCE_THRESHOLD
) -> Dict[str, Any]:
    """
    Constructs a structured QDS threat evidence object (Part 6).

    Integrates teleportation fidelity, projective measurement mismatch rates,
    distribution divergence, chi-square goodness-of-fit, and attack indicators
    into a standardized evidence payload for deterministic threat evaluation.
    """
    disturbance = max(0.0, min(1.0, 1.0 - float(teleportation_average_fidelity)))
    return {
        "teleportation_average_fidelity": round(float(teleportation_average_fidelity), 6),
        "state_disturbance": round(float(disturbance), 6),
        "mismatch_rate": round(float(mismatch_rate), 6),
        "measurement_accuracy": round(float(measurement_accuracy), 6),
        "distribution_distance": round(float(distribution_distance), 6),
        "chi_square_statistic": round(float(chi_square_statistic), 6) if chi_square_statistic is not None else None,
        "intercept_resend_indicator": bool(intercept_resend_indicator),
        "pauli_error_indicator": bool(pauli_error_indicator),
        "non_repudiation_result": non_repudiation_result,
        "verification_threshold": float(verification_threshold),
        "repudiation_threshold": float(repudiation_threshold),
        "channel_disturbance_threshold": float(channel_disturbance_threshold),
    }


def evaluate_qds_threats(
    qds_evidence: Dict[str, Any],
    replay_safe: float = 1.0,
    act_safe: float = 1.0
) -> Dict[str, Any]:
    """
    Evaluates threat classification from QDS statistical evidence and indicators (Part 7, Part 11).

    Classification Logic:
    1. Signature verification rejected (mismatch_rate > verification_threshold)
       -> DIGITAL_SIGNATURE_FORGERY
    2. Significant intercept-resend disturbance or intercept_resend_indicator
       -> QUANTUM_CHANNEL_MANIPULATION
    3. Significant Pauli channel disturbance or pauli_error_indicator
       -> QUANTUM_CHANNEL_MANIPULATION
    4. Non-repudiation disagreement (cross-verifier mismatch > repudiation_threshold)
       -> DIGITAL_SIGNATURE_FORGERY
    5. Replay evidence (replay_safe < 0.3)
       -> REPLAY_ATTACK
    6. Unauthorized verification (act_safe < 0.5)
       -> UNAUTHORIZED_VERIFICATION

    IMPORTANT:
    Does NOT classify an attack merely because fidelity is slightly below 1.0.
    Small numerical/statistical deviations are expected and allowed up to explicit thresholds.
    """
    mismatch_rate = float(qds_evidence.get("mismatch_rate", 0.0))
    fidelity = float(qds_evidence.get("teleportation_average_fidelity", 1.0))
    disturbance = float(qds_evidence.get("state_disturbance", max(0.0, 1.0 - fidelity)))
    dist_distance = float(qds_evidence.get("distribution_distance", 0.0))
    chi_sq = qds_evidence.get("chi_square_statistic")
    intercept_resend = bool(qds_evidence.get("intercept_resend_indicator", False))
    pauli_error = bool(qds_evidence.get("pauli_error_indicator", False))
    non_rep = qds_evidence.get("non_repudiation_result")

    t_ver = float(qds_evidence.get("verification_threshold", QDS_VERIFICATION_THRESHOLD))
    t_rep = float(qds_evidence.get("repudiation_threshold", QDS_REPUDIATION_THRESHOLD))
    t_dist = float(qds_evidence.get("channel_disturbance_threshold", QDS_CHANNEL_DISTURBANCE_THRESHOLD))

    threat_detected = False
    threat_type = "NONE"
    severity = "LOW"
    explanation_parts = []

    # 1. Verification Mismatch / Forgery
    if mismatch_rate > t_ver:
        threat_detected = True
        threat_type = "DIGITAL_SIGNATURE_FORGERY"
        severity = "CRITICAL" if mismatch_rate >= 0.40 else "HIGH"
        explanation_parts.append(
            f"QDS signature verification rejected: measurement mismatch rate epsilon={mismatch_rate:.4f} "
            f"exceeds security threshold T_VER={t_ver:.2f}."
        )

    # 2. Intercept-Resend / Channel Manipulation
    if intercept_resend or disturbance >= t_dist:
        threat_detected = True
        threat_type = "QUANTUM_CHANNEL_MANIPULATION"
        severity = "CRITICAL" if disturbance >= 0.50 else "HIGH"
        explanation_parts.append(
            f"Detected anomaly consistent with quantum channel manipulation: "
            f"channel disturbance D={disturbance:.4f} exceeds threshold T_DIST={t_dist:.2f}."
        )

    # 3. Pauli Channel Disturbance
    if pauli_error and disturbance >= t_dist:
        threat_detected = True
        threat_type = "QUANTUM_CHANNEL_MANIPULATION"
        severity = "HIGH"
        explanation_parts.append(
            f"Pauli channel disturbance detected: D={disturbance:.4f}."
        )

    # 4. Non-Repudiation Discrepancy
    if non_rep is not None:
        rep_mismatch = float(non_rep.get("mismatch_rate", 0.0))
        consistent = bool(non_rep.get("consistent", rep_mismatch <= t_rep))
        if not consistent or rep_mismatch > t_rep:
            threat_detected = True
            threat_type = "DIGITAL_SIGNATURE_FORGERY"
            severity = "HIGH"
            explanation_parts.append(
                f"Non-repudiation failure: cross-receiver mismatch rate {rep_mismatch:.4f} "
                f"exceeds threshold T_REP={t_rep:.2f}."
            )

    # 5. Replay Evidence
    if replay_safe < 0.3:
        threat_detected = True
        threat_type = "REPLAY_ATTACK"
        severity = "HIGH"
        explanation_parts.append(
            f"Replay attack pattern detected: replay safety index {replay_safe:.2f} < 0.30."
        )

    # 6. Unauthorized Verification
    if act_safe < 0.5:
        threat_detected = True
        threat_type = "UNAUTHORIZED_VERIFICATION"
        severity = "HIGH"
        explanation_parts.append(
            f"Unauthorized verification access attempt detected in audit log."
        )

    if not threat_detected:
        explanation = (
            f"QDS verification authentic: mismatch rate epsilon={mismatch_rate:.4f} <= {t_ver:.2f}, "
            f"channel fidelity F={fidelity:.4f} (disturbance D={disturbance:.4f} < {t_dist:.2f}). "
            "No quantum channel manipulation or forgery detected."
        )
    else:
        explanation = " | ".join(explanation_parts)

    return {
        "threat_detected": threat_detected,
        "threat_type": threat_type,
        "severity": severity if threat_detected else "LOW",
        "confidence_evidence": {
            "mismatch_rate": mismatch_rate,
            "fidelity": fidelity,
            "disturbance": disturbance,
            "distribution_distance": dist_distance,
            "chi_square": chi_sq
        },
        "thresholds": {
            "verification": t_ver,
            "repudiation": t_rep,
            "channel_disturbance": t_dist
        },
        "explanation": explanation
    }


def analyze_quantum_channel_attack(
    baseline_states: Sequence[Any],
    attacked_states: Sequence[Any],
    expected_states: Optional[Sequence[Any]] = None,
    attack_type: str = "unknown",
    threshold: float = QDS_CHANNEL_DISTURBANCE_THRESHOLD
) -> Dict[str, Any]:
    """
    Integrates quantum channel attacks (bit flip, phase flip, intercept-resend)
    with statistical and metric analysis (Part 9).

    Calculates:
    - baseline fidelity
    - attacked fidelity
    - disturbance (1 - attacked_fidelity)
    - mismatch rate
    - measurement distribution
    - distribution distance (TVD)
    - threat classification

    Uses scientifically disciplined terminology ('detected anomaly', 'threshold exceeded',
    'consistent with channel manipulation').
    """
    if len(baseline_states) == 0 or len(attacked_states) == 0:
        raise ValueError("State sequences cannot be empty.")
    if len(baseline_states) != len(attacked_states):
        raise ValueError("Baseline and attacked states length mismatch.")

    n = len(baseline_states)
    ref_states = expected_states if expected_states is not None else baseline_states

    base_fids = [state_fidelity(ref_states[i], baseline_states[i]) for i in range(n)]
    attack_fids = [state_fidelity(ref_states[i], attacked_states[i]) for i in range(n)]

    base_fid_avg = float(np.mean(base_fids))
    attack_fid_avg = float(np.mean(attack_fids))
    disturbance = max(0.0, min(1.0, 1.0 - attack_fid_avg))

    # Mismatches (projective measurement mismatch, F < 0.85)
    mismatches = sum(1 for f in attack_fids if f < 0.85)
    mismatch_rate = mismatches / n

    # Binary measurement outcome representation: 1 for match (fidelity >= 0.85), 0 for mismatch
    obs_matches = [1 if f >= 0.85 else 0 for f in attack_fids]
    exp_matches = [1 if f >= 0.85 else 0 for f in base_fids]

    p_obs_1 = sum(obs_matches) / n
    p_obs_0 = 1.0 - p_obs_1
    p_exp_1 = sum(exp_matches) / n
    p_exp_0 = 1.0 - p_exp_1

    obs_dist = [round(p_obs_0, 6), round(p_obs_1, 6)]
    exp_dist = [round(p_exp_0, 6), round(p_exp_1, 6)]
    dist_distance = calculate_deviation(exp_dist, obs_dist)

    threat_exceeded = disturbance >= threshold
    threat_classification = "QUANTUM_CHANNEL_MANIPULATION" if threat_exceeded else "NONE"

    status_desc = "threshold exceeded; detected anomaly consistent with channel manipulation" if threat_exceeded else "within acceptable channel threshold"

    explanation = (
        f"Quantum Channel Analysis ({attack_type}): baseline fidelity={base_fid_avg:.4f}, "
        f"attacked fidelity={attack_fid_avg:.4f}, disturbance D={disturbance:.4f} ({status_desc}). "
        f"Mismatch rate epsilon={mismatch_rate:.4f}, distribution distance TVD={dist_distance:.4f}."
    )

    return {
        "attack_type": attack_type,
        "baseline_fidelity": round(base_fid_avg, 6),
        "attacked_fidelity": round(attack_fid_avg, 6),
        "disturbance": round(disturbance, 6),
        "mismatch_rate": round(mismatch_rate, 6),
        "observed_distribution": obs_dist,
        "expected_distribution": exp_dist,
        "distribution_distance": round(dist_distance, 6),
        "threat_classification": threat_classification,
        "threshold_exceeded": threat_exceeded,
        "threshold": threshold,
        "explanation": explanation
    }

