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

from typing import Dict, Any, List, Optional
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
from quantum_engine.states import STATE_0, STATE_1, normalize_state


def evaluate_deterministic_threats(
    security_parameters: Dict[str, float],
    state_disturbance: float = 0.0,
    pauli_disturbances: Optional[Dict[str, float]] = None,
    forgery_risk: Optional[Dict[str, Any]] = None,
    metadata_details: Optional[Dict[str, Any]] = None,
    audit_events: Optional[List[str]] = None
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
