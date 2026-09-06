"""
Quantum-Inspired Security State and Parameter Vector Representation.

Module: quantum_engine.security_state
Connects classical digital signature verification results with deterministic,
mathematically explainable quantum state vector models.

Scientific Note:
This is a mathematical simulation and threat analysis framework. Classical digital
signatures do not physicalize as quantum states, and no quantum computer is used.
Concepts are applied strictly as normalized mathematical abstractions in Hilbert space C^2.
"""

from typing import Dict, Any, List, Optional, Tuple
import math
import numpy as np

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    normalize_state,
    state_inner_product,
    state_fidelity
)


# Configurable weights for 8-parameter normalized security vector S
DEFAULT_SECURITY_WEIGHTS: Dict[str, float] = {
    "signature_validity": 0.25,
    "hash_integrity": 0.25,
    "public_key_validity": 0.10,
    "certificate_validity": 0.10,
    "metadata_consistency": 0.08,
    "signature_consistency": 0.08,
    "replay_safety": 0.07,
    "activity_safety": 0.07,
}


def build_security_parameter_vector(
    signature_validity: float = 1.0,
    hash_integrity: float = 1.0,
    public_key_validity: float = 1.0,
    certificate_validity: float = 1.0,
    metadata_consistency: float = 1.0,
    signature_consistency: float = 1.0,
    replay_safety: float = 1.0,
    activity_safety: float = 1.0,
) -> Dict[str, float]:
    """
    Builds and validates the normalized 8-parameter security vector S.
    Each value is clamped to [0.0, 1.0], where 1.0 = Secure/Expected and 0.0 = Disturbed/Failed.
    """
    def clamp(v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    return {
        "signature_validity": clamp(signature_validity),
        "hash_integrity": clamp(hash_integrity),
        "public_key_validity": clamp(public_key_validity),
        "certificate_validity": clamp(certificate_validity),
        "metadata_consistency": clamp(metadata_consistency),
        "signature_consistency": clamp(signature_consistency),
        "replay_safety": clamp(replay_safety),
        "activity_safety": clamp(activity_safety),
    }


def extract_security_parameters_from_evidence(
    signature_verified: bool,
    integrity_verified: bool,
    public_key_status: str = "VALID",
    certificate_status: str = "VALID",
    metadata_anomalies: Optional[List[str]] = None,
    signature_reuse_conflict: bool = False,
    replay_detected: bool = False,
    unauthorized_attempts: int = 0,
    raw_signature_detected: bool = True
) -> Dict[str, float]:
    """
    Deterministically maps classical cryptographic verification outputs,
    certificate inspection, and audit history into normalized security parameters.
    """
    # 1. Signature Validity
    if signature_verified:
        sig_val = 1.0
    elif not raw_signature_detected:
        sig_val = 0.5  # Untracked / no signature (not necessarily forged)
    else:
        sig_val = 0.0  # Cryptographic verification failed

    # 2. Hash Integrity
    hash_val = 1.0 if integrity_verified else 0.0

    # 3. Public Key Validity
    pk_upper = public_key_status.upper()
    if pk_upper in ["VALID", "TRUSTED"]:
        pk_val = 1.0
    elif pk_upper in ["PUBLIC_KEY_NOT_FOUND", "UNKNOWN", "NOT_AVAILABLE"]:
        pk_val = 0.5
    else:
        pk_val = 0.0

    # 4. Certificate Validity
    cert_upper = certificate_status.upper()
    if cert_upper in ["VALID", "VALID_TIME_RANGE", "TRUSTED_FOR_QSHIELD_DEMO"]:
        cert_val = 1.0
    elif cert_upper in ["EXPIRED", "REVOKED", "TIME_INVALID"]:
        cert_val = 0.0
    elif cert_upper in ["NOT_AVAILABLE", "UNKNOWN", "SELF_SIGNED"]:
        cert_val = 0.6
    else:
        cert_val = 0.5

    # 5. Metadata Consistency
    if metadata_anomalies and len(metadata_anomalies) > 0:
        meta_val = max(0.0, 1.0 - (len(metadata_anomalies) * 0.35))
    else:
        meta_val = 1.0

    # 6. Signature Consistency
    sig_cons_val = 0.0 if signature_reuse_conflict else 1.0

    # 7. Replay Safety
    replay_val = 0.0 if replay_detected else 1.0

    # 8. Activity Safety
    if unauthorized_attempts > 0:
        act_val = max(0.0, 1.0 - (unauthorized_attempts * 0.30))
    else:
        act_val = 1.0

    return build_security_parameter_vector(
        signature_validity=sig_val,
        hash_integrity=hash_val,
        public_key_validity=pk_val,
        certificate_validity=cert_val,
        metadata_consistency=meta_val,
        signature_consistency=sig_cons_val,
        replay_safety=replay_val,
        activity_safety=act_val,
    )


def calculate_quantum_security_state(
    parameter_vector: Dict[str, float],
    weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Transforms the normalized security parameters into an explainable two-state
    quantum superposition:
        |psi> = alpha |0> + beta |1>

    where:
        |0> = [1, 0]^T : Expected / Secure state
        |1> = [0, 1]^T : Disturbed / Threat state
        alpha = sqrt(security_consistency)
        beta  = sqrt(security_disturbance)
        |alpha|^2 + |beta|^2 = 1.0
    """
    w_dict = weights if weights else DEFAULT_SECURITY_WEIGHTS

    # Normalize weights sum to 1.0
    total_w = sum(w_dict.values())
    norm_w = {k: v / total_w for k, v in w_dict.items()}

    # Weighted mean of secure indicators
    consistency = sum(norm_w.get(k, 0.0) * parameter_vector.get(k, 1.0) for k in norm_w)
    consistency = max(0.0, min(1.0, float(consistency)))
    disturbance = max(0.0, min(1.0, 1.0 - consistency))

    # Quantum Amplitudes
    alpha = math.sqrt(consistency)
    beta = math.sqrt(disturbance)

    # Reconstruct state vector in C^2
    psi_vector = alpha * STATE_0 + beta * STATE_1

    return {
        "security_parameters": parameter_vector,
        "parameter_weights": norm_w,
        "security_consistency": consistency,
        "security_disturbance": disturbance,
        "state_amplitudes": {
            "alpha_secure": round(alpha, 6),
            "beta_threat": round(beta, 6)
        },
        "state_vector": [round(float(alpha), 6), round(float(beta), 6)],
        "normalized_norm": round(float(alpha**2 + beta**2), 6),
        "mathematical_formula": f"|psi> = {alpha:.3f}|0> + {beta:.3f}|1>",
        "explanation": (
            f"State consistency C={consistency*100:.1f}%, disturbance D={disturbance*100:.1f}%. "
            f"Superposition amplitudes alpha={alpha:.3f} (secure), beta={beta:.3f} (threat). "
            f"Normalization check: |alpha|^2 + |beta|^2 = {alpha**2 + beta**2:.4f}."
        )
    }
