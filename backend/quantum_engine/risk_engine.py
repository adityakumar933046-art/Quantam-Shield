"""
Deterministic Composite Risk Engine.

Module: quantum_engine.risk_engine
Synthesizes classical cryptographic verification risks, integrity failures,
quantum-inspired state disturbance, Pauli anomaly operators, and forgery risk estimates
into a deterministic composite score (0-100), risk tier, and itemized component breakdown.

Contains NO AI, NO ML, NO random decision making.
"""

from typing import Dict, Any, List, Optional


DEFAULT_RISK_WEIGHTS: Dict[str, float] = {
    "classical_sig_risk": 0.25,
    "integrity_risk": 0.25,
    "public_key_risk": 0.10,
    "certificate_risk": 0.08,
    "replay_risk": 0.08,
    "activity_risk": 0.06,
    "state_disturbance_risk": 0.08,
    "pauli_disturbance_risk": 0.05,
    "forgery_estimate_risk": 0.05,
}


def calculate_composite_risk_score(
    security_parameters: Dict[str, float],
    state_disturbance: float,
    combined_pauli_disturbance: float,
    forgery_risk_percentage: float,
    weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Calculates a deterministic 0-100 composite risk score and risk level.
    Provides an itemized breakdown of contributing factors.
    """
    w = weights or DEFAULT_RISK_WEIGHTS
    total_w = sum(w.values())

    sig_val = security_parameters.get("signature_validity", 1.0)
    hash_integ = security_parameters.get("hash_integrity", 1.0)
    pk_val = security_parameters.get("public_key_validity", 1.0)
    cert_val = security_parameters.get("certificate_validity", 1.0)
    replay_safe = security_parameters.get("replay_safety", 1.0)
    act_safe = security_parameters.get("activity_safety", 1.0)

    # Convert normalized parameters to 0-100 risk values
    r_sig = (1.0 - sig_val) * 100.0
    r_integ = (1.0 - hash_integ) * 100.0
    r_pk = (1.0 - pk_val) * 100.0
    r_cert = (1.0 - cert_val) * 100.0
    r_replay = (1.0 - replay_safe) * 100.0
    r_act = (1.0 - act_safe) * 100.0
    r_state = state_disturbance * 100.0
    r_pauli = combined_pauli_disturbance * 100.0
    r_forgery = forgery_risk_percentage

    # Contributions
    c_sig = (w.get("classical_sig_risk", 0.25) * r_sig) / total_w
    c_integ = (w.get("integrity_risk", 0.25) * r_integ) / total_w
    c_pk = (w.get("public_key_risk", 0.10) * r_pk) / total_w
    c_cert = (w.get("certificate_risk", 0.08) * r_cert) / total_w
    c_replay = (w.get("replay_risk", 0.08) * r_replay) / total_w
    c_act = (w.get("activity_risk", 0.06) * r_act) / total_w
    c_state = (w.get("state_disturbance_risk", 0.08) * r_state) / total_w
    c_pauli = (w.get("pauli_disturbance_risk", 0.05) * r_pauli) / total_w
    c_forgery = (w.get("forgery_estimate_risk", 0.05) * r_forgery) / total_w

    raw_score = (c_sig + c_integ + c_pk + c_cert + c_replay + c_act + c_state + c_pauli + c_forgery)

    # Critical security overrides:
    # Severe hash mismatch or invalid signature guarantees minimum high risk
    if r_integ > 80.0:
        raw_score = max(raw_score, 88.0)
    elif r_sig > 80.0:
        raw_score = max(raw_score, 85.0)

    final_score = round(max(0.0, min(100.0, raw_score)), 2)

    # Risk level tiers
    if final_score >= 71.0:
        level = "CRITICAL"
    elif final_score >= 46.0:
        level = "HIGH"
    elif final_score >= 21.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Itemized contributing factors
    contributions = []
    if c_sig >= 5.0:
        contributions.append(f"Invalid/Failed Signature: +{c_sig:.1f}")
    if c_integ >= 5.0:
        contributions.append(f"Document Content Tampering: +{c_integ:.1f}")
    if c_replay >= 3.0:
        contributions.append(f"Replay Activity: +{c_replay:.1f}")
    if c_state >= 3.0:
        contributions.append(f"Quantum State Disturbance: +{c_state:.1f}")
    if c_pauli >= 3.0:
        contributions.append(f"Pauli Anomaly Operator: +{c_pauli:.1f}")
    if c_pk >= 3.0:
        contributions.append(f"Public Key Anomaly: +{c_pk:.1f}")
    if c_cert >= 3.0:
        contributions.append(f"Certificate Time/Trust Issue: +{c_cert:.1f}")
    if c_act >= 3.0:
        contributions.append(f"Unauthorized Access Log: +{c_act:.1f}")

    if not contributions:
        contributions.append("All security indicators intact; baseline nominal risk.")

    return {
        "final_risk_score": final_score,
        "composite_risk_score": final_score,
        "risk_level": level,
        "contributing_factors": contributions,
        "raw_component_scores": {
            "classical_sig_risk": round(r_sig, 2),
            "integrity_risk": round(r_integ, 2),
            "public_key_risk": round(r_pk, 2),
            "certificate_risk": round(r_cert, 2),
            "replay_risk": round(r_replay, 2),
            "activity_risk": round(r_act, 2),
            "state_disturbance_risk": round(r_state, 2),
            "pauli_disturbance_risk": round(r_pauli, 2),
            "forgery_estimate_risk": round(r_forgery, 2),
        }
    }
