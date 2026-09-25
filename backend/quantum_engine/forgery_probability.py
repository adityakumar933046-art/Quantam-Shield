"""
Deterministic Forgery Probability and Risk Estimation Model.

Module: quantum_engine.forgery_probability
Computes a normalized, mathematically explainable Forgery Risk Estimate
based on classical verification failures, hash mismatches, quantum state disturbance,
and Pauli anomaly projections.

Scientific Disclaimer:
This is an analytical risk estimate and threat heuristic, NOT a physical quantum
measurement or a mathematically absolute certainty of a real-world forgery.
"""

from typing import Dict, Any, Optional


# Default configurable weights for forgery probability model
DEFAULT_FORGERY_WEIGHTS: Dict[str, float] = {
    "w_sig_failure": 0.35,      # Cryptographic signature mathematical failure
    "w_hash_failure": 0.25,     # Document content hash mismatch
    "w_pubkey_problem": 0.10,   # Untrusted / missing / invalid public key
    "w_metadata_anomaly": 0.05, # Signer name / cert CN mismatch
    "w_state_dist": 0.10,       # Quantum-inspired state disturbance D
    "w_pauli_dist": 0.15,       # Combined Pauli anomaly projection
}


def calculate_forgery_probability_estimate(
    signature_validity: float,
    hash_integrity: float,
    public_key_validity: float,
    metadata_consistency: float,
    state_disturbance: float,
    pauli_disturbance: float,
    weights: Optional[Dict[str, float]] = None,
    qds_evidence: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Computes a deterministic Forgery Risk Estimate in [0.0, 1.0] (0% to 100%).

    Formula:
        forgery_score = w1*sig_failure + w2*hash_failure + w3*pk_problem +
                        w4*meta_anomaly + w5*state_dist + w6*pauli_dist
                        (+ QDS evidence modulation if provided)

    Scientific Note:
        This is an analytical risk heuristic; it does NOT represent an information-theoretic
        security bound or guaranteed real-world forgery.
    """
    w = weights or DEFAULT_FORGERY_WEIGHTS
    total_w = sum(w.values())

    sig_failure = max(0.0, min(1.0, 1.0 - float(signature_validity)))
    hash_failure = max(0.0, min(1.0, 1.0 - float(hash_integrity)))
    pk_problem = max(0.0, min(1.0, 1.0 - float(public_key_validity)))
    meta_anomaly = max(0.0, min(1.0, 1.0 - float(metadata_consistency)))
    st_dist = max(0.0, min(1.0, float(state_disturbance)))
    pl_dist = max(0.0, min(1.0, float(pauli_disturbance)))

    # Weighted sum
    score = (
        (w.get("w_sig_failure", 0.35) * sig_failure) +
        (w.get("w_hash_failure", 0.25) * hash_failure) +
        (w.get("w_pubkey_problem", 0.10) * pk_problem) +
        (w.get("w_metadata_anomaly", 0.05) * meta_anomaly) +
        (w.get("w_state_dist", 0.10) * st_dist) +
        (w.get("w_pauli_dist", 0.15) * pl_dist)
    ) / total_w

    # If QDS evidence is present, integrate projective mismatch rate analytically
    qds_comp = 0.0
    if qds_evidence is not None:
        qds_mismatch = float(qds_evidence.get("mismatch_rate", 0.0))
        qds_t_ver = float(qds_evidence.get("verification_threshold", 0.10))
        if qds_mismatch > qds_t_ver:
            # Scale contribution based on degree of threshold violation
            qds_factor = min(1.0, (qds_mismatch - qds_t_ver) / (1.0 - qds_t_ver))
            score = max(score, min(1.0, score + 0.35 * qds_factor))
            qds_comp = round(qds_mismatch * 100.0, 2)

    score = max(0.0, min(1.0, score))
    pct = round(score * 100.0, 2)

    # Classification
    if pct >= 70.0:
        level = "CRITICAL"
    elif pct >= 45.0:
        level = "HIGH"
    elif pct >= 20.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    components = {
        "signature_failure_component": round(sig_failure * 100.0, 2),
        "hash_tampering_component": round(hash_failure * 100.0, 2),
        "public_key_component": round(pk_problem * 100.0, 2),
        "metadata_anomaly_component": round(meta_anomaly * 100.0, 2),
        "state_disturbance_component": round(st_dist * 100.0, 2),
        "pauli_anomaly_component": round(pl_dist * 100.0, 2),
    }
    if qds_evidence is not None:
        components["qds_mismatch_component"] = qds_comp

    return {
        "forgery_probability_score": round(score, 6),
        "forgery_risk_percentage": pct,
        "forgery_risk_level": level,
        "component_factors": components,
        "model_weights": {k: round(v / total_w, 4) for k, v in w.items()},
        "scientific_disclaimer": (
            "Estimated Forgery Probability is an analytical risk heuristic derived from "
            "cryptographic failure metrics and state disturbance projections; it does not represent "
            "a physical quantum computation or guaranteed real-world forgery event."
        )
    }


def calculate_qds_forgery_probability_estimate(
    qds_evidence: Dict[str, Any],
    weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Computes a dedicated analytical Forgery Risk Estimate from QDS statistical evidence.

    Formula:
        forgery_score = 0.50 * mismatch_factor + 0.30 * channel_dist + 0.20 * repudiation_factor

    Scientific Note:
        Analytical heuristic estimate for QDS verification monitoring.
        Does not assert an information-theoretic bound.
    """
    mismatch_rate = float(qds_evidence.get("mismatch_rate", 0.0))
    t_ver = float(qds_evidence.get("verification_threshold", 0.10))
    disturbance = float(qds_evidence.get("state_disturbance", 0.0))
    t_dist = float(qds_evidence.get("channel_disturbance_threshold", 0.20))

    non_rep = qds_evidence.get("non_repudiation_result")
    rep_mismatch = float(non_rep.get("mismatch_rate", 0.0)) if non_rep else 0.0
    t_rep = float(qds_evidence.get("repudiation_threshold", 0.05))

    # Normalized component factors
    f_mismatch = max(0.0, min(1.0, mismatch_rate / max(t_ver * 2.0, 0.01))) if mismatch_rate > t_ver else (mismatch_rate / t_ver) * 0.2
    f_dist = max(0.0, min(1.0, disturbance / max(t_dist * 2.0, 0.01))) if disturbance >= t_dist else (disturbance / t_dist) * 0.2
    f_rep = max(0.0, min(1.0, rep_mismatch / max(t_rep * 2.0, 0.01))) if rep_mismatch > t_rep else (rep_mismatch / t_rep) * 0.1

    raw_score = 0.50 * f_mismatch + 0.30 * f_dist + 0.20 * f_rep
    score = max(0.0, min(1.0, raw_score))
    pct = round(score * 100.0, 2)

    if pct >= 70.0:
        level = "CRITICAL"
    elif pct >= 45.0:
        level = "HIGH"
    elif pct >= 20.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "forgery_probability_score": round(score, 6),
        "forgery_risk_percentage": pct,
        "forgery_risk_level": level,
        "component_factors": {
            "mismatch_component": round(f_mismatch * 100.0, 2),
            "channel_disturbance_component": round(f_dist * 100.0, 2),
            "repudiation_component": round(f_rep * 100.0, 2),
        },
        "scientific_disclaimer": (
            "Estimated QDS Forgery Probability is an analytical risk heuristic derived from "
            "measurement mismatch rates and channel disturbance; it does not constitute an "
            "information-theoretic security bound."
        )
    }

