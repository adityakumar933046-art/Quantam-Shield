import math
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import quantum_engine as qe

# Default Feature & Anomaly Weights
WEIGHT_VERIFICATION = 0.30  # V
WEIGHT_INTEGRITY    = 0.35  # I
WEIGHT_CERT_TIME    = 0.15  # C
WEIGHT_EXTRACTION   = 0.10  # E
WEIGHT_ALGORITHM    = 0.10  # A

def analyze_quantum_security_state(
    extraction_meta: Optional[Dict[str, Any]],
    verifications: Optional[List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """
    Executes a deterministic, mathematically explainable Quantum-Inspired Security Analysis Engine.
    
    This is an analytical security model inspired by quantum mechanics concepts (state vectors,
    state disturbance, Pauli X/Y/Z operators, projective measurements). It uses zero AI/ML/predictive models
    and yields 100% repeatable outputs for identical input parameters.
    
    Version: QIA-2.0 (Step 5 Enhanced, backward-compatible with QIA-1.0)
    """
    
    # 1. Evaluate Evidence Availability & Evidence Confidence
    has_meta = extraction_meta is not None and extraction_meta.get("signature_detected", False)
    has_verif = verifications is not None and len(verifications) > 0

    if not has_meta and not has_verif:
        # Insufficient evidence state
        exp_insufficient = {
            "step1_feature_mapping": "No signature or verification evidence available.",
            "step2_state_vector": "|psi> = 0.707|Secure> + 0.707|Disturbed>",
            "step3_pauli_analysis": "Pauli operations neutral due to missing evidence.",
            "step4_measurement": "Equal projection across subspaces.",
            "step5_decision": "Classification: INSUFFICIENT_EVIDENCE (Confidence: LOW)"
        }
        return {
            "security_state_vector": [0.5, 0.5, 0.5, 0.5, 0.5],
            "secure_consistency_score": 50.0,
            "disturbance_score": 0.5,
            "pauli_x_score": 0.0,
            "pauli_y_score": 0.0,
            "pauli_z_score": 0.0,
            "secure_measurement_score": 50.0,
            "suspicious_measurement_score": 30.0,
            "high_risk_measurement_score": 20.0,
            "forgery_risk_score": 0.0,
            "analysis_confidence_score": 0.2,
            "confidence_level": "LOW",
            "final_classification": "INSUFFICIENT_EVIDENCE",
            "analysis_version": "QIA-1.0",
            "state_consistency": 0.5,
            "state_disturbance": 0.5,
            "measurement_secure_probability": 0.5,
            "measurement_threat_probability": 0.5,
            "pauli_x_disturbance": 0.0,
            "pauli_y_disturbance": 0.0,
            "pauli_z_disturbance": 0.0,
            "combined_pauli_disturbance": 0.0,
            "forgery_risk_estimate": 0.0,
            "quantum_analysis_version": "QIA-2.0",
            "explanation_json": json.dumps(exp_insufficient),
            "explanation": exp_insufficient
        }

    # 2. Normalize Feature Vector S = [V, I, C, E, A] to [0.0, 1.0]
    
    # E: Extraction & Structure Consistency
    if has_meta and extraction_meta:
        sig_status = extraction_meta.get("signature_status", "EXTRACTION_ERROR")
        if sig_status == "SIGNATURE_FOUND":
            E = 1.0
        elif sig_status == "NO_SIGNATURE_FOUND":
            E = 0.5
        elif sig_status == "SIGNATURE_STRUCTURE_INVALID":
            E = 0.0
        else:
            E = 0.5
    else:
        E = 0.5

    # V: Signature Verification Consistency
    if has_verif and verifications:
        v_status = verifications[0].get("verification_status", "UNKNOWN")
        if v_status == "VALID":
            V = 1.0
        elif v_status in ["INVALID", "MALFORMED", "VERIFICATION_ERROR"]:
            V = 0.0
        elif v_status == "UNSUPPORTED":
            V = 0.5
        else:
            V = 0.5
    else:
        # If extraction found an invalid structure, V and I are 0.0
        if has_meta and extraction_meta and extraction_meta.get("signature_status") == "SIGNATURE_STRUCTURE_INVALID":
            V = 0.0
        else:
            V = 0.5

    # I: Document Integrity Consistency
    if has_verif and verifications:
        i_status = verifications[0].get("integrity_status", "UNKNOWN")
        if i_status == "INTACT":
            I = 1.0
        elif i_status == "MODIFIED":
            I = 0.0
        else:
            I = 0.5
    else:
        if has_meta and extraction_meta and extraction_meta.get("signature_status") == "SIGNATURE_STRUCTURE_INVALID":
            I = 0.0
        else:
            I = 0.5

    # C: Certificate Time Consistency
    if has_verif and verifications:
        c_time_status = verifications[0].get("certificate_time_status", "UNKNOWN")
        if c_time_status == "VALID_TIME_RANGE":
            C = 1.0
        elif c_time_status in ["EXPIRED", "NOT_YET_VALID"]:
            C = 0.6 # Reduced consistency but not automatic forgery
        else:
            C = 0.5
    else:
        C = 0.5

    # A: Algorithm & Parameter Strength Consistency
    if has_meta and extraction_meta:
        sig_algo = extraction_meta.get("signature_algorithm", "")
        pub_key_size = extraction_meta.get("public_key_size", 0)
        if "RSA" in sig_algo and pub_key_size >= 2048:
            A = 1.0
        elif pub_key_size >= 1024:
            A = 0.8
        else:
            A = 0.5
    else:
        A = 0.5

    # Feature vector S = [V, I, C, E, A]
    feature_vector = [V, I, C, E, A]

    # 3. State Vector Construction & Euclidean Disturbance
    # Reference secure vector S_secure = [1.0, 1.0, 1.0, 1.0, 1.0]
    sq_dist_sum = sum((1.0 - val) ** 2 for val in feature_vector)
    max_dist = math.sqrt(5.0)  # max distance in 5D unit cube from (1,1,1,1,1) to (0,0,0,0,0)
    
    # Normalized Euclidean disturbance D in [0.0, 1.0]
    beta_sq = min(1.0, max(0.0, math.sqrt(sq_dist_sum) / max_dist))
    alpha_sq = max(0.0, 1.0 - beta_sq)

    alpha = math.sqrt(alpha_sq)
    beta = math.sqrt(beta_sq)

    secure_consistency_pct = round(alpha_sq * 100.0, 2)
    disturbance_score = round(beta, 4)

    # 4. Pauli-Inspired Analytical Transformations
    
    # Pauli X-Inspired Score: Measures binary state flip anomalies (e.g. VALID -> INVALID, INTACT -> MODIFIED)
    pauli_x = round((1.0 - min(V, I)) * 100.0, 2)

    # Pauli Z-Inspired Score: Measures metadata & structural phase inconsistencies
    pauli_z = round((1.0 - (C + E + A) / 3.0) * 100.0, 2)

    # Pauli Y-Inspired Score: Combined binary flip & phase anomaly score
    pauli_y = round(math.sqrt(0.5 * ((pauli_x / 100.0)**2 + (pauli_z / 100.0)**2)) * 100.0, 2)

    # 5. Projective Measurement Model
    # Projects |psi> onto reference subspaces P_secure, P_suspicious, P_high_risk
    p_sec = max(0.0, alpha_sq - 0.3 * disturbance_score)
    p_sus = disturbance_score * (1.0 - (pauli_x / 100.0))
    p_hr  = disturbance_score * (pauli_x / 100.0)

    p_total = p_sec + p_sus + p_hr
    if p_total > 0:
        sec_measurement_pct = round((p_sec / p_total) * 100.0, 2)
        sus_measurement_pct = round((p_sus / p_total) * 100.0, 2)
        hr_measurement_pct  = round((p_hr  / p_total) * 100.0, 2)
    else:
        sec_measurement_pct = 50.0
        sus_measurement_pct = 30.0
        hr_measurement_pct  = 20.0

    # 6. Forgery Risk Estimation
    forgery_risk_score = round(min(100.0, max(0.0, (1.0 - alpha_sq) * 70.0 + (pauli_x / 100.0) * 30.0)), 2)

    # 7. Analysis Confidence Score
    confidence_factors = 0
    if has_meta: confidence_factors += 1
    if has_verif: confidence_factors += 1
    if V != 0.5: confidence_factors += 1
    if I != 0.5: confidence_factors += 1

    confidence_score = round(confidence_factors / 4.0, 2)
    if confidence_score >= 0.75:
        confidence_level = "HIGH"
    elif confidence_score >= 0.5:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    # 8. Deterministic Final Classification
    if confidence_level == "LOW" or not has_meta:
        final_classification = "INSUFFICIENT_EVIDENCE"
    elif forgery_risk_score >= 60.0 or pauli_x >= 60.0 or V == 0.0 or I == 0.0 or E == 0.0:
        final_classification = "HIGH_RISK"
    elif forgery_risk_score >= 30.0 or disturbance_score >= 0.35:
        final_classification = "SUSPICIOUS"
    elif forgery_risk_score >= 15.0:
        final_classification = "LOW_RISK"
    else:
        final_classification = "SECURE"

    # 9. Step 5 Modular Quantum Engine Evaluation
    state_consistency_val = round(alpha_sq, 4)
    state_dist_val = round(disturbance_score, 4)
    meas_sec_prob = round(sec_measurement_pct / 100.0, 4)
    meas_threat_prob = round((sus_measurement_pct + hr_measurement_pct) / 100.0, 4)
    px_dist = round(pauli_x / 100.0, 4)
    py_dist = round(pauli_y / 100.0, 4)
    pz_dist = round(pauli_z / 100.0, 4)
    comb_pauli = round(pauli_y / 100.0, 4)
    forg_est = round(forgery_risk_score, 2)

    # Pure 8-parameter normalized vector from modular quantum engine
    sec_param_vec = qe.extract_security_parameters_from_evidence(
        signature_verified=(V == 1.0),
        integrity_verified=(I == 1.0),
        public_key_status="VALID" if A >= 0.8 else "UNKNOWN",
        certificate_status="VALID" if C == 1.0 else ("EXPIRED" if C == 0.6 else "UNKNOWN"),
        raw_signature_detected=has_meta
    )
    qe_state = qe.calculate_quantum_security_state(sec_param_vec)
    qe_pauli_res = qe.evaluate_pauli_disturbances(sec_param_vec)
    qe_meas_res = qe.analyze_projective_measurements(qe_state["state_vector"])
    qe_forg_res = qe.calculate_forgery_probability_estimate(
        signature_validity=sec_param_vec["signature_validity"],
        hash_integrity=sec_param_vec["hash_integrity"],
        public_key_validity=sec_param_vec["public_key_validity"],
        metadata_consistency=sec_param_vec["metadata_consistency"],
        state_disturbance=qe_state["security_disturbance"],
        pauli_disturbance=qe_pauli_res["combined_pauli_disturbance"]
    )
    qe_threats = qe.evaluate_deterministic_threats(
        security_parameters=sec_param_vec,
        state_disturbance=qe_state["security_disturbance"],
        pauli_disturbances=qe_pauli_res,
        forgery_risk=qe_forg_res
    )
    qe_risk_res = qe.calculate_composite_risk_score(
        security_parameters=sec_param_vec,
        state_disturbance=qe_state["security_disturbance"],
        combined_pauli_disturbance=qe_pauli_res["combined_pauli_disturbance"],
        forgery_risk_percentage=qe_forg_res["forgery_risk_percentage"]
    )

    # 10. Explainability Breakdown Dictionary
    explanation_details = {
        "step1_feature_mapping": f"Normalized vector S=[V={V:.2f}, I={I:.2f}, C={C:.2f}, E={E:.2f}, A={A:.2f}]",
        "step2_state_vector": f"|psi> = {alpha:.3f}|Secure> + {beta:.3f}|Disturbed> (Secure Consistency: {secure_consistency_pct}%, Disturbance: {disturbance_score:.4f})",
        "step3_pauli_analysis": f"Pauli X (Binary Flip): {pauli_x}%, Pauli Z (Phase Conflict): {pauli_z}%, Pauli Y (Combined): {pauli_y}%",
        "step4_measurement": f"Projective Distribution: P_secure={sec_measurement_pct}%, P_suspicious={sus_measurement_pct}%, P_high_risk={hr_measurement_pct}%",
        "step5_decision": f"Forgery Risk: {forgery_risk_score}/100. Confidence: {confidence_level} ({confidence_score * 100}%). Final Classification: {final_classification}"
    }

    return {
        "security_state_vector": feature_vector,
        "secure_consistency_score": secure_consistency_pct,
        "disturbance_score": disturbance_score,
        "pauli_x_score": pauli_x,
        "pauli_y_score": pauli_y,
        "pauli_z_score": pauli_z,
        "secure_measurement_score": sec_measurement_pct,
        "suspicious_measurement_score": sus_measurement_pct,
        "high_risk_measurement_score": hr_measurement_pct,
        "forgery_risk_score": forgery_risk_score,
        "analysis_confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "final_classification": final_classification,
        "analysis_version": "QIA-1.0",
        "state_consistency": state_consistency_val,
        "state_disturbance": state_dist_val,
        "measurement_secure_probability": meas_sec_prob,
        "measurement_threat_probability": meas_threat_prob,
        "pauli_x_disturbance": px_dist,
        "pauli_y_disturbance": py_dist,
        "pauli_z_disturbance": pz_dist,
        "combined_pauli_disturbance": comb_pauli,
        "forgery_risk_estimate": forg_est,
        "quantum_analysis_version": "QIA-2.0",
        "explanation_json": json.dumps(explanation_details),
        "explanation": explanation_details,
        "quantum_engine_state": qe_state,
        "quantum_engine_pauli": qe_pauli_res,
        "quantum_engine_measurement": qe_meas_res,
        "quantum_engine_forgery": qe_forg_res,
        "quantum_engine_threats": qe_threats,
        "quantum_engine_risk": qe_risk_res
    }
