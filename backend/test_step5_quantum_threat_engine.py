import sys
import math
from pathlib import Path
import numpy as np

sys.path.append(str(Path(__file__).resolve().parent))

import quantum_engine as qe
from quantum_engine.states import (
    STATE_0, STATE_1, STATE_PLUS, STATE_MINUS,
    normalize_state, state_inner_product, state_fidelity, is_valid_state
)
from quantum_engine.bell_states import (
    BELL_PHI_PLUS, BELL_PHI_MINUS, BELL_PSI_PLUS, BELL_PSI_MINUS,
    get_bell_state, get_all_bell_states, bell_state_fidelity
)
from quantum_engine.pauli_operations import (
    PAULI_I, PAULI_X, PAULI_Y, PAULI_Z,
    apply_x, apply_y, apply_z, apply_identity,
    calculate_state_change, evaluate_pauli_disturbances
)
from quantum_engine.metrics import (
    calculate_measurement_probability,
    calculate_state_disturbance,
    calculate_consistency_score,
    calculate_measurement_distribution,
    calculate_deviation
)
from quantum_engine.security_state import (
    build_security_parameter_vector,
    extract_security_parameters_from_evidence,
    calculate_quantum_security_state
)
from quantum_engine.measurement_analysis import (
    analyze_projective_measurements,
    simulate_stochastic_measurements
)
from quantum_engine.forgery_probability import (
    calculate_forgery_probability_estimate
)
from quantum_engine.threat_detector import (
    evaluate_deterministic_threats,
    simulate_quantum_channel
)
from quantum_engine.risk_engine import (
    calculate_composite_risk_score
)


def test_1_quantum_states_and_math():
    print("\n--- 1. Testing Quantum States & Mathematical Foundations ---")
    assert np.allclose(STATE_0, np.array([1, 0]))
    assert np.allclose(STATE_1, np.array([0, 1]))
    assert is_valid_state(STATE_0)
    assert is_valid_state(STATE_1)
    assert is_valid_state(STATE_PLUS)
    assert is_valid_state(STATE_MINUS)

    ip = state_inner_product(STATE_0, STATE_1)
    assert abs(ip) < 1e-9, f"Expected <0|1> = 0, got {ip}"

    fid = state_fidelity(STATE_0, STATE_0)
    assert abs(fid - 1.0) < 1e-9, f"Expected fidelity 1.0, got {fid}"

    raw = np.array([3.0, 4.0], dtype=complex)
    normalized = normalize_state(raw)
    assert is_valid_state(normalized)
    assert abs(np.linalg.norm(normalized) - 1.0) < 1e-9
    print("[PASS] Quantum basis states, superposition, normalization, and fidelity verified.")


def test_2_bell_states_orthogonality():
    print("\n--- 2. Testing Bell States & Two-Qubit Entangled Representations ---")
    bell_dict = get_all_bell_states()
    assert len(bell_dict) == 4
    for name, state in bell_dict.items():
        assert state.shape == (4,), f"Expected shape (4,) for {name}"
        norm = np.linalg.norm(state)
        assert abs(norm - 1.0) < 1e-9, f"Bell state {name} not normalized: norm={norm}"

    names = list(bell_dict.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            fid = bell_state_fidelity(bell_dict[names[i]], bell_dict[names[j]])
            assert abs(fid) < 1e-9, f"Bell states {names[i]} and {names[j]} are not orthogonal (fidelity={fid})"
    print("[PASS] All 4 Bell states verified for normalization and mutual orthogonality.")


def test_3_pauli_operators_and_disturbances():
    print("\n--- 3. Testing Pauli Operators & Analytical Disturbances ---")
    x_0 = apply_x(STATE_0)
    assert np.allclose(x_0, STATE_1)
    x_1 = apply_x(STATE_1)
    assert np.allclose(x_1, STATE_0)

    z_0 = apply_z(STATE_0)
    assert np.allclose(z_0, STATE_0)
    z_1 = apply_z(STATE_1)
    assert np.allclose(z_1, -STATE_1)

    change = calculate_state_change(STATE_0, x_0)
    assert abs(change - 1.0) < 1e-9, f"Expected state change 1.0 for |0> -> |1>, got {change}"

    sec_vec = build_security_parameter_vector()
    pauli_sec = evaluate_pauli_disturbances(sec_vec)
    assert pauli_sec["pauli_x_disturbance"] == 0.0
    assert pauli_sec["pauli_z_disturbance"] == 0.0
    assert pauli_sec["combined_pauli_disturbance"] == 0.0

    tampered_vec = build_security_parameter_vector(signature_validity=0.0, hash_integrity=0.0)
    pauli_tamp = evaluate_pauli_disturbances(tampered_vec)
    assert pauli_tamp["pauli_x_disturbance"] == 1.0
    assert pauli_tamp["combined_pauli_disturbance"] >= 0.40
    print(f"[PASS] Pauli operations verified. Tampered Pauli X={pauli_tamp['pauli_x_disturbance']:.2f}, Combined={pauli_tamp['combined_pauli_disturbance']:.2f}")


def test_4_quantum_metrics():
    print("\n--- 4. Testing Core Quantum Metrics & Born Rule ---")
    p_0 = calculate_measurement_probability(STATE_PLUS, STATE_0)
    p_1 = calculate_measurement_probability(STATE_PLUS, STATE_1)
    assert abs(p_0 - 0.5) < 1e-6
    assert abs(p_1 - 0.5) < 1e-6
    assert abs(p_0 + p_1 - 1.0) < 1e-6

    d_perfect = calculate_state_disturbance(STATE_0, STATE_0)
    assert abs(d_perfect - 0.0) < 1e-9
    c_perfect = calculate_consistency_score(STATE_0, STATE_0)
    assert abs(c_perfect - 1.0) < 1e-9

    d_total = calculate_state_disturbance(STATE_0, STATE_1)
    assert abs(d_total - 1.0) < 1e-9
    print(f"[PASS] Born rule P(|+> -> |0>)={p_0}, perfect disturbance={d_perfect}, total disturbance={d_total}.")


def test_5_security_state_vector_and_superposition():
    print("\n--- 5. Testing Security State Vector & Superposition Amplitudes ---")
    params_sec = extract_security_parameters_from_evidence(
        signature_verified=True,
        integrity_verified=True,
        public_key_status="VALID",
        certificate_status="VALID"
    )
    state_sec = calculate_quantum_security_state(params_sec)
    assert abs(state_sec["security_consistency"] - 1.0) < 1e-6
    assert abs(state_sec["security_disturbance"] - 0.0) < 1e-6
    assert abs(state_sec["state_amplitudes"]["alpha_secure"] - 1.0) < 1e-6
    assert abs(state_sec["state_amplitudes"]["beta_threat"] - 0.0) < 1e-6
    assert abs(state_sec["normalized_norm"] - 1.0) < 1e-6

    params_fail = extract_security_parameters_from_evidence(
        signature_verified=False,
        integrity_verified=False,
        public_key_status="INVALID",
        certificate_status="REVOKED"
    )
    state_fail = calculate_quantum_security_state(params_fail)
    assert state_fail["security_disturbance"] > 0.6
    assert state_fail["state_amplitudes"]["beta_threat"] > 0.7
    assert abs(state_fail["normalized_norm"] - 1.0) < 1e-6
    print(f"[PASS] Secure alpha={state_sec['state_amplitudes']['alpha_secure']}, Failed beta={state_fail['state_amplitudes']['beta_threat']:.4f}, Norm=1.0")


def test_6_projective_measurement_born_rule():
    print("\n--- 6. Testing Projective Born-Rule Measurements ---")
    state_vec = [math.sqrt(0.8), math.sqrt(0.2)]
    res = analyze_projective_measurements(state_vec)
    assert abs(res["secure_probability"] - 0.8) < 1e-4
    assert abs(res["threat_probability"] - 0.2) < 1e-4
    assert abs(res["secure_probability"] + res["threat_probability"] - 1.0) < 1e-4

    stoch = simulate_stochastic_measurements(state_vec, number_of_shots=1000, seed=42)
    assert stoch["number_of_shots"] == 1000
    assert abs(stoch["simulated_secure_rate"] - 0.8) < 0.05
    print(f"[PASS] Projective P(secure)={res['secure_probability']:.4f}, Stochastic fraction secure={stoch['simulated_secure_rate']:.4f}")


def test_7_forgery_risk_model_and_disclaimer():
    print("\n--- 7. Testing Forgery Risk Estimate & Scientific Disclaimers ---")
    forg_valid = calculate_forgery_probability_estimate(
        signature_validity=1.0,
        hash_integrity=1.0,
        public_key_validity=1.0,
        metadata_consistency=1.0,
        state_disturbance=0.0,
        pauli_disturbance=0.0
    )
    assert forg_valid["forgery_risk_percentage"] == 0.0
    assert forg_valid["forgery_risk_level"] == "LOW"
    assert "scientific_disclaimer" in forg_valid
    assert "not represent a physical quantum computation" in forg_valid["scientific_disclaimer"]

    forg_bad = calculate_forgery_probability_estimate(
        signature_validity=0.0,
        hash_integrity=0.0,
        public_key_validity=0.0,
        metadata_consistency=0.0,
        state_disturbance=1.0,
        pauli_disturbance=1.0
    )
    assert forg_bad["forgery_risk_percentage"] == 100.0
    assert forg_bad["forgery_risk_level"] == "CRITICAL"
    print(f"[PASS] Forgery estimates: Valid={forg_valid['forgery_risk_percentage']}%, Forged={forg_bad['forgery_risk_percentage']}%. Disclaimer verified.")


def test_8_threat_engine_composite_risk_and_bell_channel():
    print("\n--- 8. Testing Threat Engine, Composite Risk & Decoupled Bell Channel ---")
    params_forged = build_security_parameter_vector(signature_validity=0.0)
    p_forged = evaluate_pauli_disturbances(params_forged)
    f_forged = calculate_forgery_probability_estimate(0.0, 1.0, 1.0, 1.0, 0.5, p_forged["combined_pauli_disturbance"])
    threats_forged = evaluate_deterministic_threats(params_forged, 0.5, p_forged, f_forged)
    assert any(t["threat_category"] == "DIGITAL_SIGNATURE_FORGERY" for t in threats_forged)

    params_tampered = build_security_parameter_vector(hash_integrity=0.0)
    threats_tampered = evaluate_deterministic_threats(params_tampered)
    assert any(t["threat_category"] == "DOCUMENT_TAMPERING" for t in threats_tampered)

    params_replay = build_security_parameter_vector(replay_safety=0.0)
    threats_replay = evaluate_deterministic_threats(params_replay)
    assert any(t["threat_category"] == "REPLAY_ATTACK" for t in threats_replay)

    bell_sim_ideal = simulate_quantum_channel(scenario="NO_ATTACK")
    assert abs(bell_sim_ideal["fidelity"] - 1.0) < 1e-6
    assert bell_sim_ideal["threat_detected"] is False

    bell_sim_noisy = simulate_quantum_channel(scenario="PAULI_X_DISTURBANCE")
    assert bell_sim_noisy["fidelity"] < 0.1
    assert bell_sim_noisy["threat_detected"] is True
    assert "scientific_disclaimer" in bell_sim_noisy

    risk_valid = calculate_composite_risk_score(
        security_parameters=build_security_parameter_vector(),
        state_disturbance=0.0,
        combined_pauli_disturbance=0.0,
        forgery_risk_percentage=0.0
    )
    assert risk_valid["composite_risk_score"] == 0.0
    assert risk_valid["risk_level"] == "LOW"

    risk_crit = calculate_composite_risk_score(
        security_parameters=build_security_parameter_vector(signature_validity=0.0, hash_integrity=0.0),
        state_disturbance=0.9,
        combined_pauli_disturbance=0.95,
        forgery_risk_percentage=90.0
    )
    assert risk_crit["composite_risk_score"] >= 85.0
    assert risk_crit["risk_level"] == "CRITICAL"

    run0 = calculate_composite_risk_score(params_forged, 0.5, 0.6, 50.0)
    for _ in range(20):
        run_i = calculate_composite_risk_score(params_forged, 0.5, 0.6, 50.0)
        assert run_i["composite_risk_score"] == run0["composite_risk_score"]
        assert run_i["risk_level"] == run0["risk_level"]
        assert run_i["contributing_factors"] == run0["contributing_factors"]

    print(f"[PASS] Threats detected: Forgery, Tampering, Replay.")
    print(f"[PASS] Bell channel simulation: Ideal fidelity={bell_sim_ideal['fidelity']}, Noisy fidelity={bell_sim_noisy['fidelity']:.4f}")
    print(f"[PASS] Composite risk scores: Valid={risk_valid['composite_risk_score']}, Critical={risk_crit['composite_risk_score']}.")
    print("[PASS] 20/20 consecutive executions yielded 100.0% identical deterministic results!")


def run_all_tests():
    print("==================================================================")
    print("RUNNING STEP 5 - QUANTUM THREAT ENGINE COMPREHENSIVE TEST SUITE")
    print("==================================================================")
    test_1_quantum_states_and_math()
    test_2_bell_states_orthogonality()
    test_3_pauli_operators_and_disturbances()
    test_4_quantum_metrics()
    test_5_security_state_vector_and_superposition()
    test_6_projective_measurement_born_rule()
    test_7_forgery_risk_model_and_disclaimer()
    test_8_threat_engine_composite_risk_and_bell_channel()
    print("\n==================================================================")
    print("ALL STEP 5 QUANTUM THREAT ENGINE TESTS PASSED WITH 100% SUCCESS!")
    print("==================================================================")


if __name__ == "__main__":
    run_all_tests()

