"""
Unit and Integration Tests for QDS Statistical Analysis & Threat Detection.

Module: quantum_engine.test_qds_statistical_analysis
Validates:
1. Perfect honest measurements
2. Threshold boundary conditions
3. Threshold exceeded conditions
4. Total Variation Distance for identical distributions
5. Total Variation Distance for divergent distributions
6. Chi-Square calculation with valid sample size
7. Chi-Square calculation with insufficient sample size
8. Honest teleportation produces no threat
9. Bit-flip attack disturbance detection
10. Phase-flip attack disturbance detection
11. Intercept-resend attack statistical disturbance detection
12. Forged signature rejection & forgery threat classification
13. Non-repudiation mismatch detection
14. Replay attack detection preservation
15. Unauthorized verification detection preservation
16. Unaltered existing threat categories
17. Risk score bounding [0, 100] with QDS evidence
18. Absence of AI/ML dependencies
"""

import sys
import unittest
from pathlib import Path
import numpy as np

# Ensure backend root is on sys.path
backend_path = Path(__file__).resolve().parent.parent
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

import quantum_engine as qe
from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    QDS_REPUDIATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD,
    CHI_SQUARE_MIN_SAMPLE_SIZE,
    CHI_SQUARE_MIN_EXPECTED_COUNT,
    get_qds_thresholds
)
from quantum_engine.measurement_analysis import (
    calculate_chi_square,
    calculate_total_variation_distance,
    analyze_qds_measurements
)
from quantum_engine.threat_detector import (
    build_qds_threat_evidence,
    evaluate_qds_threats,
    analyze_quantum_channel_attack,
    evaluate_deterministic_threats
)
from quantum_engine.forgery_probability import (
    calculate_forgery_probability_estimate,
    calculate_qds_forgery_probability_estimate
)
from quantum_engine.risk_engine import (
    calculate_composite_risk_score
)
from quantum_engine.qds_protocol import (
    generate_qds_key_pair,
    sign_hash_qds,
    teleport_signature,
    verify_signature_qds,
    forge_qds_signature,
    verify_non_repudiation_qds
)


class TestQDSStatisticalAnalysis(unittest.TestCase):
    """Test suite for QDS statistical analysis, threat evidence, and risk integration."""

    def setUp(self):
        self.key_pair = generate_qds_key_pair(length=32, seed=12345)
        self.message_hash = "a1b2c3d4"  # 8 hex chars = 32 bits
        self.signature = sign_hash_qds(self.message_hash, self.key_pair)

    # --------------------------------------------------------------------------
    # 1. Perfect Honest Measurements
    # --------------------------------------------------------------------------
    def test_01_perfect_honest_measurements(self):
        observed = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        expected = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]

        res = analyze_qds_measurements(observed, expected, threshold=0.10)

        self.assertEqual(res["total_measurements"], 10)
        self.assertEqual(res["matches"], 10)
        self.assertEqual(res["mismatches"], 0)
        self.assertEqual(res["mismatch_rate"], 0.0)
        self.assertEqual(res["accuracy"], 1.0)
        self.assertTrue(res["accepted"])
        self.assertEqual(res["distribution_distance"], 0.0)

    # --------------------------------------------------------------------------
    # 2. Threshold Boundary (Exactly on threshold -> Accepted)
    # --------------------------------------------------------------------------
    def test_02_threshold_boundary(self):
        # 10 measurements, exactly 1 mismatch = 10% mismatch
        observed = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        expected = [0, 1, 0, 1, 0, 1, 0, 1, 0, 0]  # last bit differs

        res = analyze_qds_measurements(observed, expected, threshold=0.10)

        self.assertEqual(res["total_measurements"], 10)
        self.assertEqual(res["mismatches"], 1)
        self.assertAlmostEqual(res["mismatch_rate"], 0.10, places=5)
        self.assertTrue(res["accepted"], "Boundary condition epsilon == threshold must be accepted.")

    # --------------------------------------------------------------------------
    # 3. Threshold Exceeded (Rejected)
    # --------------------------------------------------------------------------
    def test_03_threshold_exceeded(self):
        # 10 measurements, 2 mismatches = 20% mismatch > 10%
        observed = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        expected = [0, 1, 0, 1, 0, 1, 0, 1, 1, 0]  # last 2 differ

        res = analyze_qds_measurements(observed, expected, threshold=0.10)

        self.assertEqual(res["mismatches"], 2)
        self.assertAlmostEqual(res["mismatch_rate"], 0.20, places=5)
        self.assertFalse(res["accepted"], "Mismatch rate > threshold must be rejected.")

    # --------------------------------------------------------------------------
    # 4. Distribution Distance: Identical Distributions -> 0
    # --------------------------------------------------------------------------
    def test_04_distribution_distance_identical(self):
        dist_a = [0.5, 0.5]
        dist_b = [0.5, 0.5]

        tvd = calculate_total_variation_distance(dist_a, dist_b)
        self.assertAlmostEqual(tvd, 0.0, places=7)

    # --------------------------------------------------------------------------
    # 5. Distribution Distance: Different Distributions -> > 0
    # --------------------------------------------------------------------------
    def test_05_distribution_distance_different(self):
        dist_a = [1.0, 0.0]
        dist_b = [0.0, 1.0]
        tvd_disjoint = calculate_total_variation_distance(dist_a, dist_b)
        self.assertAlmostEqual(tvd_disjoint, 1.0, places=7)

        dist_c = [0.8, 0.2]
        dist_d = [0.2, 0.8]
        tvd_partial = calculate_total_variation_distance(dist_c, dist_d)
        self.assertAlmostEqual(tvd_partial, 0.6, places=5)
        self.assertGreater(tvd_partial, 0.0)

    # --------------------------------------------------------------------------
    # 6. Chi-Square with Valid Sample Size
    # --------------------------------------------------------------------------
    def test_06_chi_square_valid_sample(self):
        # Total sample = 50 >= 20, expected counts = 25 >= 5
        observed = [30, 20]
        expected = [25, 25]

        res = calculate_chi_square(observed, expected)

        self.assertTrue(res["valid"])
        self.assertEqual(res["status"], "valid")
        self.assertEqual(res["degrees_of_freedom"], 1)
        # Chi^2 = (30-25)^2/25 + (20-25)^2/25 = 25/25 + 25/25 = 2.0
        self.assertAlmostEqual(res["chi_square"], 2.0, places=5)

    # --------------------------------------------------------------------------
    # 7. Chi-Square with Insufficient Sample Size
    # --------------------------------------------------------------------------
    def test_07_chi_square_insufficient_sample(self):
        # Sample size = 5 < 20
        observed = [3, 2]
        expected = [2.5, 2.5]

        res = calculate_chi_square(observed, expected)

        self.assertFalse(res["valid"])
        self.assertEqual(res["status"], "insufficient_sample_size")

    # --------------------------------------------------------------------------
    # 8. Honest Teleportation: High Fidelity, No Threat
    # --------------------------------------------------------------------------
    def test_08_honest_teleportation_no_threat(self):
        teleport_res = teleport_signature(self.signature.signature_states, seed=42)
        ver_res = verify_signature_qds(self.signature, teleport_res.received_states, self.key_pair)

        self.assertTrue(ver_res.accepted)
        self.assertGreaterEqual(teleport_res.average_fidelity, 0.99)

        evidence = build_qds_threat_evidence(
            teleportation_average_fidelity=teleport_res.average_fidelity,
            mismatch_rate=ver_res.mismatch_rate,
            measurement_accuracy=1.0 - ver_res.mismatch_rate,
            distribution_distance=0.0
        )
        threat_eval = evaluate_qds_threats(evidence)

        self.assertFalse(threat_eval["threat_detected"])
        self.assertEqual(threat_eval["threat_type"], "NONE")
        self.assertEqual(threat_eval["severity"], "LOW")

    # --------------------------------------------------------------------------
    # 9. Bit-Flip Attack: Disturbance Detected
    # --------------------------------------------------------------------------
    def test_09_bit_flip_attack_disturbance_detected(self):
        forged = forge_qds_signature(self.signature, attack_type="bit_flip")
        analysis = analyze_quantum_channel_attack(
            baseline_states=self.signature.signature_states,
            attacked_states=forged.signature_states,
            attack_type="bit_flip"
        )

        self.assertTrue(analysis["threshold_exceeded"])
        self.assertEqual(analysis["threat_classification"], "QUANTUM_CHANNEL_MANIPULATION")
        self.assertGreaterEqual(analysis["disturbance"], QDS_CHANNEL_DISTURBANCE_THRESHOLD)

    # --------------------------------------------------------------------------
    # 10. Phase-Flip Attack: Disturbance Detected
    # --------------------------------------------------------------------------
    def test_10_phase_flip_attack_disturbance_detected(self):
        forged = forge_qds_signature(self.signature, attack_type="phase_flip")
        analysis = analyze_quantum_channel_attack(
            baseline_states=self.signature.signature_states,
            attacked_states=forged.signature_states,
            attack_type="phase_flip"
        )

        self.assertTrue(analysis["threshold_exceeded"])
        self.assertEqual(analysis["threat_classification"], "QUANTUM_CHANNEL_MANIPULATION")
        self.assertGreaterEqual(analysis["disturbance"], QDS_CHANNEL_DISTURBANCE_THRESHOLD)

    # --------------------------------------------------------------------------
    # 11. Intercept-Resend Attack: Statistical Disturbance Detected
    # --------------------------------------------------------------------------
    def test_11_intercept_resend_attack_statistical_disturbance(self):
        forged = forge_qds_signature(self.signature, attack_type="intercept_resend", seed=42)
        analysis = analyze_quantum_channel_attack(
            baseline_states=self.signature.signature_states,
            attacked_states=forged.signature_states,
            attack_type="intercept_resend"
        )

        self.assertGreater(analysis["disturbance"], 0.05)
        self.assertGreater(analysis["distribution_distance"], 0.0)

    # --------------------------------------------------------------------------
    # 12. Forged Signature: Verification Rejected & Threat Flagged
    # --------------------------------------------------------------------------
    def test_12_forged_signature_verification_rejected(self):
        forged = forge_qds_signature(self.signature, attack_type="random_state_substitution", seed=42)
        ver_res = verify_signature_qds(forged, forged.signature_states, self.key_pair)

        self.assertFalse(ver_res.accepted)
        self.assertGreater(ver_res.mismatch_rate, QDS_VERIFICATION_THRESHOLD)

        evidence = build_qds_threat_evidence(
            teleportation_average_fidelity=0.50,
            mismatch_rate=ver_res.mismatch_rate,
            measurement_accuracy=1.0 - ver_res.mismatch_rate,
            distribution_distance=0.25
        )
        threat_eval = evaluate_qds_threats(evidence)

        self.assertTrue(threat_eval["threat_detected"])
        self.assertIn(threat_eval["threat_type"], ["DIGITAL_SIGNATURE_FORGERY", "QUANTUM_CHANNEL_MANIPULATION"])
        self.assertIn(threat_eval["severity"], ["HIGH", "CRITICAL"])

    # --------------------------------------------------------------------------
    # 13. Non-Repudiation Mismatch Detected
    # --------------------------------------------------------------------------
    def test_13_non_repudiation_mismatch_detected(self):
        bob_measurements = [0] * 20
        charlie_measurements = [1] * 20  # Completely conflicting

        non_rep = verify_non_repudiation_qds(bob_measurements, charlie_measurements, threshold=0.05)
        self.assertFalse(non_rep["consistent"])
        self.assertEqual(non_rep["mismatch_rate"], 1.0)

        evidence = build_qds_threat_evidence(
            teleportation_average_fidelity=1.0,
            mismatch_rate=0.0,
            measurement_accuracy=1.0,
            distribution_distance=0.0,
            non_repudiation_result=non_rep
        )
        threat_eval = evaluate_qds_threats(evidence)

        self.assertTrue(threat_eval["threat_detected"])
        self.assertEqual(threat_eval["threat_type"], "DIGITAL_SIGNATURE_FORGERY")

    # --------------------------------------------------------------------------
    # 14. Replay Evidence: Existing Replay Detector Still Works
    # --------------------------------------------------------------------------
    def test_14_replay_evidence_preserved(self):
        params = {
            "signature_validity": 1.0,
            "hash_integrity": 1.0,
            "public_key_validity": 1.0,
            "certificate_validity": 1.0,
            "metadata_consistency": 1.0,
            "signature_consistency": 1.0,
            "replay_safety": 0.0,  # Replay trigger
            "activity_safety": 1.0
        }
        threats = evaluate_deterministic_threats(params)
        replay_found = any(t.get("threat_type") == "REPLAY_ATTACK" for t in threats)
        self.assertTrue(replay_found)

        # Also via QDS threat evaluation
        evidence = build_qds_threat_evidence(1.0, 0.0, 1.0, 0.0)
        qds_eval = evaluate_qds_threats(evidence, replay_safe=0.0)
        self.assertTrue(qds_eval["threat_detected"])
        self.assertEqual(qds_eval["threat_type"], "REPLAY_ATTACK")

    # --------------------------------------------------------------------------
    # 15. Unauthorized Verification: Existing Detector Still Works
    # --------------------------------------------------------------------------
    def test_15_unauthorized_verification_preserved(self):
        params = {
            "signature_validity": 1.0,
            "hash_integrity": 1.0,
            "activity_safety": 0.2  # Unauthorized trigger
        }
        threats = evaluate_deterministic_threats(params)
        unauth_found = any(t.get("threat_type") == "UNAUTHORIZED_VERIFICATION" for t in threats)
        self.assertTrue(unauth_found)

        evidence = build_qds_threat_evidence(1.0, 0.0, 1.0, 0.0)
        qds_eval = evaluate_qds_threats(evidence, act_safe=0.2)
        self.assertTrue(qds_eval["threat_detected"])
        self.assertEqual(qds_eval["threat_type"], "UNAUTHORIZED_VERIFICATION")

    # --------------------------------------------------------------------------
    # 16. Existing Threat Categories Remain Unchanged
    # --------------------------------------------------------------------------
    def test_16_existing_threat_categories_intact(self):
        expected_categories = {
            "DIGITAL_SIGNATURE_FORGERY",
            "DOCUMENT_TAMPERING",
            "REPLAY_ATTACK",
            "IMPERSONATION",
            "UNAUTHORIZED_VERIFICATION",
            "SIGNATURE_MANIPULATION",
            "CERTIFICATE_PROBLEM",
        }
        # Run nominal with clean params
        clean_params = {
            "signature_validity": 1.0,
            "hash_integrity": 1.0,
            "public_key_validity": 1.0,
            "certificate_validity": 1.0,
            "metadata_consistency": 1.0,
            "signature_consistency": 1.0,
            "replay_safety": 1.0,
            "activity_safety": 1.0
        }
        clean_threats = evaluate_deterministic_threats(clean_params)
        self.assertEqual(len(clean_threats), 0)

        # Trigger each one to verify category naming
        t_tamper = evaluate_deterministic_threats({**clean_params, "hash_integrity": 0.0})
        self.assertEqual(t_tamper[0]["threat_category"], "DOCUMENT_TAMPERING")

        t_imperson = evaluate_deterministic_threats({**clean_params, "metadata_consistency": 0.0})
        self.assertEqual(t_imperson[0]["threat_category"], "IMPERSONATION")

        t_cert = evaluate_deterministic_threats({**clean_params, "certificate_validity": 0.1})
        self.assertEqual(t_cert[0]["threat_category"], "CERTIFICATE_PROBLEM")

    # --------------------------------------------------------------------------
    # 17. Composite Risk Score Remains Bounded in [0, 100]
    # --------------------------------------------------------------------------
    def test_17_risk_score_bounded_with_qds_evidence(self):
        params = {"signature_validity": 1.0, "hash_integrity": 1.0}

        # Nominal case
        risk_clean = calculate_composite_risk_score(params, 0.0, 0.0, 0.0)
        self.assertTrue(0.0 <= risk_clean["final_risk_score"] <= 100.0)
        self.assertEqual(risk_clean["risk_level"], "LOW")

        # High QDS threat case
        qds_ev_forged = {
            "mismatch_rate": 0.60,
            "state_disturbance": 0.70,
            "verification_threshold": 0.10,
            "channel_disturbance_threshold": 0.20
        }
        risk_qds = calculate_composite_risk_score(params, 0.5, 0.5, 50.0, qds_evidence=qds_ev_forged)
        self.assertTrue(0.0 <= risk_qds["final_risk_score"] <= 100.0)
        self.assertIn(risk_qds["risk_level"], ["HIGH", "CRITICAL"])
        self.assertTrue(any("QDS" in factor for factor in risk_qds["contributing_factors"]))

        # Forgery probability estimate with QDS evidence
        forgery_est = calculate_forgery_probability_estimate(
            signature_validity=0.0,
            hash_integrity=1.0,
            public_key_validity=1.0,
            metadata_consistency=1.0,
            state_disturbance=0.5,
            pauli_disturbance=0.5,
            qds_evidence=qds_ev_forged
        )
        self.assertTrue(0.0 <= forgery_est["forgery_risk_percentage"] <= 100.0)
        self.assertIn("qds_mismatch_component", forgery_est["component_factors"])

    # --------------------------------------------------------------------------
    # 18. No AI/ML Dependency Introduced
    # --------------------------------------------------------------------------
    def test_18_no_ai_ml_dependencies(self):
        forbidden_modules = ["torch", "tensorflow", "sklearn", "keras", "xgboost", "scipy.optimize"]
        for mod in forbidden_modules:
            self.assertNotIn(
                mod, sys.modules,
                f"Forbidden ML/AI dependency '{mod}' must not be loaded in quantum_engine."
            )

        thresholds = get_qds_thresholds()
        self.assertIn("verification_threshold", thresholds)
        self.assertIn("repudiation_threshold", thresholds)
        self.assertIn("channel_disturbance_threshold", thresholds)


if __name__ == "__main__":
    unittest.main()
