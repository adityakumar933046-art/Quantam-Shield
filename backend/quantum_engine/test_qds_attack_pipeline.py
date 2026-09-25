"""
Unit and Integration Tests for End-to-End QDS Attack Simulation Pipeline.

Module: quantum_engine.test_qds_attack_pipeline
Validates:
1. Honest baseline: accepted, high fidelity, low risk, no threat
2. Deterministic reproducibility with identical seeds
3. Random-state forgery attack detection
4. Bit-flip (Pauli X) attack channel disturbance
5. Phase-flip (Pauli Z) attack with basis-dependent observability
6. Intercept-resend eavesdropping attack detection
7. Multi-scenario attack comparison runner
8. Threat classification consistency
9. Risk score bounding within [0, 100] across all scenarios
10. Honest scenario never triggers channel manipulation
11. Forgery scenario produces elevated forgery evidence
12. Bit-flip produces substantial channel disturbance
13. Intercept-resend produces statistical distribution anomaly
14. Preservation of existing platform threat categories
15. Invalid attack type raises ValueError
16. Invalid key length raises ValueError
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
from quantum_engine.qds_attack_pipeline import (
    run_qds_attack_simulation,
    run_all_qds_attack_scenarios,
    SUPPORTED_QDS_ATTACKS,
)
from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD,
)
from quantum_engine.threat_detector import evaluate_deterministic_threats


class TestQDSAttackPipeline(unittest.TestCase):
    """Test suite for end-to-end QDS attack simulation pipeline."""

    def setUp(self):
        self.test_hash = "a1b2c3d4"  # 8 hex chars = 32 bits
        self.key_length = 32
        self.seed = 4242

    # --------------------------------------------------------------------------
    # 1. Honest Baseline
    # --------------------------------------------------------------------------
    def test_01_honest_baseline(self):
        res = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="none",
            key_length=self.key_length,
            seed=self.seed
        )

        self.assertEqual(res["protocol"], "QDS")
        self.assertEqual(res["attack_type"], "none")
        self.assertTrue(res["verification"]["accepted"])
        self.assertEqual(res["verification"]["mismatches"], 0)
        self.assertEqual(res["verification"]["mismatch_rate"], 0.0)
        self.assertGreaterEqual(res["teleportation"]["attacked_average_fidelity"], 0.99)
        self.assertFalse(res["threat"]["detected"])
        self.assertEqual(res["threat"]["type"], "NONE")
        self.assertEqual(res["threat"]["severity"], "LOW")
        self.assertLessEqual(res["risk"]["score"], 20.0)
        self.assertEqual(res["risk"]["tier"], "LOW")

    # --------------------------------------------------------------------------
    # 2. Deterministic Reproducibility
    # --------------------------------------------------------------------------
    def test_02_deterministic_reproducibility(self):
        run_1 = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="random_state_substitution",
            key_length=self.key_length,
            seed=999
        )
        run_2 = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="random_state_substitution",
            key_length=self.key_length,
            seed=999
        )

        self.assertEqual(run_1["verification"]["mismatches"], run_2["verification"]["mismatches"])
        self.assertEqual(run_1["verification"]["mismatch_rate"], run_2["verification"]["mismatch_rate"])
        self.assertEqual(run_1["teleportation"]["attacked_average_fidelity"], run_2["teleportation"]["attacked_average_fidelity"])
        self.assertEqual(run_1["threat"]["detected"], run_2["threat"]["detected"])
        self.assertEqual(run_1["risk"]["score"], run_2["risk"]["score"])

    # --------------------------------------------------------------------------
    # 3. Random-State Forgery Attack
    # --------------------------------------------------------------------------
    def test_03_random_state_forgery_attack(self):
        res = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="random_state_substitution",
            key_length=self.key_length,
            seed=self.seed
        )

        self.assertFalse(res["verification"]["accepted"])
        self.assertGreater(res["verification"]["mismatch_rate"], QDS_VERIFICATION_THRESHOLD)
        self.assertTrue(res["threat"]["detected"])
        self.assertIn(res["threat"]["type"], ["DIGITAL_SIGNATURE_FORGERY", "QUANTUM_CHANNEL_MANIPULATION"])
        self.assertIn(res["threat"]["severity"], ["HIGH", "CRITICAL"])
        self.assertGreater(res["risk"]["score"], 40.0)

    # --------------------------------------------------------------------------
    # 4. Bit-Flip Attack
    # --------------------------------------------------------------------------
    def test_04_bit_flip_attack(self):
        res = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="bit_flip",
            key_length=self.key_length,
            seed=self.seed
        )

        # Inversion of states leads to high disturbance
        dist = 1.0 - res["teleportation"]["attacked_average_fidelity"]
        self.assertGreaterEqual(dist, QDS_CHANNEL_DISTURBANCE_THRESHOLD)
        self.assertTrue(res["threat"]["detected"])
        self.assertIn(res["threat"]["type"], ["QUANTUM_CHANNEL_MANIPULATION", "DIGITAL_SIGNATURE_FORGERY"])
        self.assertIn(res["threat"]["severity"], ["HIGH", "CRITICAL"])

    # --------------------------------------------------------------------------
    # 5. Phase-Flip Attack (Basis-Dependent Observability)
    # --------------------------------------------------------------------------
    def test_05_phase_flip_attack_basis_dependence(self):
        # Scientific Note: Pauli Z preserves Z-basis (|0> -> |0>, |1> -> -|1>),
        # but inverts conjugate X-basis (|+> -> |->, |-> -> |+>).
        # Therefore, only X-basis qubits trigger projective measurement mismatches.
        res = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="phase_flip",
            key_length=self.key_length,
            seed=self.seed
        )

        bases = res["signature"]["bases_used"]
        x_count = bases.get("X", 0)

        # Disturbance must be non-zero if X-basis qubits were present
        if x_count > 0:
            self.assertGreater(res["verification"]["mismatches"], 0)
            self.assertGreater(res["verification"]["mismatch_rate"], 0.0)
            self.assertTrue(res["threat"]["detected"])

    # --------------------------------------------------------------------------
    # 6. Intercept-Resend Attack
    # --------------------------------------------------------------------------
    def test_06_intercept_resend_attack(self):
        res = run_qds_attack_simulation(
            message_hash=self.test_hash,
            attack_type="intercept_resend",
            key_length=self.key_length,
            seed=self.seed
        )

        # Measurement collapse alters superposition states, inducing non-zero disturbance
        dist = 1.0 - res["teleportation"]["attacked_average_fidelity"]
        self.assertGreater(dist, 0.05)
        self.assertTrue(res["threat"]["detected"])
        self.assertIn(res["threat"]["type"], ["QUANTUM_CHANNEL_MANIPULATION", "DIGITAL_SIGNATURE_FORGERY"])

    # --------------------------------------------------------------------------
    # 7. All Attack Scenarios Runner
    # --------------------------------------------------------------------------
    def test_07_all_attack_scenarios_runner(self):
        comp = run_all_qds_attack_scenarios(
            message_hash=self.test_hash,
            key_length=self.key_length,
            seed=self.seed
        )

        self.assertEqual(len(comp["scenarios"]), len(SUPPORTED_QDS_ATTACKS))
        attack_types_present = [s["attack_type"] for s in comp["scenarios"]]
        for expected in SUPPORTED_QDS_ATTACKS:
            self.assertIn(expected, attack_types_present)

        summary = comp["summary"]
        self.assertEqual(summary["total_scenarios"], 5)
        self.assertEqual(summary["attacks_evaluated"], 4)
        self.assertGreaterEqual(summary["attacks_detected"], 3)
        self.assertGreaterEqual(summary["detection_rate_percentage"], 75.0)

    # --------------------------------------------------------------------------
    # 8. Threat Classification Consistency
    # --------------------------------------------------------------------------
    def test_08_threat_classification_consistency(self):
        res_none = run_qds_attack_simulation(self.test_hash, "none", self.key_length, self.seed)
        self.assertEqual(res_none["threat"]["type"], "NONE")

        res_forge = run_qds_attack_simulation(self.test_hash, "random_state_substitution", self.key_length, self.seed)
        self.assertIn(res_forge["threat"]["type"], ["DIGITAL_SIGNATURE_FORGERY", "QUANTUM_CHANNEL_MANIPULATION"])

        res_bit = run_qds_attack_simulation(self.test_hash, "bit_flip", self.key_length, self.seed)
        self.assertIn(res_bit["threat"]["type"], ["QUANTUM_CHANNEL_MANIPULATION", "DIGITAL_SIGNATURE_FORGERY"])

    # --------------------------------------------------------------------------
    # 9. Risk Score Bounded [0, 100]
    # --------------------------------------------------------------------------
    def test_09_risk_score_bounded_in_all_scenarios(self):
        for attack in SUPPORTED_QDS_ATTACKS:
            res = run_qds_attack_simulation(self.test_hash, attack, self.key_length, self.seed)
            risk = res["risk"]["score"]
            tier = res["risk"]["tier"]
            self.assertTrue(0.0 <= risk <= 100.0, f"Risk {risk} out of [0, 100] for {attack}")
            self.assertIn(tier, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    # --------------------------------------------------------------------------
    # 10. Honest Scenario Does Not Trigger Channel Attack
    # --------------------------------------------------------------------------
    def test_10_honest_does_not_trigger_channel_attack(self):
        res = run_qds_attack_simulation(self.test_hash, "none", self.key_length, self.seed)
        self.assertFalse(res["threat"]["detected"])
        self.assertNotEqual(res["threat"]["type"], "QUANTUM_CHANNEL_MANIPULATION")
        self.assertLess(1.0 - res["teleportation"]["attacked_average_fidelity"], QDS_CHANNEL_DISTURBANCE_THRESHOLD)

    # --------------------------------------------------------------------------
    # 11. Forgery Scenario Produces Forgery Evidence
    # --------------------------------------------------------------------------
    def test_11_forgery_scenario_produces_forgery_evidence(self):
        res = run_qds_attack_simulation(self.test_hash, "random_state_substitution", self.key_length, self.seed)
        self.assertFalse(res["verification"]["accepted"])
        self.assertGreater(res["verification"]["mismatches"], 0)
        self.assertGreater(res["risk"]["score"], 20.0)

    # --------------------------------------------------------------------------
    # 12. Bit-Flip Produces Channel Disturbance
    # --------------------------------------------------------------------------
    def test_12_bit_flip_produces_channel_disturbance(self):
        res = run_qds_attack_simulation(self.test_hash, "bit_flip", self.key_length, self.seed)
        disturbance = 1.0 - res["teleportation"]["attacked_average_fidelity"]
        self.assertGreaterEqual(disturbance, QDS_CHANNEL_DISTURBANCE_THRESHOLD)

    # --------------------------------------------------------------------------
    # 13. Intercept-Resend Produces Statistical Anomaly
    # --------------------------------------------------------------------------
    def test_13_intercept_resend_produces_statistical_anomaly(self):
        res = run_qds_attack_simulation(self.test_hash, "intercept_resend", self.key_length, self.seed)
        dist_distance = res["statistics"]["distribution_distance"]
        mismatch_rate = res["verification"]["mismatch_rate"]
        # Intercept-resend collapses quantum superposition, causing detectable skew
        self.assertTrue(dist_distance > 0.0 or mismatch_rate > 0.0)

    # --------------------------------------------------------------------------
    # 14. Existing Threat Categories Remain Functional
    # --------------------------------------------------------------------------
    def test_14_existing_threat_categories_functional(self):
        params = {
            "signature_validity": 1.0,
            "hash_integrity": 1.0,
            "public_key_validity": 1.0,
            "certificate_validity": 1.0,
            "metadata_consistency": 1.0,
            "signature_consistency": 1.0,
            "replay_safety": 1.0,
            "activity_safety": 1.0
        }
        # Verify classical rules still detect standard threats
        t_replay = evaluate_deterministic_threats({**params, "replay_safety": 0.0})
        self.assertTrue(any(t["threat_category"] == "REPLAY_ATTACK" for t in t_replay))

        t_tamper = evaluate_deterministic_threats({**params, "hash_integrity": 0.0})
        self.assertTrue(any(t["threat_category"] == "DOCUMENT_TAMPERING" for t in t_tamper))

    # --------------------------------------------------------------------------
    # 15. Invalid Attack Type Raises ValueError
    # --------------------------------------------------------------------------
    def test_15_invalid_attack_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            run_qds_attack_simulation(self.test_hash, "quantum_entanglement_destroyer", self.key_length)

    # --------------------------------------------------------------------------
    # 16. Invalid Key Length Handled Correctly
    # --------------------------------------------------------------------------
    def test_16_invalid_key_length_raises_value_error(self):
        # 32 bits required for 8 hex chars; length 10 is too short
        with self.assertRaises(ValueError):
            run_qds_attack_simulation(self.test_hash, "none", key_length=10)

        with self.assertRaises(ValueError):
            run_qds_attack_simulation(self.test_hash, "none", key_length=0)


if __name__ == "__main__":
    unittest.main()
