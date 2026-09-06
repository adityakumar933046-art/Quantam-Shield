"""
Comprehensive Verification Test Suite for Quantum Mathematical Core.

Tests all 10 requirements:
1. State normalization.
2. Pauli X changes |0> to |1>.
3. Pauli Z applies phase change correctly.
4. Bell states are normalized.
5. Fidelity of identical states is 1.
6. Fidelity is between 0 and 1.
7. Disturbance of identical states is 0.
8. Consistency of identical states is 1.
9. Measurement probabilities are valid.
10. Invalid input is handled safely.
"""

import sys
import os
import unittest
import numpy as np

# Ensure backend root is in sys.path when running directly
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    STATE_PLUS,
    STATE_MINUS,
    STATE_I_PLUS,
    STATE_I_MINUS,
    normalize_state,
    state_inner_product,
    state_fidelity,
    is_valid_state,
)
from quantum_engine.bell_states import (
    STATE_00,
    STATE_01,
    STATE_10,
    STATE_11,
    BELL_PHI_PLUS,
    BELL_PHI_MINUS,
    BELL_PSI_PLUS,
    BELL_PSI_MINUS,
    get_bell_state,
    get_all_bell_states,
    bell_state_fidelity,
)
from quantum_engine.pauli_operations import (
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    apply_pauli,
    apply_x,
    apply_y,
    apply_z,
    apply_identity,
    calculate_state_change,
)
from quantum_engine.metrics import (
    calculate_measurement_probability,
    calculate_state_disturbance,
    calculate_consistency_score,
    calculate_measurement_distribution,
    calculate_deviation,
)


class TestQuantumEngineCore(unittest.TestCase):
    """Test suite verifying mathematical precision of the quantum engine core."""

    # --------------------------------------------------------------------------
    # 1. State Normalization
    # --------------------------------------------------------------------------
    def test_01_state_normalization(self):
        """Test 1: Verify state normalization to Euclidean norm 1.0."""
        # Unnormalized state [3.0, 4.0] has norm sqrt(9 + 16) = 5.0
        raw_state = np.array([3.0, 4.0], dtype=np.complex128)
        norm_state = normalize_state(raw_state)

        # Norm must equal exactly 1.0 within tolerance
        norm = np.linalg.norm(norm_state)
        self.assertAlmostEqual(norm, 1.0, places=9)
        self.assertTrue(is_valid_state(norm_state))
        self.assertAlmostEqual(norm_state[0].real, 3.0 / 5.0, places=9)
        self.assertAlmostEqual(norm_state[1].real, 4.0 / 5.0, places=9)

        # Pre-defined basis states must already be normalized
        for name, st in [
            ("STATE_0", STATE_0),
            ("STATE_1", STATE_1),
            ("STATE_PLUS", STATE_PLUS),
            ("STATE_MINUS", STATE_MINUS),
            ("STATE_I_PLUS", STATE_I_PLUS),
            ("STATE_I_MINUS", STATE_I_MINUS),
        ]:
            self.assertTrue(is_valid_state(st), f"{name} must be a valid normalized state.")
            self.assertAlmostEqual(np.linalg.norm(st), 1.0, places=9)

    # --------------------------------------------------------------------------
    # 2. Pauli X Bit-Flip: |0> -> |1>
    # --------------------------------------------------------------------------
    def test_02_pauli_x_changes_0_to_1(self):
        """Test 2: Verify Pauli X transforms |0> to |1> and |1> to |0>."""
        res_0 = apply_x(STATE_0)
        fid_to_1 = state_fidelity(res_0, STATE_1)
        self.assertAlmostEqual(fid_to_1, 1.0, places=9)
        np.testing.assert_allclose(res_0, STATE_1, atol=1e-9)

        res_1 = apply_x(STATE_1)
        fid_to_0 = state_fidelity(res_1, STATE_0)
        self.assertAlmostEqual(fid_to_0, 1.0, places=9)
        np.testing.assert_allclose(res_1, STATE_0, atol=1e-9)

    # --------------------------------------------------------------------------
    # 3. Pauli Z Phase-Flip
    # --------------------------------------------------------------------------
    def test_03_pauli_z_phase_change(self):
        """Test 3: Verify Pauli Z preserves |0> and applies phase change -1 to |1>, and |+> -> |->."""
        # Z|0> = |0>
        z_0 = apply_z(STATE_0)
        np.testing.assert_allclose(z_0, STATE_0, atol=1e-9)

        # Z|1> = -|1>
        z_1 = apply_z(STATE_1)
        np.testing.assert_allclose(z_1, -1.0 * STATE_1, atol=1e-9)
        # Fidelity with |1> is still 1 (global phase does not affect fidelity)
        self.assertAlmostEqual(state_fidelity(z_1, STATE_1), 1.0, places=9)

        # Z|+> = |->
        z_plus = apply_z(STATE_PLUS)
        fid_to_minus = state_fidelity(z_plus, STATE_MINUS)
        self.assertAlmostEqual(fid_to_minus, 1.0, places=9)
        np.testing.assert_allclose(z_plus, STATE_MINUS, atol=1e-9)

    # --------------------------------------------------------------------------
    # 4. Bell States Normalization & Orthogonality
    # --------------------------------------------------------------------------
    def test_04_bell_states_are_normalized(self):
        """Test 4: Verify all four Bell states are normalized to 1.0 and mutually orthonormal."""
        bell_dict = get_all_bell_states()
        self.assertEqual(len(bell_dict), 4)

        for name, b_state in bell_dict.items():
            self.assertEqual(b_state.shape, (4,), f"{name} must be 4D vector.")
            norm = np.linalg.norm(b_state)
            self.assertAlmostEqual(norm, 1.0, places=9, msg=f"{name} must have unit norm.")

        # Also check named getter
        phi_p = get_bell_state("phi_plus")
        phi_m = get_bell_state("phi_minus")
        psi_p = get_bell_state("psi_plus")
        psi_m = get_bell_state("psi_minus")

        # Mutually orthogonal: fidelity between distinct Bell states must be 0.0
        self.assertAlmostEqual(bell_state_fidelity(phi_p, phi_m), 0.0, places=9)
        self.assertAlmostEqual(bell_state_fidelity(phi_p, psi_p), 0.0, places=9)
        self.assertAlmostEqual(bell_state_fidelity(phi_p, psi_m), 0.0, places=9)
        self.assertAlmostEqual(bell_state_fidelity(phi_m, psi_p), 0.0, places=9)
        self.assertAlmostEqual(bell_state_fidelity(psi_p, psi_m), 0.0, places=9)

    # --------------------------------------------------------------------------
    # 5. Fidelity of Identical States is 1.0
    # --------------------------------------------------------------------------
    def test_05_fidelity_of_identical_states(self):
        """Test 5: Verify quantum fidelity F(|ψ>, |ψ>) = 1.0 for all states."""
        test_states = [
            STATE_0,
            STATE_1,
            STATE_PLUS,
            STATE_MINUS,
            STATE_I_PLUS,
            STATE_I_MINUS,
            BELL_PHI_PLUS,
            np.array([1.0 + 2.0j, 3.0 - 1.0j], dtype=np.complex128),
        ]
        for st in test_states:
            fid = state_fidelity(st, st)
            self.assertAlmostEqual(fid, 1.0, places=9)

    # --------------------------------------------------------------------------
    # 6. Fidelity is Strictly Bounded in [0, 1]
    # --------------------------------------------------------------------------
    def test_06_fidelity_bounded_between_zero_and_one(self):
        """Test 6: Verify fidelity strictly satisfies 0.0 <= F <= 1.0 across diverse vectors."""
        # Orthogonal pair: |0> and |1>
        fid_ortho = state_fidelity(STATE_0, STATE_1)
        self.assertEqual(fid_ortho, 0.0)

        # Overlapping non-orthogonal pair: |0> and |+> (F = 1/2)
        fid_half = state_fidelity(STATE_0, STATE_PLUS)
        self.assertAlmostEqual(fid_half, 0.5, places=9)

        # Random normalized states
        np.random.seed(42)
        for _ in range(50):
            v1 = np.random.randn(2) + 1j * np.random.randn(2)
            v2 = np.random.randn(2) + 1j * np.random.randn(2)
            f = state_fidelity(v1, v2)
            self.assertGreaterEqual(f, 0.0)
            self.assertLessEqual(f, 1.0)

    # --------------------------------------------------------------------------
    # 7. Disturbance of Identical States is 0.0
    # --------------------------------------------------------------------------
    def test_07_disturbance_of_identical_states_is_zero(self):
        """Test 7: Verify disturbance D(|ψ>, |ψ>) = 0.0 and D(|0>, |1>) = 1.0."""
        # Disturbance for identity operation
        dist_0 = calculate_state_change(STATE_0, apply_identity(STATE_0))
        self.assertAlmostEqual(dist_0, 0.0, places=9)

        dist_plus = calculate_state_disturbance(STATE_PLUS, STATE_PLUS)
        self.assertAlmostEqual(dist_plus, 0.0, places=9)

        # Maximum disturbance for orthogonal states
        dist_max = calculate_state_disturbance(STATE_0, STATE_1)
        self.assertAlmostEqual(dist_max, 1.0, places=9)

    # --------------------------------------------------------------------------
    # 8. Consistency of Identical States is 1.0
    # --------------------------------------------------------------------------
    def test_08_consistency_of_identical_states_is_one(self):
        """Test 8: Verify consistency score C(|ψ>, |ψ>) = 1.0 and C(|0>, |1>) = 0.0."""
        score_0 = calculate_consistency_score(STATE_0, STATE_0)
        self.assertAlmostEqual(score_0, 1.0, places=9)

        score_bell = calculate_consistency_score(BELL_PHI_PLUS, BELL_PHI_PLUS)
        self.assertAlmostEqual(score_bell, 1.0, places=9)

        score_mismatch = calculate_consistency_score(STATE_0, STATE_1)
        self.assertAlmostEqual(score_mismatch, 0.0, places=9)

    # --------------------------------------------------------------------------
    # 9. Measurement Probabilities are Valid (Born Rule)
    # --------------------------------------------------------------------------
    def test_09_measurement_probabilities_valid(self):
        """Test 9: Verify Born rule probabilities P(i) in [0, 1] and sum to 1.0."""
        # Measurement of |0> in Z basis {|0>, |1>}
        p0 = calculate_measurement_probability(STATE_0, STATE_0)
        p1 = calculate_measurement_probability(STATE_0, STATE_1)
        self.assertAlmostEqual(p0, 1.0, places=9)
        self.assertAlmostEqual(p1, 0.0, places=9)
        self.assertAlmostEqual(p0 + p1, 1.0, places=9)

        # Measurement of |+> in Z basis: P(0) = 0.5, P(1) = 0.5
        p_plus_0 = calculate_measurement_probability(STATE_PLUS, STATE_0)
        p_plus_1 = calculate_measurement_probability(STATE_PLUS, STATE_1)
        self.assertAlmostEqual(p_plus_0, 0.5, places=9)
        self.assertAlmostEqual(p_plus_1, 0.5, places=9)
        self.assertAlmostEqual(p_plus_0 + p_plus_1, 1.0, places=9)

        # Ensemble measurement distribution
        ensemble = [STATE_0, STATE_1, STATE_PLUS, STATE_MINUS]
        dist = calculate_measurement_distribution(ensemble, [STATE_0, STATE_1])
        self.assertEqual(len(dist), 2)
        self.assertAlmostEqual(np.sum(dist), 1.0, places=9)
        self.assertAlmostEqual(dist[0], 0.5, places=9)
        self.assertAlmostEqual(dist[1], 0.5, places=9)

        # Statistical deviation (Total Variation Distance)
        dev_zero = calculate_deviation([0.5, 0.5], [0.5, 0.5])
        self.assertAlmostEqual(dev_zero, 0.0, places=9)

        dev_max = calculate_deviation([1.0, 0.0], [0.0, 1.0])
        self.assertAlmostEqual(dev_max, 1.0, places=9)

    # --------------------------------------------------------------------------
    # 10. Invalid Input Handled Safely
    # --------------------------------------------------------------------------
    def test_10_invalid_input_handled_safely(self):
        """Test 10: Verify invalid inputs (zero vectors, NaN, inf, dimension mismatches) are handled safely."""
        # Zero norm vector should raise ValueError in normalize_state
        with self.assertRaises(ValueError):
            normalize_state(np.array([0.0, 0.0]))

        # None state
        with self.assertRaises(ValueError):
            normalize_state(None)

        # Empty array
        with self.assertRaises(ValueError):
            normalize_state([])

        # NaN / Inf in vector
        with self.assertRaises(ValueError):
            normalize_state([np.nan, 1.0])
        with self.assertRaises(ValueError):
            normalize_state([np.inf, 1.0])

        # is_valid_state must safely return False without raising exceptions
        self.assertFalse(is_valid_state([0.0, 0.0]))
        self.assertFalse(is_valid_state(None))
        self.assertFalse(is_valid_state([]))
        self.assertFalse(is_valid_state([np.nan, 0.0]))
        self.assertFalse(is_valid_state([1.0, 1.0]))  # norm is sqrt(2) != 1

        # Dimension mismatch in inner product
        with self.assertRaises(ValueError):
            state_inner_product(STATE_0, BELL_PHI_PLUS)

        # Unknown Bell state name
        with self.assertRaises(ValueError):
            get_bell_state("non_existent_bell_state")

        # Unknown Pauli operation
        with self.assertRaises(ValueError):
            apply_pauli(STATE_0, "invalid_op")

        # Invalid distribution for deviation
        with self.assertRaises(ValueError):
            calculate_deviation([0.5, 0.5], [0.5, 0.3, 0.2])  # Length mismatch


def run_tests():
    """Runs the test suite and prints clean summary."""
    print("=" * 70)
    print("RUNNING STEP 1: QUANTUM MATHEMATICAL CORE VERIFICATION")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestQuantumEngineCore)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print("ALL 10 QUANTUM MATHEMATICAL CORE TESTS PASSED WITH 100% PRECISION!")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print("TEST FAILURES DETECTED IN QUANTUM MATHEMATICAL CORE.")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
