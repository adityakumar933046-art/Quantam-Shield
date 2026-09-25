"""
Test Suite for Teleportation-Based Quantum Digital Signature (QDS) Protocol Core.

File: backend/quantum_engine/test_qds_protocol.py
Verifies all 18 test requirements:
1. State normalization
2. Allowed state generation
3. Deterministic seeded key generation
4. Different seeds produce different keys
5. Bell pair normalization
6. Teleportation preserves normalized states
7. Teleportation fidelity is approximately 1.0
8. Pauli correction mapping
9. Multi-qubit teleportation
10. Hash-to-bit conversion
11. QDS signature generation
12. Valid signature verification
13. Forged signature rejection
14. Bit-flip attack detection
15. Phase-flip attack detection
16. Non-repudiation consistency
17. Non-repudiation mismatch detection
18. Invalid input handling
"""

import sys
import os
import unittest
import numpy as np

# Ensure backend root is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    STATE_PLUS,
    STATE_MINUS,
    state_fidelity,
    is_valid_state,
)
from quantum_engine.bell_states import BELL_PHI_PLUS
from quantum_engine.qds_protocol import (
    QDSKeyPair,
    QDSSignature,
    TeleportationResult,
    QDSVerificationResult,
    validate_qubit_state,
    state_to_tuple,
    generate_random_state_from_allowed_set,
    generate_qds_key_pair,
    hex_to_bit_sequence,
    sign_hash_qds,
    create_bell_pairs,
    teleport_qubit,
    teleport_signature,
    verify_signature_qds,
    forge_qds_signature,
    verify_non_repudiation_qds,
    ALLOWED_QDS_STATES,
    DEFAULT_T_VER,
)


class TestQDSProtocolCore(unittest.TestCase):

    # --------------------------------------------------------------------------
    # 1. State Normalization
    # --------------------------------------------------------------------------
    def test_01_state_normalization(self):
        for name, state in ALLOWED_QDS_STATES.items():
            norm = np.linalg.norm(state)
            self.assertAlmostEqual(norm, 1.0, places=6, msg=f"State {name} norm is {norm}")
            self.assertTrue(is_valid_state(state))
            vec = validate_qubit_state(state)
            self.assertEqual(vec.shape, (2,))

    # --------------------------------------------------------------------------
    # 2. Allowed State Generation
    # --------------------------------------------------------------------------
    def test_02_allowed_state_generation(self):
        states_seen = set()
        for i in range(100):
            name, st = generate_random_state_from_allowed_set()
            self.assertIn(name, ALLOWED_QDS_STATES)
            self.assertEqual(st.shape, (2,))
            self.assertAlmostEqual(np.linalg.norm(st), 1.0, places=6)
            states_seen.add(name)
        # Should see all 4 canonical states over 100 trials
        self.assertEqual(states_seen, {"|0>", "|1>", "|+>", "|->"})

    # --------------------------------------------------------------------------
    # 3. Deterministic Seeded Key Generation
    # --------------------------------------------------------------------------
    def test_03_deterministic_seeded_key_generation(self):
        key1 = generate_qds_key_pair(length=16, seed=42)
        key2 = generate_qds_key_pair(length=16, seed=42)

        self.assertEqual(key1.basis_sequence, key2.basis_sequence)
        self.assertEqual(len(key1.private_states), 16)
        self.assertEqual(len(key1.public_states), 16)

        for s1, s2 in zip(key1.private_states, key2.private_states):
            self.assertAlmostEqual(state_fidelity(s1, s2), 1.0, places=6)

    # --------------------------------------------------------------------------
    # 4. Different Seeds Produce Different Keys
    # --------------------------------------------------------------------------
    def test_04_different_seeds_produce_different_keys(self):
        key_a = generate_qds_key_pair(length=32, seed=1001)
        key_b = generate_qds_key_pair(length=32, seed=9999)

        # Sequences must not be identical across 32 qubits
        self.assertNotEqual(key_a.basis_sequence, key_b.basis_sequence)

    # --------------------------------------------------------------------------
    # 5. Bell Pair Normalization
    # --------------------------------------------------------------------------
    def test_05_bell_pair_normalization(self):
        pairs = create_bell_pairs(count=8)
        self.assertEqual(len(pairs), 8)
        for bp in pairs:
            self.assertEqual(bp.shape, (4,))
            norm = np.linalg.norm(bp)
            self.assertAlmostEqual(norm, 1.0, places=6)

    # --------------------------------------------------------------------------
    # 6. Teleportation Preserves Normalized States
    # --------------------------------------------------------------------------
    def test_06_teleportation_preserves_normalized_states(self):
        for name, st in ALLOWED_QDS_STATES.items():
            for bits in ["00", "01", "10", "11"]:
                rec_state, used_bits, pauli_op = teleport_qubit(st, measurement_bits=bits)
                norm = np.linalg.norm(rec_state)
                self.assertAlmostEqual(norm, 1.0, places=6, msg=f"Teleporting {name} with {bits} failed normalization")
                self.assertEqual(used_bits, bits)

    # --------------------------------------------------------------------------
    # 7. Teleportation Fidelity is Approximately 1.0
    # --------------------------------------------------------------------------
    def test_07_teleportation_fidelity_approx_1(self):
        for name, st in ALLOWED_QDS_STATES.items():
            for bits in ["00", "01", "10", "11"]:
                rec_state, _, _ = teleport_qubit(st, measurement_bits=bits)
                fid = state_fidelity(st, rec_state)
                self.assertGreaterEqual(fid, 0.9999, msg=f"Teleportation fidelity {fid} < 0.9999 for {name} with bits {bits}")

    # --------------------------------------------------------------------------
    # 8. Pauli Correction Mapping
    # --------------------------------------------------------------------------
    def test_08_pauli_correction_mapping(self):
        # 00 -> I, 01 -> X, 10 -> Z, 11 -> XZ
        expected_mapping = {
            "00": "I",
            "01": "X",
            "10": "Z",
            "11": "XZ"
        }
        for bits, expected_op in expected_mapping.items():
            _, out_bits, pauli_op = teleport_qubit(STATE_PLUS, measurement_bits=bits)
            self.assertEqual(out_bits, bits)
            self.assertEqual(pauli_op, expected_op)

    # --------------------------------------------------------------------------
    # 9. Multi-Qubit Teleportation
    # --------------------------------------------------------------------------
    def test_09_multi_qubit_teleportation(self):
        test_states = [STATE_0, STATE_1, STATE_PLUS, STATE_MINUS] * 4 # 16 qubits
        res = teleport_signature(test_states, seed=42)

        self.assertIsInstance(res, TeleportationResult)
        self.assertEqual(len(res.received_states), 16)
        self.assertEqual(len(res.fidelities), 16)
        self.assertTrue(res.success)
        self.assertGreaterEqual(res.average_fidelity, 0.9999)

        # Dictionary access backward compatibility
        self.assertIn("fidelities", res.to_dict())
        self.assertIn("average_fidelity", res.to_dict())

    # --------------------------------------------------------------------------
    # 10. Hash-to-Bit Conversion
    # --------------------------------------------------------------------------
    def test_10_hash_to_bit_conversion(self):
        hex_hash = "a5" # 1010 0101
        bits = hex_to_bit_sequence(hex_hash)
        self.assertEqual(bits, "10100101")
        self.assertEqual(len(bits), 8)

        # 64-char SHA256 length string -> 256 bits
        sample_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        bits256 = hex_to_bit_sequence(sample_sha256)
        self.assertEqual(len(bits256), 256)

    # --------------------------------------------------------------------------
    # 11. QDS Signature Generation
    # --------------------------------------------------------------------------
    def test_11_qds_signature_generation(self):
        key = generate_qds_key_pair(length=16, seed=123)
        sample_hash = "3f" # 0011 1111 -> 8 bits
        sig = sign_hash_qds(sample_hash, key)

        self.assertIsInstance(sig, QDSSignature)
        self.assertEqual(sig.message_hash, "3f")
        self.assertEqual(sig.num_qubits, 8)
        self.assertEqual(len(sig.signature_states), 8)
        self.assertEqual(len(sig.basis_metadata), 8)

        for st in sig.signature_states:
            self.assertAlmostEqual(np.linalg.norm(st), 1.0, places=6)

    # --------------------------------------------------------------------------
    # 12. Valid Signature Verification
    # --------------------------------------------------------------------------
    def test_12_valid_signature_verification(self):
        key = generate_qds_key_pair(length=16, seed=42)
        sample_hash = "a5" # 8 bits
        sig = sign_hash_qds(sample_hash, key)

        # Teleport signature states to verifier (Bob)
        tp_res = teleport_signature(sig.signature_states, seed=100)
        self.assertTrue(tp_res.success)

        # Bob verifies received states against public key
        ver_res = verify_signature_qds(sig, tp_res.received_states, key, threshold=DEFAULT_T_VER)

        self.assertIsInstance(ver_res, QDSVerificationResult)
        self.assertTrue(ver_res.accepted)
        self.assertEqual(ver_res.mismatches, 0)
        self.assertEqual(ver_res.mismatch_rate, 0.0)
        self.assertEqual(ver_res.total_measurements, 8)

    # --------------------------------------------------------------------------
    # 13. Forged Signature Rejection
    # --------------------------------------------------------------------------
    def test_13_forged_signature_rejection(self):
        key = generate_qds_key_pair(length=64, seed=42)
        sample_hash = "1a2b3c4d" # 8 hex = 32 bits
        sig = sign_hash_qds(sample_hash, key)

        # Attacker substitutes random non-orthogonal states
        forged_sig = forge_qds_signature(sig, attack_type="random_state_substitution", seed=777)
        self.assertNotEqual(id(sig), id(forged_sig))

        ver_res = verify_signature_qds(forged_sig, forged_sig.signature_states, key, threshold=0.10)
        self.assertFalse(ver_res.accepted)
        self.assertGreater(ver_res.mismatch_rate, 0.10)

    # --------------------------------------------------------------------------
    # 14. Bit-Flip Attack Detection
    # --------------------------------------------------------------------------
    def test_14_bit_flip_attack_detection(self):
        key = generate_qds_key_pair(length=64, seed=42)
        sample_hash = "cafe" # 16 bits
        sig = sign_hash_qds(sample_hash, key)

        # Attacker applies bit flip (Pauli X) to signature qubits
        forged_sig = forge_qds_signature(sig, attack_type="bit_flip")

        ver_res = verify_signature_qds(forged_sig, forged_sig.signature_states, key, threshold=0.10)
        self.assertFalse(ver_res.accepted)
        self.assertGreater(ver_res.mismatch_rate, 0.10)

    # --------------------------------------------------------------------------
    # 15. Phase-Flip Attack Detection
    # --------------------------------------------------------------------------
    def test_15_phase_flip_attack_detection(self):
        key = generate_qds_key_pair(length=64, seed=42)
        sample_hash = "beef" # 16 bits
        sig = sign_hash_qds(sample_hash, key)

        # Attacker applies phase flip (Pauli Z) to signature qubits
        forged_sig = forge_qds_signature(sig, attack_type="phase_flip")

        ver_res = verify_signature_qds(forged_sig, forged_sig.signature_states, key, threshold=0.10)
        self.assertFalse(ver_res.accepted)
        self.assertGreater(ver_res.mismatch_rate, 0.10)

    # --------------------------------------------------------------------------
    # 16. Non-Repudiation Consistency
    # --------------------------------------------------------------------------
    def test_16_non_repudiation_consistency(self):
        bob_outcomes = [0, 1, 0, 1, 1, 0, 0, 1] * 4 # 32 bits
        charlie_outcomes = list(bob_outcomes) # exact match

        res = verify_non_repudiation_qds(bob_outcomes, charlie_outcomes, threshold=0.10)
        self.assertTrue(res["consistent"])
        self.assertEqual(res["mismatches"], 0)
        self.assertEqual(res["mismatch_rate"], 0.0)

    # --------------------------------------------------------------------------
    # 17. Non-Repudiation Mismatch Detection
    # --------------------------------------------------------------------------
    def test_17_non_repudiation_mismatch_detection(self):
        bob_outcomes = [0] * 32
        charlie_outcomes = [1] * 16 + [0] * 16 # 50% mismatch

        res = verify_non_repudiation_qds(bob_outcomes, charlie_outcomes, threshold=0.10)
        self.assertFalse(res["consistent"])
        self.assertEqual(res["mismatches"], 16)
        self.assertAlmostEqual(res["mismatch_rate"], 0.50, places=4)

    # --------------------------------------------------------------------------
    # 18. Invalid Input Handling
    # --------------------------------------------------------------------------
    def test_18_invalid_input_handling(self):
        # 1. Invalid key length
        with self.assertRaises(ValueError):
            generate_qds_key_pair(length=0)
        with self.assertRaises(ValueError):
            generate_qds_key_pair(length=-5)

        # 2. Invalid hash format (non-hex, empty)
        with self.assertRaises(ValueError):
            hex_to_bit_sequence("")
        with self.assertRaises(ValueError):
            hex_to_bit_sequence("not_a_hex_zzz")

        # 3. Key shorter than hash
        short_key = generate_qds_key_pair(length=4, seed=1)
        with self.assertRaises(ValueError):
            sign_hash_qds("abcd", short_key) # 16 bits > 4 qubits

        # 4. Zero norm state
        with self.assertRaises(ValueError):
            validate_qubit_state([0.0, 0.0])

        # 5. Invalid state dimensions
        with self.assertRaises(ValueError):
            validate_qubit_state([1.0, 0.0, 0.0])

        # 6. Invalid threshold
        key = generate_qds_key_pair(length=8, seed=1)
        sig = sign_hash_qds("0f", key)
        with self.assertRaises(ValueError):
            verify_signature_qds(sig, sig.signature_states, key, threshold=1.5)
        with self.assertRaises(ValueError):
            verify_signature_qds(sig, sig.signature_states, key, threshold=-0.1)

        # 7. Invalid measurement bits
        with self.assertRaises(ValueError):
            teleport_qubit(STATE_0, measurement_bits="99")

        # 8. Unsupported forgery attack
        with self.assertRaises(ValueError):
            forge_qds_signature(sig, attack_type="quantum_supremacy_magic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
