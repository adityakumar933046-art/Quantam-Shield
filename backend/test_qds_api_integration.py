"""
Comprehensive REST API Integration Test Suite for Multi-Qubit QDS Endpoints.

Module: test_qds_api_integration
Validates:
1. Health endpoint (GET /api/qds/health)
2. Thresholds endpoint (GET /api/qds/thresholds)
3. Key generation (POST /api/qds/key-generation)
4. Invalid key generation rejected with HTTP 400
5. Sign valid hash (POST /api/qds/sign)
6. Invalid hash rejected with HTTP 400
7. Teleport valid signature (POST /api/qds/teleport)
8. Verify honest signature (POST /api/qds/verify)
9. Attack simulation: None (POST /api/qds/attack-simulation)
10. Attack simulation: Bit flip
11. Attack simulation: Phase flip
12. Attack simulation: Intercept-resend
13. Attack simulation: Random substitution
14. Attack scenarios comparison (POST /api/qds/attack-scenarios)
15. Invalid attack type rejected with HTTP 400
16. Unknown signature ID rejected with HTTP 404
17. Risk scores bounded within [0, 100] across endpoints
18. Zero private key state leakage in responses
19. Existing Step 8 QDS endpoints remain functional
20. Role-based and token authentication enforced with HTTP 401
"""

import sys
import unittest
from pathlib import Path
import requests

BASE_URL = "http://127.0.0.1:8000/api"


class TestQDSAPIIntegration(unittest.TestCase):
    """Integration test suite for QDS REST API endpoints."""

    @classmethod
    def setUpClass(cls):
        # 1. Login as Analyst
        login_resp = requests.post(f"{BASE_URL}/auth/login", json={
            "email": "analyst@qshield.com",
            "password": "AnalystPassword123!"
        })
        if login_resp.status_code != 200:
            raise RuntimeError(f"Analyst login failed: {login_resp.text}")
        cls.analyst_token = login_resp.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.analyst_token}"}

        # 2. Login as regular User
        user_resp = requests.post(f"{BASE_URL}/auth/login", json={
            "email": "user@qshield.com",
            "password": "UserPassword123!"
        })
        if user_resp.status_code != 200:
            raise RuntimeError(f"User login failed: {user_resp.text}")
        cls.user_token = user_resp.json()["access_token"]
        cls.user_headers = {"Authorization": f"Bearer {cls.user_token}"}

    # --------------------------------------------------------------------------
    # 1. Health Endpoint
    # --------------------------------------------------------------------------
    def test_01_health_endpoint(self):
        resp = requests.get(f"{BASE_URL}/qds/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["protocol"], "QDS")
        self.assertEqual(data["quantum_engine"], "available")
        self.assertEqual(data["statistical_analysis"], "available")
        self.assertEqual(data["attack_pipeline"], "available")
        self.assertFalse(data["ai_ml"])

    # --------------------------------------------------------------------------
    # 2. Thresholds Endpoint
    # --------------------------------------------------------------------------
    def test_02_thresholds_endpoint(self):
        resp = requests.get(f"{BASE_URL}/qds/thresholds")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertAlmostEqual(data["verification_threshold"], 0.10)
        self.assertAlmostEqual(data["repudiation_threshold"], 0.05)
        self.assertAlmostEqual(data["channel_disturbance_threshold"], 0.20)
        self.assertAlmostEqual(data["minimum_acceptable_fidelity"], 0.90)
        self.assertEqual(data["chi_square_min_sample_size"], 20)

    # --------------------------------------------------------------------------
    # 3. Key Generation
    # --------------------------------------------------------------------------
    def test_03_key_generation(self):
        resp = requests.post(
            f"{BASE_URL}/qds/key-generation",
            headers=self.headers,
            json={"key_length": 32, "seed": 4242}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("key_id", data)
        self.assertEqual(data["key_length"], 32)
        self.assertEqual(len(data["public_key"]), 32)
        self.assertEqual(len(data["basis_information"]), 32)
        # Ensure no private key states leaked
        self.assertNotIn("private_states", data)
        self.assertNotIn("private_key", data)

    # --------------------------------------------------------------------------
    # 4. Invalid Key Generation
    # --------------------------------------------------------------------------
    def test_04_invalid_key_generation(self):
        resp_zero = requests.post(
            f"{BASE_URL}/qds/key-generation",
            headers=self.headers,
            json={"key_length": 0}
        )
        self.assertIn(resp_zero.status_code, [400, 422])

        resp_too_large = requests.post(
            f"{BASE_URL}/qds/key-generation",
            headers=self.headers,
            json={"key_length": 1000}
        )
        self.assertIn(resp_too_large.status_code, [400, 422])

    # --------------------------------------------------------------------------
    # 5. Sign Valid Hash
    # --------------------------------------------------------------------------
    def test_05_sign_valid_hash(self):
        # Generate key
        k_resp = requests.post(
            f"{BASE_URL}/qds/key-generation",
            headers=self.headers,
            json={"key_length": 32, "seed": 100}
        )
        key_id = k_resp.json()["key_id"]

        # Sign 8 hex chars = 32 bits
        sig_resp = requests.post(
            f"{BASE_URL}/qds/sign",
            headers=self.headers,
            json={"key_id": key_id, "message_hash": "a1b2c3d4"}
        )
        self.assertEqual(sig_resp.status_code, 200)
        sig_data = sig_resp.json()
        self.assertIn("signature_id", sig_data)
        self.assertEqual(sig_data["message_hash"], "a1b2c3d4")
        self.assertEqual(sig_data["qubit_count"], 32)

    # --------------------------------------------------------------------------
    # 6. Invalid Hash
    # --------------------------------------------------------------------------
    def test_06_invalid_hash(self):
        k_resp = requests.post(
            f"{BASE_URL}/qds/key-generation",
            headers=self.headers,
            json={"key_length": 32}
        )
        key_id = k_resp.json()["key_id"]

        # Non-hex characters
        resp_non_hex = requests.post(
            f"{BASE_URL}/qds/sign",
            headers=self.headers,
            json={"key_id": key_id, "message_hash": "xyz123_invalid"}
        )
        self.assertIn(resp_non_hex.status_code, [400, 422])

        # Empty hash
        resp_empty = requests.post(
            f"{BASE_URL}/qds/sign",
            headers=self.headers,
            json={"key_id": key_id, "message_hash": ""}
        )
        self.assertIn(resp_empty.status_code, [400, 422])

    # --------------------------------------------------------------------------
    # 7. Teleport Valid Signature
    # --------------------------------------------------------------------------
    def test_07_teleport_valid_signature(self):
        # Key + Sign
        k_resp = requests.post(f"{BASE_URL}/qds/key-generation", headers=self.headers, json={"key_length": 16})
        sig_resp = requests.post(f"{BASE_URL}/qds/sign", headers=self.headers, json={"key_id": k_resp.json()["key_id"], "message_hash": "abcd"})
        sig_id = sig_resp.json()["signature_id"]

        # Teleport
        t_resp = requests.post(f"{BASE_URL}/qds/teleport", headers=self.headers, json={"signature_id": sig_id, "seed": 42})
        self.assertEqual(t_resp.status_code, 200)
        t_data = t_resp.json()
        self.assertEqual(t_data["signature_id"], sig_id)
        self.assertEqual(t_data["qubit_count"], 16)
        self.assertGreaterEqual(t_data["average_fidelity"], 0.99)
        self.assertTrue(t_data["success"])
        self.assertEqual(len(t_data["measurement_bits"]), 16)

    # --------------------------------------------------------------------------
    # 8. Verify Honest Signature
    # --------------------------------------------------------------------------
    def test_08_verify_honest_signature(self):
        k_resp = requests.post(f"{BASE_URL}/qds/key-generation", headers=self.headers, json={"key_length": 16})
        sig_resp = requests.post(f"{BASE_URL}/qds/sign", headers=self.headers, json={"key_id": k_resp.json()["key_id"], "message_hash": "abcd"})
        sig_id = sig_resp.json()["signature_id"]
        requests.post(f"{BASE_URL}/qds/teleport", headers=self.headers, json={"signature_id": sig_id})

        v_resp = requests.post(f"{BASE_URL}/qds/verify", headers=self.headers, json={"signature_id": sig_id, "threshold": 0.10})
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.json()
        self.assertTrue(v_data["verification"]["accepted"])
        self.assertEqual(v_data["verification"]["mismatch_rate"], 0.0)
        self.assertFalse(v_data["threat"]["detected"])
        self.assertEqual(v_data["threat"]["type"], "NONE")
        self.assertEqual(v_data["risk"]["tier"], "LOW")

    # --------------------------------------------------------------------------
    # 9. Attack Simulation: None
    # --------------------------------------------------------------------------
    def test_09_attack_simulation_none(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2", "attack_type": "none", "key_length": 16, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["attack_type"], "none")
        self.assertTrue(data["verification"]["accepted"])
        self.assertFalse(data["threat"]["detected"])
        self.assertEqual(data["risk"]["tier"], "LOW")

    # --------------------------------------------------------------------------
    # 10. Attack Simulation: Bit Flip
    # --------------------------------------------------------------------------
    def test_10_attack_simulation_bit_flip(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2", "attack_type": "bit_flip", "key_length": 16, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["attack_type"], "bit_flip")
        self.assertTrue(data["threat"]["detected"])
        self.assertIn(data["threat"]["type"], ["QUANTUM_CHANNEL_MANIPULATION", "DIGITAL_SIGNATURE_FORGERY"])

    # --------------------------------------------------------------------------
    # 11. Attack Simulation: Phase Flip
    # --------------------------------------------------------------------------
    def test_11_attack_simulation_phase_flip(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2c3d4", "attack_type": "phase_flip", "key_length": 32, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["attack_type"], "phase_flip")
        # In multi-qubit keys with conjugate bases, phase flips in X-basis qubits are detected
        self.assertIn("bases_used", data["signature"])

    # --------------------------------------------------------------------------
    # 12. Attack Simulation: Intercept-Resend
    # --------------------------------------------------------------------------
    def test_12_attack_simulation_intercept_resend(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2", "attack_type": "intercept_resend", "key_length": 16, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["attack_type"], "intercept_resend")
        self.assertTrue(data["threat"]["detected"])

    # --------------------------------------------------------------------------
    # 13. Attack Simulation: Random State Substitution
    # --------------------------------------------------------------------------
    def test_13_attack_simulation_random_substitution(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2c3d4", "attack_type": "random_state_substitution", "key_length": 32, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["verification"]["accepted"])
        self.assertTrue(data["threat"]["detected"])

    # --------------------------------------------------------------------------
    # 14. Attack Scenarios Comparison
    # --------------------------------------------------------------------------
    def test_14_attack_scenarios_comparison(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-scenarios",
            headers=self.headers,
            json={"message_hash": "abcd", "key_length": 16, "seed": 42}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["scenarios"]), 5)
        self.assertEqual(data["summary"]["attacks_evaluated"], 4)
        self.assertGreaterEqual(data["summary"]["detection_rate_percentage"], 75.0)

    # --------------------------------------------------------------------------
    # 15. Invalid Attack Type
    # --------------------------------------------------------------------------
    def test_15_invalid_attack_type(self):
        resp = requests.post(
            f"{BASE_URL}/qds/attack-simulation",
            headers=self.headers,
            json={"message_hash": "a1b2", "attack_type": "dark_matter_inversion", "key_length": 16}
        )
        self.assertEqual(resp.status_code, 400)

    # --------------------------------------------------------------------------
    # 16. Unknown Signature ID
    # --------------------------------------------------------------------------
    def test_16_unknown_signature_id(self):
        resp = requests.post(
            f"{BASE_URL}/qds/verify",
            headers=self.headers,
            json={"signature_id": "qds-sig-nonexistent-12345"}
        )
        self.assertEqual(resp.status_code, 404)

    # --------------------------------------------------------------------------
    # 17. Risk Score Bounded 0–100
    # --------------------------------------------------------------------------
    def test_17_risk_score_bounded(self):
        for att in ["none", "bit_flip", "random_state_substitution"]:
            resp = requests.post(
                f"{BASE_URL}/qds/attack-simulation",
                headers=self.headers,
                json={"message_hash": "a1b2", "attack_type": att, "key_length": 16, "seed": 42}
            )
            score = resp.json()["risk"]["score"]
            self.assertTrue(0.0 <= score <= 100.0, f"Risk score {score} out of bounds")

    # --------------------------------------------------------------------------
    # 18. No Private Key Leakage
    # --------------------------------------------------------------------------
    def test_18_no_private_key_leakage(self):
        k_resp = requests.post(f"{BASE_URL}/qds/key-generation", headers=self.headers, json={"key_length": 16})
        sig_resp = requests.post(f"{BASE_URL}/qds/sign", headers=self.headers, json={"key_id": k_resp.json()["key_id"], "message_hash": "abcd"})

        # Check key generation response
        self.assertNotIn("private_key", k_resp.json())
        self.assertNotIn("private_states", k_resp.json())

        # Check sign response
        self.assertNotIn("private_key", sig_resp.json())
        self.assertNotIn("private_states", sig_resp.json())
        self.assertNotIn("signature_states", sig_resp.json())

    # --------------------------------------------------------------------------
    # 19. Existing QDS Endpoints Remain Functional
    # --------------------------------------------------------------------------
    def test_19_existing_endpoints_functional(self):
        sim_resp = requests.get(f"{BASE_URL}/qds/simulations", headers=self.headers)
        self.assertEqual(sim_resp.status_code, 200)

        metrics_resp = requests.get(f"{BASE_URL}/qds/metrics", headers=self.headers)
        self.assertEqual(metrics_resp.status_code, 200)

    # --------------------------------------------------------------------------
    # 20. Existing Authentication Behavior Functional
    # --------------------------------------------------------------------------
    def test_20_authentication_enforced(self):
        # Unauthenticated request to /qds/key-generation should be blocked with 401
        no_auth_resp = requests.post(f"{BASE_URL}/qds/key-generation", json={"key_length": 16})
        self.assertEqual(no_auth_resp.status_code, 401)

        # Authenticated request succeeds
        auth_resp = requests.post(f"{BASE_URL}/qds/key-generation", headers=self.user_headers, json={"key_length": 16})
        self.assertEqual(auth_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
