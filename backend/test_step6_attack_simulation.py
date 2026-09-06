"""
Step 6 Verification Test Suite: Controlled Attack Simulation Module
Tests 10 required simulation scenarios, defensive isolation guarantees,
analytical threat detection, and API endpoints.
"""

import sys
from pathlib import Path
import numpy as np

sys.path.append(str(Path(__file__).resolve().parent))

from attack_simulation import (
    DocumentTamperingSimulator,
    SignatureForgerySimulator,
    ReplayAttackSimulator,
    ImpersonationSimulator,
    UnauthorizedAttemptSimulator,
    SignatureManipulationSimulator,
    QuantumChannelSimulator,
    ResultsAggregator,
    AttackType,
    SimulationStatus
)
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token


def test_1_valid_baseline():
    """Test 1: Normal document and signature baseline (no threats, low risk)."""
    print("\n--- TEST 1: Valid Baseline Document / Signature ---")
    sim = DocumentTamperingSimulator()
    content = b"Official transaction report 2026."
    res = sim.simulate(content, strategy="NO_ATTACK")
    
    assert res.attack_type == AttackType.DOCUMENT_TAMPERING.value
    assert res.integrity_valid is True
    assert res.state_consistency > 0.95
    assert res.state_disturbance < 0.05
    assert len(res.threats_detected) == 0
    assert res.detection_status in ["BLOCKED", "SECURE", "UNDETECTED"]
    assert res.final_risk_score <= 20.0
    print("[PASS] Baseline test passed: Integrity intact, disturbance 0, 0 threats.")


def test_2_document_tampering():
    """Test 2: Document tampering via character flip -> integrity failure detected."""
    print("\n--- TEST 2: Document Tampering Simulation ---")
    sim = DocumentTamperingSimulator()
    content = b"Pay to recipient the amount of 1000 USD."
    res = sim.simulate(content, strategy="CHARACTER_FLIP", flip_index=15)
    
    assert res.integrity_valid is False
    assert res.original_hash != res.tampered_hash
    assert res.detection_status == "DETECTED"
    assert res.final_risk_score >= 60.0
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "DOCUMENT_TAMPERING" in threat_names
    assert res.baseline_comparison["normal_state"]["integrity_status"] == "INTACT"
    assert res.baseline_comparison["simulated_attack_state"]["integrity_status"] == "MODIFIED"
    print(f"[PASS] Tampering test passed: Original hash {res.original_hash[:8]}... != Tampered {res.tampered_hash[:8]}..., Threat flagged.")


def test_3_signature_forgery():
    """Test 3: Signature forgery via corrupted bytes -> mathematical failure detected."""
    print("\n--- TEST 3: Signature Forgery Simulation ---")
    sim = SignatureForgerySimulator()
    original_sig = b"VALID_CRYPTOGRAPHIC_SIGNATURE_BYTES_1234567890"
    res = sim.simulate(original_sig, strategy="CORRUPT_BYTES", corrupt_fraction=0.4)
    
    assert res.signature_valid is False
    assert res.detection_status == "DETECTED"
    assert res.forgery_risk_estimate > 40.0
    assert res.final_risk_score >= 70.0
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "DIGITAL_SIGNATURE_FORGERY" in threat_names
    assert res.pauli_disturbance > 0.3
    print(f"[PASS] Forgery test passed: Signature rejected, forgery risk {res.forgery_risk_estimate:.1f}%, Pauli disturbance {res.pauli_disturbance:.2f}.")


def test_4_replay_attack():
    """Test 4: Replay attack simulation -> high frequency within time window detected."""
    print("\n--- TEST 4: Replay Attack Simulation ---")
    sim = ReplayAttackSimulator()
    doc_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = sim.simulate(doc_hash, attempt_count=12, interval_seconds=0.1, threshold=5)
    
    assert res.detection_status == "DETECTED"
    assert res.final_risk_level in ["HIGH", "CRITICAL"]
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "REPLAY_ATTACK" in threat_names
    print(f"[PASS] Replay attack test passed: 12 attempts detected, frequency {res.explanation['rate_per_second']:.1f} req/s.")


def test_5_impersonation_attack():
    """Test 5: Impersonation attack simulation -> claimed signer identity mismatch detected."""
    print("\n--- TEST 5: Impersonation Attack Simulation ---")
    sim = ImpersonationSimulator()
    res = sim.simulate(
        claimed_signer="alice@quantum.gov",
        cert_subject="eve@adversary.org",
        cert_serial="CERT-999-EVIL",
        mismatch_scenario="FULL_SUBJECT_MISMATCH"
    )
    
    assert res.detection_status == "DETECTED"
    assert res.pauli_disturbance > 0.1
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "IMPERSONATION" in threat_names
    print("[PASS] Impersonation test passed: Alice vs Eve identity mismatch detected with phase disturbance.")


def test_6_unauthorized_attempt():
    """Test 6: Unauthorized verification attempt -> unprivileged role blocked."""
    print("\n--- TEST 6: Unauthorized Verification Attempt Simulation ---")
    sim = UnauthorizedAttemptSimulator()
    res = sim.simulate(
        user_role="GUEST",
        required_roles=["SECURITY_ANALYST", "SUPER_ADMIN"],
        action="EXECUTE_DEEP_INSPECTION"
    )
    
    assert res.detection_status == "BLOCKED"
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "UNAUTHORIZED_VERIFICATION_ATTEMPT" in threat_names
    assert res.final_risk_score >= 50.0
    print("[PASS] Unauthorized attempt test passed: GUEST role access blocked and flagged.")


def test_7_signature_manipulation():
    """Test 7: Signature manipulation -> truncated ASN.1 / corrupted DER detected."""
    print("\n--- TEST 7: Signature Manipulation Simulation ---")
    sim = SignatureManipulationSimulator()
    asn1_structure = b"3045022100" + b"A" * 32 + b"0220" + b"B" * 32
    res = sim.simulate(asn1_structure, manipulation_type="TRUNCATE_ASN1", truncate_bytes=10)
    
    assert res.signature_valid is False
    assert res.detection_status == "DETECTED"
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "SIGNATURE_MANIPULATION" in threat_names
    print("[PASS] Signature manipulation test passed: ASN.1 truncation detected and flagged.")


def test_8_pauli_x_disturbance():
    """Test 8: Quantum channel simulation -> Pauli X bit-flip disturbance."""
    print("\n--- TEST 8: Pauli X Bit-Flip Disturbance Simulation ---")
    sim = QuantumChannelSimulator()
    res = sim.simulate(scenario="PAULI_X_DISTURBANCE", bell_state_name="PHI_PLUS")
    
    assert res.detection_status == "DETECTED"
    assert res.pauli_disturbance > 0.3
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "QUANTUM_CHANNEL_DISTURBANCE" in threat_names
    print(f"[PASS] Pauli X test passed: Disturbance {res.pauli_disturbance:.2f}, threat detected.")


def test_9_pauli_y_disturbance():
    """Test 9: Quantum channel simulation -> Pauli Y compound bit-and-phase noise."""
    print("\n--- TEST 9: Pauli Y Compound Disturbance Simulation ---")
    sim = QuantumChannelSimulator()
    res = sim.simulate(scenario="PAULI_Y_DISTURBANCE", bell_state_name="PHI_PLUS")
    
    assert res.detection_status == "DETECTED"
    assert res.pauli_disturbance > 0.4
    assert res.state_consistency < 0.8
    print(f"[PASS] Pauli Y test passed: Consistency {res.state_consistency:.2f}, Pauli anomaly {res.pauli_disturbance:.2f}.")


def test_10_measurement_disturbance():
    """Test 10: Quantum channel simulation -> Projective measurement collapse."""
    print("\n--- TEST 10: Measurement Disturbance Simulation ---")
    sim = QuantumChannelSimulator()
    res = sim.simulate(scenario="MEASUREMENT_DISTURBANCE", bell_state_name="PHI_PLUS")
    
    assert res.detection_status == "DETECTED"
    assert res.measurement_threat_probability > 0.2
    threat_names = [t["threat_category"] for t in res.threats_detected]
    assert "MEASUREMENT_COLLAPSE" in threat_names
    print(f"[PASS] Measurement disturbance test passed: P(threat) = {res.measurement_threat_probability:.2f}.")


def test_results_aggregator():
    """Test ResultsAggregator metric calculation and breakdown."""
    print("\n--- Testing ResultsAggregator ---")
    agg = ResultsAggregator()
    sim_tamper = DocumentTamperingSimulator()
    r1 = sim_tamper.simulate(b"Doc 1", strategy="CHARACTER_FLIP")
    agg.add_result(r1)

    sim_forgery = SignatureForgerySimulator()
    r2 = sim_forgery.simulate(b"Sig 2", strategy="CORRUPT_BYTES")
    agg.add_result(r2)

    summary = agg.get_summary()
    assert summary["total_simulations"] == 2
    assert summary["threats_correctly_detected"] == 2
    assert summary["detection_rate"] == 100.0
    print(f"[PASS] Aggregator test passed: 100% detection rate across {summary['total_simulations']} tests.")


def test_api_integration():
    """Test API endpoints via TestClient with security analyst auth token."""
    print("\n--- Testing API Endpoints Integration ---")
    client = TestClient(app)
    token = create_access_token({"sub": "3", "role": "SECURITY_ANALYST"})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Execute direct simulation
    exec_payload = {
        "attack_type": "DOCUMENT_TAMPERING",
        "parameters": {"content_text": "Secret report 2026", "tamper_mode": "CHAR_FLIP"}
    }
    response = client.post("/api/simulations/execute/", json=exec_payload, headers=headers)
    assert response.status_code == 200, f"Failed execution: {response.text}"
    data = response.json()
    assert data["attack_type"] == "DOCUMENT_TAMPERING"
    assert data["result"]["detection_status"] == "DETECTED"
    print("[PASS] API /api/simulations/execute/ returned 200 with DETECTED status.")

    # 2. Get metrics summary
    summary_resp = client.get("/api/simulations/metrics/summary", headers=headers)
    assert summary_resp.status_code == 200
    summary_data = summary_resp.json()
    assert "detection_rate" in summary_data
    assert "attack_type_breakdown" in summary_data
    print(f"[PASS] API /api/simulations/metrics/summary returned 200: rate={summary_data['detection_rate']}%.")

    # 3. Get history
    history_resp = client.get("/api/simulations/history/", headers=headers)
    assert history_resp.status_code == 200
    history_list = history_resp.json()
    assert len(history_list) >= 1
    print(f"[PASS] API /api/simulations/history/ returned {len(history_list)} records.")

    # 4. RBAC check: Unprivileged user cannot execute simulation
    guest_token = create_access_token({"sub": "2", "role": "DIGITAL_SIGNATURE_USER"})
    guest_headers = {"Authorization": f"Bearer {guest_token}"}
    forbidden_resp = client.post("/api/simulations/execute/", json=exec_payload, headers=guest_headers)
    assert forbidden_resp.status_code == 403, f"Expected 403, got {forbidden_resp.status_code}"
    print("[PASS] RBAC test passed: DIGITAL_SIGNATURE_USER cannot execute simulations (HTTP 403 Forbidden).")


if __name__ == "__main__":
    print("=" * 60)
    print("STARTING STEP 6 CONTROLLED ATTACK SIMULATION TESTS")
    print("=" * 60)
    test_1_valid_baseline()
    test_2_document_tampering()
    test_3_signature_forgery()
    test_4_replay_attack()
    test_5_impersonation_attack()
    test_6_unauthorized_attempt()
    test_7_signature_manipulation()
    test_8_pauli_x_disturbance()
    test_9_pauli_y_disturbance()
    test_10_measurement_disturbance()
    test_results_aggregator()
    test_api_integration()
    print("=" * 60)
    print("ALL 10 STEP 6 ATTACK SIMULATION SCENARIOS & API TESTS PASSED!")
    print("=" * 60)
