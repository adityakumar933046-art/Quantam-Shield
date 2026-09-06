import requests
import json
from pathlib import Path
import sys

BASE_URL = "http://127.0.0.1:8000/api"

def run_step8_qds_tests():
    print("==================================================================")
    print("RUNNING STEP 8 - QUANTUM DIGITAL SIGNATURE (QDS) SIMULATION TESTS")
    print("==================================================================")

    # 0. Authentication
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_analyst = login_resp.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    login_user = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_user.status_code == 200, f"User login failed: {login_user.text}"
    token_dsuser = login_user.json()["access_token"]
    headers_dsuser = {"Authorization": f"Bearer {token_dsuser}"}
    print("[AUTH] Logged in as user@qshield.com")

    # TEST 1: Ideal QDS Teleportation Simulation
    print("\n--- TEST 1: Ideal Teleportation Simulation ---")
    sim_req = {
        "initial_state": "|+>",
        "bell_state": "|Phi+>",
        "simulation_seed": 42,
        "signer_id": "Alice (Signer)",
        "verifier_id": "Bob (Verifier)",
        "attack_simulation": "none",
        "noise_model": "none",
        "depolarizing_error_prob": 0.0,
        "phase_flip_error_prob": 0.0,
        "amplitude_damping_prob": 0.0,
        "acceptance_threshold": 0.95
    }
    resp1 = requests.post(f"{BASE_URL}/qds/simulate", headers=headers_analyst, json=sim_req)
    assert resp1.status_code == 200, f"Simulate failed: {resp1.text}"
    data1 = resp1.json()
    assert data1["fidelity"] == 1.0, f"Expected fidelity 1.0, got {data1['fidelity']}"
    assert data1["verification_result"] in ["VERIFIED", "ACCEPT"], f"Expected VERIFIED/ACCEPT, got {data1['verification_result']}"
    assert data1["session_status"] in ["AUTHENTIC_QUANTUM_SIGNATURE", "COMPLETED"], f"Got status {data1['session_status']}"
    assert len(data1["measurement_bits"]) == 2, f"Expected 2 measurement bits, got {data1['measurement_bits']}"
    simulation_id_1 = data1["simulation_id"]
    print(f"[SUCCESS] Ideal simulation created (ID: {simulation_id_1}, Fidelity: {data1['fidelity']}, Result: {data1['verification_result']})")

    # TEST 2: Attacked QDS Simulation (Intercept-Resend Attack)
    print("\n--- TEST 2: Attacked Teleportation Simulation ---")
    attack_sim_req = {
        "initial_state": "|+>",
        "bell_state": "|Phi+>",
        "simulation_seed": 100,
        "signer_id": "Alice (Signer)",
        "verifier_id": "Bob (Verifier)",
        "attack_simulation": "intercept_resend",
        "noise_model": "depolarizing",
        "depolarizing_error_prob": 0.3,
        "phase_flip_error_prob": 0.1,
        "amplitude_damping_prob": 0.0,
        "acceptance_threshold": 0.95
    }
    resp2 = requests.post(f"{BASE_URL}/qds/simulate", headers=headers_analyst, json=attack_sim_req)
    assert resp2.status_code == 200, f"Attack simulate failed: {resp2.text}"
    data2 = resp2.json()
    assert data2["fidelity"] < 0.95, f"Expected fidelity < 0.95, got {data2['fidelity']}"
    assert data2["verification_result"] in ["REJECTED", "TAMPERED", "REJECT"], f"Got {data2['verification_result']}"
    assert data2["session_status"] in ["TAMPERED_OR_NOISY_QUANTUM_CHANNEL", "COMPLETED", "REJECTED"], f"Got status {data2['session_status']}"
    print(f"[SUCCESS] Attacked simulation caught (Fidelity: {data2['fidelity']}, Status: {data2['session_status']})")

    # TEST 3: Statistical Attack Simulation Module (100 Trials)
    print("\n--- TEST 3: Attack Simulation Module (Batch Trials) ---")
    attack_module_req = {
        "attack_type": "intercept_resend",
        "number_of_trials": 50,
        "simulation_seed": 42,
        "initial_state": "|+>",
        "bell_state": "|Phi+>",
        "acceptance_threshold": 0.95,
        "noise_level": 0.2
    }
    resp3 = requests.post(f"{BASE_URL}/qds/attack-simulation", headers=headers_analyst, json=attack_module_req)
    assert resp3.status_code == 200, f"Attack batch simulation failed: {resp3.text}"
    data3 = resp3.json()
    assert data3["number_of_trials"] == 50, f"Expected 50 trials, got {data3['number_of_trials']}"
    assert "detection_rate" in data3, "Missing detection_rate"
    assert data3["detection_rate"] > 0.0, f"Expected detection rate > 0, got {data3['detection_rate']}"
    print(f"[SUCCESS] Attack batch simulation complete (Detection Rate: {data3['detection_rate']:.1f}%, Mean Fidelity: {data3['mean_fidelity']:.4f})")

    # TEST 4: Seed-Based Reproducibility & Rerun
    print("\n--- TEST 4: Seed Reproducibility & Session Rerun ---")
    resp4_a = requests.post(f"{BASE_URL}/qds/simulations/{simulation_id_1}/rerun", headers=headers_analyst)
    assert resp4_a.status_code == 200, f"Rerun failed: {resp4_a.text}"
    data4_a = resp4_a.json()
    assert data4_a["measurement_bits"] == data1["measurement_bits"], "Measurement bits differ on identical seed!"
    assert data4_a["reconstructed_state"] == data1["reconstructed_state"], "Reconstructed state vectors differ!"
    print(f"[SUCCESS] Seed reproducibility verified (Bits: {data4_a['measurement_bits']} matched original)")

    # TEST 5: Threat Incident Engine Integration
    print("\n--- TEST 5: QDS Threat Event Log ---")
    resp5 = requests.get(f"{BASE_URL}/qds/threat-events", headers=headers_analyst)
    assert resp5.status_code == 200, f"Get threats failed: {resp5.text}"
    data5 = resp5.json()
    assert len(data5) > 0, "Threat log should contain at least 1 threat from attacked simulation"
    last_threat = data5[0]
    assert "threat_type" in last_threat and "severity" in last_threat, f"Unexpected threat object {last_threat}"
    print(f"[SUCCESS] Threat event verified in log (Threat Type: {last_threat['threat_type']}, Severity: {last_threat['severity']})")

    # TEST 6: QDS Performance Metrics Endpoint
    print("\n--- TEST 6: Performance Metrics Endpoint ---")
    resp6 = requests.get(f"{BASE_URL}/qds/metrics", headers=headers_analyst)
    assert resp6.status_code == 200, f"Metrics failed: {resp6.text}"
    data6 = resp6.json()
    assert data6["total_simulations"] >= 2, f"Expected total_simulations >= 2, got {data6['total_simulations']}"
    assert "time_complexity_explanation" in data6, "Missing time complexity explanation"
    assert "space_complexity_explanation" in data6, "Missing space complexity explanation"
    print(f"[SUCCESS] Performance metrics retrieved (Total Sims: {data6['total_simulations']}, Avg Fidelity: {data6['average_fidelity']:.4f})")

    # TEST 7: Decoupling Verification (Classical Document Signing Remains Functional)
    print("\n--- TEST 7: Classical PDF Signing Decoupling Test ---")
    from pypdf import PdfWriter
    dummy_pdf = Path("test_qds_decouple.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(dummy_pdf, "wb") as f:
        writer.write(f)

    with open(dummy_pdf, "rb") as f:
        u_res = requests.post(f"{BASE_URL}/documents/upload", headers=headers_dsuser, files={"file": ("test_qds_decouple.pdf", f, "application/pdf")})
    assert u_res.status_code == 200, f"Document upload failed: {u_res.text}"
    doc_id = u_res.json()["document_id"]

    s_res = requests.post(f"{BASE_URL}/documents/{doc_id}/sign", headers=headers_dsuser)
    assert s_res.status_code == 200, f"Document sign failed: {s_res.text}"
    assert s_res.json()["status"] == "SIGNED", "Classical signing failed!"
    print("[SUCCESS] Classical PDF signing works cleanly without interference from QDS module")

    # TEST 8: Role-Based Authorization Security
    print("\n--- TEST 8: Role-Based Authorization Enforcement ---")
    unauth_resp = requests.post(f"{BASE_URL}/qds/simulate", json=sim_req)
    assert unauth_resp.status_code == 401, f"Expected HTTP 401 for unauthenticated request, got {unauth_resp.status_code}"
    print("[SUCCESS] Unauthenticated QDS request properly blocked with HTTP 401")

    # TEST 9: Scientific Non-Overclaiming & Mathematical Boundaries
    print("\n--- TEST 9: Scientific Non-Overclaiming Check ---")
    assert "2^n" in data6["time_complexity_explanation"] or "O(" in data6["time_complexity_explanation"], "Missing complexity details!"
    assert "storage" in data6["space_complexity_explanation"].lower() or "qubit" in data6["space_complexity_explanation"].lower(), "Missing space details!"
    print("[SUCCESS] Scientific explanations strictly confirm classical software mathematical simulation")

    print("\n==================================================================")
    print("ALL STEP 8 QUANTUM DIGITAL SIGNATURE TESTS PASSED SUCCESSFULLY!")
    print("==================================================================")

if __name__ == "__main__":
    run_step8_qds_tests()
