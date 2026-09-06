import requests
import sqlite3
from pathlib import Path
from pypdf import PdfWriter
import sys

# Ensure backend directory is in sys.path for direct module import testing
sys.path.append(str(Path(__file__).resolve().parent))
from app.core.quantum_engine import analyze_quantum_security_state

BASE_URL = "http://127.0.0.1:8000/api"
DB_PATH = Path("database/qshield.db").resolve()
if not DB_PATH.exists():
    DB_PATH = Path("../database/qshield.db").resolve()

def run_step5_quantum_tests():
    print("==================================================================")
    print("RUNNING STEP 5 - QUANTUM-INSPIRED SECURITY ANALYSIS ENGINE TESTS")
    print("==================================================================")

    # 0. Authenticate Security Analyst & Digital Signature User
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp.status_code == 200, "Analyst authentication failed"
    token_analyst = login_resp.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    print("[AUTH] Logged in as analyst@qshield.com (Security Analyst)")

    login_resp2 = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_resp2.status_code == 200, "User authentication failed"
    token_user2 = login_resp2.json()["access_token"]
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    # Generate a fresh valid signed PDF via Step 2 API
    sample_pdf_path = Path("step5_blank.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(sample_pdf_path, "wb") as f:
        writer.write(f)

    with open(sample_pdf_path, "rb") as f:
        u_res = requests.post(f"{BASE_URL}/documents/upload", headers=headers_user2, files={"file": ("step5_blank.pdf", f, "application/pdf")})
    assert u_res.status_code == 200
    doc_id = u_res.json()["document_id"]
    
    s_res = requests.post(f"{BASE_URL}/documents/{doc_id}/sign", headers=headers_user2)
    assert s_res.status_code == 200
    
    d_res = requests.get(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_user2)
    signed_pdf_bytes = d_res.content
    valid_signed_pdf_path = Path("step5_valid_signed.pdf")
    valid_signed_pdf_path.write_bytes(signed_pdf_bytes)

    # ------------------------------------------------------------------
    # TEST 1: Valid Digitally Signed PDF (SECURE State Analysis)
    # ------------------------------------------------------------------
    print("\n--- TEST 1: Valid Digitally Signed PDF Quantum Analysis ---")
    with open(valid_signed_pdf_path, "rb") as f:
        ana_res = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step5_valid_signed.pdf", f, "application/pdf")})
    assert ana_res.status_code == 200
    ana_id1 = ana_res.json()["analysis_document_id"]

    # Verify signature first (Step 4)
    v_res1 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/verify", headers=headers_analyst)
    assert v_res1.status_code == 200

    # Run Quantum Analysis (Step 5)
    q_res1 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/quantum-analysis", headers=headers_analyst)
    assert q_res1.status_code == 200
    q_doc1 = q_res1.json()
    q_data1 = q_doc1["quantum_analysis"]

    assert q_data1["final_classification"] == "SECURE", f"Expected SECURE but got {q_data1['final_classification']}"
    assert q_data1["forgery_risk_score"] < 15.0, f"Expected Risk Score < 15 but got {q_data1['forgery_risk_score']}"
    assert q_data1["disturbance_score"] < 0.1, f"Expected Disturbance D < 0.1 but got {q_data1['disturbance_score']}"
    assert q_data1["secure_measurement_score"] > 80.0, f"Expected P(Secure) > 80% but got {q_data1['secure_measurement_score']}"
    print(f"[OK] Classification: {q_data1['final_classification']}")
    print(f"[OK] Forgery Risk Score: {q_data1['forgery_risk_score']}/100 | Disturbance D: {q_data1['disturbance_score']}")
    print(f"[OK] Projective Measurement P(Secure): {q_data1['secure_measurement_score']}%")

    # ------------------------------------------------------------------
    # TEST 2: Invalid / Corrupted Signature (HIGH_RISK State Analysis)
    # ------------------------------------------------------------------
    print("\n--- TEST 2: Invalid Signature Quantum Analysis ---")
    corrupt_bytes = signed_pdf_bytes.replace(b'00000000', b'FFFFFFFF')
    corrupt_pdf_path = Path("step5_corrupt.pdf")
    corrupt_pdf_path.write_bytes(corrupt_bytes)

    with open(corrupt_pdf_path, "rb") as f:
        ana_res2 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step5_corrupt.pdf", f, "application/pdf")})
    ana_id2 = ana_res2.json()["analysis_document_id"]
    requests.post(f"{BASE_URL}/security/analysis/{ana_id2}/verify", headers=headers_analyst)

    q_res2 = requests.post(f"{BASE_URL}/security/analysis/{ana_id2}/quantum-analysis", headers=headers_analyst)
    assert q_res2.status_code == 200
    q_data2 = q_res2.json()["quantum_analysis"]

    assert q_data2["final_classification"] == "HIGH_RISK", f"Expected HIGH_RISK but got {q_data2['final_classification']}"
    assert q_data2["forgery_risk_score"] > 60.0, f"Expected Risk Score > 60 but got {q_data2['forgery_risk_score']}"
    assert q_data2["pauli_x_score"] > 50.0, f"Expected Pauli X > 50% but got {q_data2['pauli_x_score']}"
    print(f"[OK] Classification: {q_data2['final_classification']}")
    print(f"[OK] Forgery Risk Score: {q_data2['forgery_risk_score']}/100 | Pauli X (Bit Flip): {q_data2['pauli_x_score']}%")

    # ------------------------------------------------------------------
    # TEST 3: Modified Document (HIGH_RISK Integrity Failure Analysis)
    # ------------------------------------------------------------------
    print("\n--- TEST 3: Modified Document Quantum Analysis ---")
    modified_bytes = signed_pdf_bytes.replace(b'/Catalog', b'/Xatalog')
    modified_pdf_path = Path("step5_modified.pdf")
    modified_pdf_path.write_bytes(modified_bytes)

    with open(modified_pdf_path, "rb") as f:
        ana_res3 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step5_modified.pdf", f, "application/pdf")})
    ana_id3 = ana_res3.json()["analysis_document_id"]
    requests.post(f"{BASE_URL}/security/analysis/{ana_id3}/verify", headers=headers_analyst)

    q_res3 = requests.post(f"{BASE_URL}/security/analysis/{ana_id3}/quantum-analysis", headers=headers_analyst)
    assert q_res3.status_code == 200
    q_data3 = q_res3.json()["quantum_analysis"]

    assert q_data3["final_classification"] == "HIGH_RISK", f"Expected HIGH_RISK but got {q_data3['final_classification']}"
    assert q_data3["forgery_risk_score"] > 60.0
    print(f"[OK] Classification: {q_data3['final_classification']}")
    print(f"[OK] Forgery Risk Score: {q_data3['forgery_risk_score']}/100 | High Risk Measurement: {q_data3['high_risk_measurement_score']}%")

    # ------------------------------------------------------------------
    # TEST 4: Unsigned PDF Document Analysis
    # ------------------------------------------------------------------
    print("\n--- TEST 4: Unsigned Document Quantum Analysis ---")
    with open(sample_pdf_path, "rb") as f:
        ana_res4 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step5_blank.pdf", f, "application/pdf")})
    ana_id4 = ana_res4.json()["analysis_document_id"]
    requests.post(f"{BASE_URL}/security/analysis/{ana_id4}/verify", headers=headers_analyst)

    q_res4 = requests.post(f"{BASE_URL}/security/analysis/{ana_id4}/quantum-analysis", headers=headers_analyst)
    assert q_res4.status_code == 200
    q_data4 = q_res4.json()["quantum_analysis"]

    assert q_data4["final_classification"] in ["INSUFFICIENT_EVIDENCE", "SUSPICIOUS", "HIGH_RISK"]
    print(f"[OK] Classification: {q_data4['final_classification']} | Forgery Risk: {q_data4['forgery_risk_score']}/100")

    # ------------------------------------------------------------------
    # TEST 5: Certificate Time Validity Anomaly Unit Test
    # ------------------------------------------------------------------
    print("\n--- TEST 5: Certificate Time Anomaly Quantum Engine Test ---")
    cert_expired_meta = {
        "signature_detected": True,
        "signature_status": "SIGNATURE_FOUND",
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_size": 2048
    }
    cert_expired_verifs = [
        {
            "verification_status": "VALID",
            "integrity_status": "INTACT",
            "certificate_time_status": "EXPIRED"
        }
    ]
    q_cert_exp = analyze_quantum_security_state(cert_expired_meta, cert_expired_verifs)
    assert q_cert_exp["final_classification"] in ["SUSPICIOUS", "HIGH_RISK"]
    assert q_cert_exp["pauli_z_score"] > 0.0, "Expected Pauli Z phase anomaly > 0"
    print(f"[OK] Expired Cert State: {q_cert_exp['final_classification']} | Pauli Z (Phase Anomaly): {q_cert_exp['pauli_z_score']}%")

    # ------------------------------------------------------------------
    # TEST 6: Combined Anomalies Quantum Engine Test
    # ------------------------------------------------------------------
    print("\n--- TEST 6: Combined Anomalies Quantum Engine Test ---")
    comb_meta = {
        "signature_detected": True,
        "signature_status": "SIGNATURE_FOUND",
        "signature_algorithm": "md5WithRSAEncryption", # Weak algorithm
        "public_key_size": 1024                         # Weak key
    }
    comb_verifs = [
        {
            "verification_status": "INVALID",
            "integrity_status": "MODIFIED",
            "certificate_time_status": "EXPIRED"
        }
    ]
    q_comb = analyze_quantum_security_state(comb_meta, comb_verifs)
    assert q_comb["final_classification"] == "HIGH_RISK"
    assert q_comb["forgery_risk_score"] > 75.0
    assert q_comb["high_risk_measurement_score"] > 70.0
    print(f"[OK] Combined Anomalies Classification: {q_comb['final_classification']}")
    print(f"[OK] Risk Score: {q_comb['forgery_risk_score']}/100 | P(HighRisk): {q_comb['high_risk_measurement_score']}%")

    # ------------------------------------------------------------------
    # TEST 7: 100% Determinism and Repeatability Verification
    # ------------------------------------------------------------------
    print("\n--- TEST 7: Determinism & Repeatability Verification (10 Runs) ---")
    initial_run = analyze_quantum_security_state(cert_expired_meta, cert_expired_verifs)
    for run_idx in range(1, 11):
        repeat_run = analyze_quantum_security_state(cert_expired_meta, cert_expired_verifs)
        assert repeat_run["security_state_vector"] == initial_run["security_state_vector"]
        assert repeat_run["disturbance_score"] == initial_run["disturbance_score"]
        assert repeat_run["pauli_x_score"] == initial_run["pauli_x_score"]
        assert repeat_run["pauli_y_score"] == initial_run["pauli_y_score"]
        assert repeat_run["pauli_z_score"] == initial_run["pauli_z_score"]
        assert repeat_run["secure_measurement_score"] == initial_run["secure_measurement_score"]
        assert repeat_run["suspicious_measurement_score"] == initial_run["suspicious_measurement_score"]
        assert repeat_run["high_risk_measurement_score"] == initial_run["high_risk_measurement_score"]
        assert repeat_run["forgery_risk_score"] == initial_run["forgery_risk_score"]
        assert repeat_run["final_classification"] == initial_run["final_classification"]
    print("[OK] 10/10 consecutive runs yielded 100.0% identical deterministic results across all variables!")

    # ------------------------------------------------------------------
    # TEST 8: Explanation API Endpoint Verification
    # ------------------------------------------------------------------
    print("\n--- TEST 8: Quantum Analysis Explanation API Verification ---")
    exp_res = requests.get(f"{BASE_URL}/security/analysis/{ana_id1}/analysis-explanation", headers=headers_analyst)
    assert exp_res.status_code == 200
    exp_data = exp_res.json()
    assert "Normalized" in exp_data["step1_feature_mapping"]
    assert "|psi>" in exp_data["step2_state_vector"]
    assert "Pauli" in exp_data["step3_pauli_analysis"]
    assert "Projective" in exp_data["step4_measurement"]
    assert "Forgery Risk" in exp_data["step5_decision"]
    print(f"[OK] Mathematical explanation API returned full step-by-step breakdown!")

    # Clean up temporary test files
    sample_pdf_path.unlink(missing_ok=True)
    valid_signed_pdf_path.unlink(missing_ok=True)
    modified_pdf_path.unlink(missing_ok=True)
    corrupt_pdf_path.unlink(missing_ok=True)

    print("\n==================================================================")
    print("ALL 8 STEP 5 QUANTUM-INSPIRED ENGINE TESTS PASSED PERFECTLY!")
    print("==================================================================")

if __name__ == "__main__":
    run_step5_quantum_tests()
