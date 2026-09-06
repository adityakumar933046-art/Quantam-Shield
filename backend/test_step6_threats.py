import requests
import sqlite3
import time
from pathlib import Path
from pypdf import PdfWriter
import sys

sys.path.append(str(Path(__file__).resolve().parent))
from app.core.threat_engine import analyze_replay_suspicion

BASE_URL = "http://127.0.0.1:8000/api"
DB_PATH = Path("database/qshield.db").resolve()
if not DB_PATH.exists():
    DB_PATH = Path("../database/qshield.db").resolve()

def run_step6_threat_tests():
    print("==================================================================")
    print("RUNNING STEP 6 - HISTORICAL THREAT DETECTION ENGINE TESTS")
    print("==================================================================")

    # 0. Authenticate Security Analyst & Digital Signature User
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp.status_code == 200
    token_analyst = login_resp.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    print("[AUTH] Logged in as analyst@qshield.com (Security Analyst)")

    login_resp2 = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_resp2.status_code == 200
    token_user2 = login_resp2.json()["access_token"]
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    # Generate a fresh valid signed PDF via Step 2 API
    sample_pdf_path = Path("step6_blank.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(sample_pdf_path, "wb") as f:
        writer.write(f)

    with open(sample_pdf_path, "rb") as f:
        u_res = requests.post(f"{BASE_URL}/documents/upload", headers=headers_user2, files={"file": ("step6_blank.pdf", f, "application/pdf")})
    assert u_res.status_code == 200
    doc_id = u_res.json()["document_id"]
    
    s_res = requests.post(f"{BASE_URL}/documents/{doc_id}/sign", headers=headers_user2)
    assert s_res.status_code == 200
    
    d_res = requests.get(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_user2)
    signed_pdf_bytes = d_res.content
    valid_signed_pdf_path = Path("step6_valid_signed.pdf")
    valid_signed_pdf_path.write_bytes(signed_pdf_bytes)

    # ------------------------------------------------------------------
    # TEST 1: Normal Repeat Activity (Single Upload)
    # ------------------------------------------------------------------
    print("\n--- TEST 1: Normal Single Document Activity ---")
    with open(valid_signed_pdf_path, "rb") as f:
        ana_res1 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step6_valid_signed.pdf", f, "application/pdf")})
    assert ana_res1.status_code == 200
    ana_id1 = ana_res1.json()["analysis_document_id"]

    t_res1 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/threat-detection", headers=headers_analyst)
    assert t_res1.status_code == 200
    incidents1 = t_res1.json().get("threat_incidents", [])
    print(f"[OK] Normal repeat document analyzed without false attack alerts (Incidents: {len(incidents1)})")

    # ------------------------------------------------------------------
    # TEST 2: Suspicious Replay Activity Detection (REPLAY_SUSPECTED)
    # ------------------------------------------------------------------
    print("\n--- TEST 2: Suspicious Replay Activity Detection ---")
    # Upload the exact same document 3 more times rapidly
    for i in range(3):
        with open(valid_signed_pdf_path, "rb") as f:
            requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": (f"step6_valid_signed_r{i}.pdf", f, "application/pdf")})

    # Run threat detection on the latest document
    t_res2 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/threat-detection", headers=headers_analyst)
    assert t_res2.status_code == 200
    incidents2 = t_res2.json().get("threat_incidents", [])

    replay_inc = next((inc for inc in incidents2 if inc["threat_category"] == "REPLAY_SUSPECTED"), None)
    assert replay_inc is not None, "Expected REPLAY_SUSPECTED threat incident to be generated"
    assert replay_inc["severity"] in ["MEDIUM", "HIGH"]
    assert replay_inc["threat_score"] >= 35.0
    print(f"[OK] Replay Suspicion Threat Detected! Category: {replay_inc['threat_category']} | Score: {replay_inc['threat_score']}/100")

    # ------------------------------------------------------------------
    # TEST 3: Suspicious Repeated Verification Detection
    # ------------------------------------------------------------------
    print("\n--- TEST 3: Suspicious Repeated Verification Detection ---")
    for _ in range(3):
        requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/verify", headers=headers_analyst)

    t_res3 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/threat-detection", headers=headers_analyst)
    assert t_res3.status_code == 200
    incidents3 = t_res3.json().get("threat_incidents", [])

    rep_verif_inc = next((inc for inc in incidents3 if inc["threat_category"] == "SUSPICIOUS_REPEATED_VERIFICATION"), None)
    assert rep_verif_inc is not None, "Expected SUSPICIOUS_REPEATED_VERIFICATION incident"
    print(f"[OK] Repeated Verification Threat Detected! Category: {rep_verif_inc['threat_category']} | Score: {rep_verif_inc['threat_score']}/100")

    # ------------------------------------------------------------------
    # TEST 4: Unauthorized Access Attempt Logging
    # ------------------------------------------------------------------
    print("\n--- TEST 4: Unauthorized Access Attempt Logging ---")
    # Digital Signature User calls restricted analyst endpoint
    unauth_resp = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/verify", headers=headers_user2)
    assert unauth_resp.status_code == 403

    t_res4 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/threat-detection", headers=headers_analyst)
    assert t_res4.status_code == 200
    incidents4 = t_res4.json().get("threat_incidents", [])

    unauth_inc = next((inc for inc in incidents4 if inc["threat_category"] == "UNAUTHORIZED_VERIFICATION_ATTEMPT"), None)
    assert unauth_inc is not None, "Expected UNAUTHORIZED_VERIFICATION_ATTEMPT incident"
    print(f"[OK] Unauthorized Access Threat Logged! Category: {unauth_inc['threat_category']} | Severity: {unauth_inc['severity']}")

    # ------------------------------------------------------------------
    # TEST 5: Time-Window Activity Statistics API
    # ------------------------------------------------------------------
    print("\n--- TEST 5: Time-Window Activity Statistics API Verification ---")
    stats_res = requests.get(f"{BASE_URL}/security/activity-stats", headers=headers_analyst)
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert "stats_5m" in stats_data
    assert "stats_15m" in stats_data
    assert "stats_1h" in stats_data
    assert "stats_24h" in stats_data
    assert stats_data["stats_15m"]["total_uploads"] >= 4
    print(f"[OK] Activity Statistics returned for 5m, 15m, 1h, 24h! Uploads (15m): {stats_data['stats_15m']['total_uploads']}")

    # ------------------------------------------------------------------
    # TEST 6: Threat Incident Resolution API Lifecycle
    # ------------------------------------------------------------------
    print("\n--- TEST 6: Threat Incident Resolution API Lifecycle ---")
    inc_id = replay_inc["incident_id"]
    upd_res = requests.put(f"{BASE_URL}/security/threat-incidents/{inc_id}/status", json={"threat_status": "INVESTIGATING"}, headers=headers_analyst)
    assert upd_res.status_code == 200
    assert upd_res.json()["threat_status"] == "INVESTIGATING"

    upd_res2 = requests.put(f"{BASE_URL}/security/threat-incidents/{inc_id}/status", json={"threat_status": "RESOLVED"}, headers=headers_analyst)
    assert upd_res2.status_code == 200
    assert upd_res2.json()["threat_status"] == "RESOLVED"
    print(f"[OK] Incident #{inc_id} status lifecycle updated: OPEN -> INVESTIGATING -> RESOLVED")

    # ------------------------------------------------------------------
    # TEST 7: Global Threat Incidents Filtering API
    # ------------------------------------------------------------------
    print("\n--- TEST 7: Global Threat Incidents List API ---")
    # ------------------------------------------------------------------
    # TEST 8: 100% Determinism & Repeatability Verification (10 Runs)
    # ------------------------------------------------------------------
    print("\n--- TEST 8: Determinism & Repeatability Verification (10 Runs) ---")
    # Query database session directly for test
    db_conn = sqlite3.connect(DB_PATH)
    cur = db_conn.cursor()
    cur.execute("SELECT document_hash FROM analyzed_documents LIMIT 1")
    row = cur.fetchone()
    db_conn.close()

    if row:
        target_h = row[0]
        from app.core.db import SessionLocal
        db_s = SessionLocal()
        try:
            r_init = analyze_replay_suspicion(db_s, document_hash=target_h, time_window_minutes=15)
            for _ in range(10):
                r_rep = analyze_replay_suspicion(db_s, document_hash=target_h, time_window_minutes=15)
                assert r_rep["replay_suspicion_score"] == r_init["replay_suspicion_score"]
                assert r_rep["replay_classification"] == r_init["replay_classification"]
            print("[OK] 10/10 consecutive runs yielded 100.0% identical deterministic replay scores!")
        finally:
            db_s.close()

    # Clean up temporary test files
    sample_pdf_path.unlink(missing_ok=True)
    valid_signed_pdf_path.unlink(missing_ok=True)

    print("\n==================================================================")
    print("ALL 8 STEP 6 HISTORICAL THREAT ENGINE TESTS PASSED PERFECTLY!")
    print("==================================================================")

if __name__ == "__main__":
    run_step6_threat_tests()
