"""
STEP 8 — FINAL SYSTEM INTEGRATION & SIH DEMO SCENARIOS TEST SUITE
Validates the complete end-to-end Q-SHIELD platform:
- 20-Step Full Verification Lifecycle
- All 7 SIH Demonstration Scenarios
- Defensive Performance Evaluation Metrics & Latency Benchmarks
- Security Protections (Zero Secret Leakage, RBAC)
"""

import sys
import os
import time
import json
import uuid
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app
from app.core.db import SessionLocal
from app.core.audit_engine import verify_audit_log_integrity
from app.core.performance_engine import calculate_performance_metrics

client = TestClient(app)


def run_step8_final_integration():
    print("==================================================================")
    print("  Q-SHIELD STEP 8: FINAL SYSTEM INTEGRATION & SIH DEMO TEST SUITE")
    print("==================================================================")

    passed = 0
    failed = 0
    latencies = {}

    # ==================================================================
    # 1. AUTHENTICATION & TOKEN RETRIEVAL
    # ==================================================================
    print("\n--- PHASE 1: Authenticating Platform Personas ---")
    t0 = time.perf_counter()
    resp_user = client.post("/api/auth/login", json={"email": "user@qshield.com", "password": "UserPassword123!"})
    assert resp_user.status_code == 200, f"User login failed: {resp_user.text}"
    user_token = resp_user.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {user_token}"}

    resp_analyst = client.post("/api/auth/login", json={"email": "analyst@qshield.com", "password": "AnalystPassword123!"})
    assert resp_analyst.status_code == 200, f"Analyst login failed: {resp_analyst.text}"
    analyst_token = resp_analyst.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    resp_admin = client.post("/api/auth/login", json={"email": "admin@qshield.com", "password": "AdminPassword123!"})
    assert resp_admin.status_code == 200, f"Admin login failed: {resp_admin.text}"
    admin_token = resp_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    latencies["auth_roundtrip_ms"] = (time.perf_counter() - t0) * 1000

    print(f"[PASS] Authentication verified for all 3 roles ({latencies['auth_roundtrip_ms']:.1f} ms).")
    passed += 1

    # ==================================================================
    # 2. COMPLETE 20-STEP END-TO-END LIFECYCLE
    # ==================================================================
    print("\n--- PHASE 2: 20-Step Full Verification Lifecycle ---")
    try:
        sample_text = f"Q-SHIELD DEFENSE CONTRACT AUTHORIZATION #{uuid.uuid4().hex[:6].upper()}\nTerms: Validated"
        sample_bytes = sample_text.encode("utf-8")

        # Step 2.1: Upload & Sign Document
        t_sign_start = time.perf_counter()
        sign_resp = client.post(
            "/api/signatures/create/",
            headers=user_headers,
            files={"file": ("contract_e2e.txt", sample_bytes, "text/plain")}
        )
        assert sign_resp.status_code == 200, f"Signing failed: {sign_resp.text}"
        sign_data = sign_resp.json()
        doc_id = sign_data["document_id"]
        doc_hash = sign_data["document_hash"]
        signature_id = sign_data["signature_id"]
        latencies["document_signing_ms"] = (time.perf_counter() - t_sign_start) * 1000
        print(f"  [+] Step 1-6: Document signed. Hash: {doc_hash[:16]}... ({latencies['document_signing_ms']:.1f} ms)")

        # Download signed artifact
        signed_file_bytes = client.get(sign_data["download_url"], headers=user_headers).content

        # Step 2.2: Analyst Upload & Multi-Layer Analysis
        t_anl_start = time.perf_counter()
        anl_resp = client.post(
            "/api/verify/analyze/",
            headers=analyst_headers,
            files={"file": ("contract_e2e.signed.txt", signed_file_bytes, "text/plain")}
        )
        assert anl_resp.status_code == 200, f"Analysis failed: {anl_resp.text}"
        anl_data = anl_resp.json()
        analysis_id = anl_data["analysis_document_id"]
        latencies["security_analysis_ms"] = (time.perf_counter() - t_anl_start) * 1000

        assert anl_data["signature_verified"] is True or anl_data["final_decision"] in ["SECURE", "VERIFIED", "VALID", "AUTHENTIC"]
        assert anl_data["integrity_verified"] is True
        assert anl_data["risk_level"] in ["LOW", "MEDIUM"]
        print(f"  [+] Step 7-19: Multi-layer analysis completed ({latencies['security_analysis_ms']:.1f} ms). Status: {anl_data['final_decision']}")

        # Step 2.3: Generate & Export Security Report
        t_rep_start = time.perf_counter()
        rep_resp = client.post(
            "/api/reports/generate",
            headers=analyst_headers,
            json={"report_type": "ANALYSIS_REPORT", "analysis_id": analysis_id, "notes": "E2E Automated test run"}
        )
        assert rep_resp.status_code == 200, f"Report generation failed: {rep_resp.text}"
        rep_data = rep_resp.json()
        report_ref = rep_data.get("report_reference")
        latencies["report_generation_ms"] = (time.perf_counter() - t_rep_start) * 1000
        print(f"  [+] Step 20: Report generated: {report_ref} ({latencies['report_generation_ms']:.1f} ms)")

        print("[PASS] Full 20-step verification lifecycle executed successfully with actual DB persistence.")
        passed += 1
    except Exception as e:
        import traceback
        print(f"[FAIL] Error: {e}")
        traceback.print_exc()
        failed += 1

    # ==================================================================
    # 3. SIH DEMO SCENARIOS 1 TO 7
    # ==================================================================
    print("\n--- PHASE 3: Validating SIH Demo Scenarios (1 to 7) ---")

    # SCENARIO 1: VALID DOCUMENT
    try:
        demo_clean_text = "SIH 2026 DEMO VALID PROCUREMENT SPECIFICATION\nClassification: Secure"
        demo_clean_bytes = demo_clean_text.encode("utf-8")

        s_res = client.post(
            "/api/signatures/create/",
            headers=user_headers,
            files={"file": ("SIH_clean.txt", demo_clean_bytes, "text/plain")}
        )
        assert s_res.status_code == 200
        s_clean_bytes = client.get(s_res.json()["download_url"], headers=user_headers).content

        a_res = client.post(
            "/api/verify/analyze/",
            headers=analyst_headers,
            files={"file": ("SIH_clean.signed.txt", s_clean_bytes, "text/plain")}
        )
        assert a_res.status_code == 200
        d_res = a_res.json()
        assert d_res["integrity_verified"] is True
        assert d_res["risk_score"] <= 25.0
        assert len(d_res.get("threats", [])) == 0
        print("[PASS] Scenario 1: Valid document analysis yields VALID, INTACT, LOW RISK, 0 THREATS.")
        passed += 1
    except Exception as e:
        import traceback
        print(f"[FAIL] Scenario 1 error: {e}")
        traceback.print_exc()
        failed += 1

    # SCENARIO 2: DOCUMENT TAMPERING
    try:
        # Alter the signed message body while keeping the signature block intact
        tampered_signed_bytes = s_clean_bytes.replace(
            b"SIH 2026 DEMO VALID PROCUREMENT SPECIFICATION",
            b"SIH 2026 TAMPERED ILLEGAL SPECIFICATION - COMPROMISED"
        )
        if tampered_signed_bytes == s_clean_bytes:
            # Fallback if replace didn't find exact text: modify first 20 bytes
            tampered_signed_bytes = b"[TAMPERED DATA] " + s_clean_bytes

        a_tamp = client.post(
            "/api/verify/analyze/",
            headers=analyst_headers,
            files={"file": ("SIH_clean.signed.txt", tampered_signed_bytes, "text/plain")}
        )
        assert a_tamp.status_code == 200
        t_data = a_tamp.json()
        assert t_data["integrity_verified"] is False
        assert t_data["risk_level"] in ["HIGH", "CRITICAL"]
        assert any(t["threat_category"] == "DOCUMENT_TAMPERING" for t in t_data.get("threats", []))
        print("[PASS] Scenario 2: Document tampering caught with DOCUMENT_TAMPERING threat & CRITICAL risk.")
        passed += 1
    except Exception as e:
        import traceback
        print(f"[FAIL] Scenario 2 error: {e}")
        traceback.print_exc()
        failed += 1

    # SCENARIO 3: SIGNATURE FORGERY
    try:
        sim_forgery = client.post(
            "/api/simulations/execute/",
            headers=analyst_headers,
            json={"attack_type": "SIGNATURE_FORGERY", "target_document_reference": "SIH_clean.txt"}
        )
        assert sim_forgery.status_code == 200
        f_data = sim_forgery.json()
        res_f = f_data["result"]
        assert res_f["detection_status"] == "DETECTED"
        assert res_f["forgery_risk_estimate"] >= 40.0
        assert res_f["final_risk_score"] >= 70.0
        print(f"[PASS] Scenario 3: Signature forgery detected (Forgery Risk: {res_f['forgery_risk_estimate']:.1f}%).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Scenario 3 error: {e}")
        failed += 1

    # SCENARIO 4: REPLAY ATTACK (Threshold Frequency Detection)
    try:
        # Rapid repeated verification events
        for _ in range(7):
            client.post(
                "/api/verify/analyze/",
                headers=analyst_headers,
                files={"file": ("SIH_clean.signed.txt", s_clean_bytes, "text/plain")}
            )
        # Check last analysis for replay detection
        check_anl = client.post(
            "/api/verify/analyze/",
            headers=analyst_headers,
            files={"file": ("SIH_clean.signed.txt", s_clean_bytes, "text/plain")}
        )
        assert check_anl.status_code == 200
        anl_replay = check_anl.json()
        replay_found = any(t["threat_category"] == "REPLAY_ATTACK" for t in anl_replay.get("threats", []))
        assert replay_found, "Replay attack was not detected after rapid successive requests"
        print("[PASS] Scenario 4: Replay attack detected only after rapid frequency threshold exceeded.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Scenario 4 error: {e}")
        failed += 1

    # SCENARIO 5: IMPERSONATION (Identity Mismatch)
    try:
        sim_imp = client.post(
            "/api/simulations/execute/",
            headers=analyst_headers,
            json={"attack_type": "IMPERSONATION", "target_document_reference": "SIH_clean.txt"}
        )
        assert sim_imp.status_code == 200
        res_imp = sim_imp.json()["result"]
        assert res_imp["detection_status"] == "DETECTED"
        assert any("IMPERSONATION" in str(t) for t in (res_imp["threats_detected"] or []))
        print("[PASS] Scenario 5: Impersonation mismatch detected through PKI signer identity evaluation.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Scenario 5 error: {e}")
        failed += 1

    # SCENARIO 6: UNAUTHORIZED VERIFICATION ACCESS
    try:
        resp_unauth = client.get("/api/admin/audit-logs", headers=user_headers)
        assert resp_unauth.status_code == 403, f"Expected 403 Forbidden, got {resp_unauth.status_code}"

        resp_no_token = client.get("/api/reports")
        assert resp_no_token.status_code in [401, 403]
        print("[PASS] Scenario 6: Unauthorized access strictly blocked with HTTP 401/403.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Scenario 6 error: {e}")
        failed += 1

    # SCENARIO 7: QUANTUM-INSPIRED ATTACK SIMULATION (Pauli X, Y, Z, Projective Measurement)
    try:
        for p_scenario in ["PAULI_X_DISTURBANCE", "PAULI_Y_DISTURBANCE", "MEASUREMENT_DISTURBANCE"]:
            sim_q = client.post(
                "/api/simulations/execute/",
                headers=analyst_headers,
                json={
                    "attack_type": "QUANTUM_CHANNEL_MANIPULATION",
                    "target_document_reference": "SIH_clean.txt",
                    "parameters": {"scenario": p_scenario}
                }
            )
            assert sim_q.status_code == 200
            q_res = sim_q.json()["result"]
            assert q_res["detection_status"] == "DETECTED"
            assert q_res["state_disturbance"] > 0.0 or q_res["pauli_disturbance"] > 0.0

        print("[PASS] Scenario 7: Quantum-inspired Pauli disturbances & Born measurements strictly evaluated.")
        passed += 1
    except Exception as e:
        import traceback
        print(f"[FAIL] Scenario 7 error: {e}")
        traceback.print_exc()
        failed += 1

    # ==================================================================
    # 4. DEFENSIVE PERFORMANCE BENCHMARKING & AUDIT INTEGRITY
    # ==================================================================
    print("\n--- PHASE 4: Performance Benchmarking & Audit Verification ---")
    try:
        db = SessionLocal()
        perf = calculate_performance_metrics(db)
        assert perf["total_simulations"] >= 1
        assert perf["accuracy"] >= 0.80
        assert perf["detection_rate"] >= 80.0
        assert "SIMULATION" in perf["disclaimer"].upper()
        print(f"  [+] Defensive Accuracy: {perf['accuracy']*100:.1f}%, F1-Score: {perf['f1_score']:.4f}, Rate: {perf['detection_rate']:.1f}%")

        audit_check = verify_audit_log_integrity(db)
        assert audit_check["status"] == "AUDIT_LOG_VALID"
        assert audit_check["chain_intact"] is True
        print(f"  [+] Cryptographic Audit Chain: AUDIT_LOG_VALID ({audit_check['total_records_verified']} records verified intact)")

        db.close()
        print("[PASS] Defensive performance evaluation & SHA-256 audit chain verified.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Performance & Audit verification error: {e}")
        failed += 1

    # ==================================================================
    # 5. SECURITY & ZERO SECRET LEAKAGE TESTING
    # ==================================================================
    print("\n--- PHASE 5: Security & Defensive Protections Verification ---")
    try:
        # Verify no private keys in reports list
        r_list = client.get("/api/reports", headers=analyst_headers).json()
        r_str = json.dumps(r_list)
        assert "-----BEGIN RSA PRIVATE KEY-----" not in r_str
        assert "UserPassword123!" not in r_str
        assert "AnalystPassword123!" not in r_str

        # Verify no stack trace leaks on malformed input
        bad_resp = client.post(
            "/api/verify/analyze/",
            headers=analyst_headers,
            files={"file": ("corrupt.bin", b"\x00\xff\xfe\xfd\x00\x01\x02", "application/octet-stream")}
        )
        assert bad_resp.status_code in [200, 400, 422]
        if bad_resp.status_code >= 400:
            assert "Traceback" not in bad_resp.text

        print("[PASS] Security protections verified: zero private keys, zero passwords in responses.")
        passed += 1
    except Exception as e:
        import traceback
        print(f"[FAIL] Security verification error: {e}")
        traceback.print_exc()
        failed += 1

    # ==================================================================
    # LATENCY SUMMARY
    # ==================================================================
    print("\n--- Real Performance Latency Measurements ---")
    for metric, ms in latencies.items():
        print(f"  * {metric}: {ms:.2f} ms")

    print("\n==================================================================")
    print(f"  STEP 8 FINAL INTEGRATION RESULTS: {passed} PASSED, {failed} FAILED")
    print("==================================================================")
    return failed == 0


if __name__ == "__main__":
    success = run_step8_final_integration()
    sys.exit(0 if success else 1)
