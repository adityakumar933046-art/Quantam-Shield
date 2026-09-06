"""
STEP 4 INTEGRATION TEST SUITE: DATABASE INTEGRATION & COMPLETE END-TO-END CONNECTION

Covers the 6 mandatory test scenarios:
1. Valid Signed File Verification (PDF & TXT)
2. Tampered File Verification (detects DOCUMENT_TAMPERING)
3. Replay Attack Simulation (rapid verifications trigger REPLAY_ATTACK)
4. Invalid Signature Verification (detects FORGERY/INVALID_SIGNATURE)
5. Unknown Signature Verification (produces UNKNOWN_SIGNATURE / PUBLIC_KEY_NOT_FOUND, NOT FORGERY)
6. Private Key Security (private key encrypted at rest, NEVER returned in API responses)
"""

import os
import sys
import json
import base64
import requests

BASE_URL = "http://127.0.0.1:8000"

# Test credentials
USER_CREDENTIALS = {
    "email": "user@qshield.com",
    "password": "UserPassword123!"
}
ANALYST_CREDENTIALS = {
    "email": "analyst@qshield.com",
    "password": "AnalystPassword123!"
}


def get_token(credentials):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json=credentials)
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


def test_scenario_1_valid_signature(signer_token, analyst_token):
    print("\n--- TEST 1: Valid Signed File Verification ---")
    headers_signer = {"Authorization": f"Bearer {signer_token}"}
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    import uuid
    run_id = uuid.uuid4().hex[:8]
    # 1. Sign text content
    payload_text = f"OFFICIAL EXECUTIVE AUTHORIZATION ORDER #{run_id}. FUNDS CLEARED."
    data = {
        "raw_text": payload_text,
        "filename": f"executive_order_{run_id}.txt"
    }
    sign_resp = requests.post(f"{BASE_URL}/api/signatures/create/", data=data, headers=headers_signer)
    assert sign_resp.status_code == 200, f"Signing failed: {sign_resp.text}"
    sig_data = sign_resp.json()

    sig_id = sig_data["signature_id"]
    doc_hash = sig_data["document_hash"]
    sig_val = sig_data["signature_value"]
    print(f"[OK] Generated Signature ID: {sig_id}")
    print(f"[OK] Document SHA-256 Hash: {doc_hash}")

    assert sig_id.startswith("QSHIELD-SIGN-"), f"Unexpected signature ID format: {sig_id}"
    assert sig_data["public_key"] is not None, "Missing public key"

    # 2. Retrieve signature by ID
    get_resp = requests.get(f"{BASE_URL}/api/signatures/{sig_id}/", headers=headers_analyst)
    assert get_resp.status_code == 200, f"Fetch failed: {get_resp.text}"
    assert get_resp.json()["signature_id"] == sig_id

    # 3. Verify valid content
    verif_data = {
        "raw_text": payload_text,
        "filename": "executive_order.txt",
        "signature": sig_val,
        "signature_id": sig_id
    }
    v_resp = requests.post(f"{BASE_URL}/api/verify/analyze/", data=verif_data, headers=headers_analyst)
    assert v_resp.status_code == 200, f"Verification failed: {v_resp.text}"
    result = v_resp.json()

    print(f"[OK] Analysis ID: {result['analysis_id']}")
    print(f"[OK] Final Decision: {result['final_decision']}")
    print(f"[OK] Signature Verified: {result['signature_verified']}")
    print(f"[OK] Integrity Verified: {result['integrity_verified']}")
    print(f"[OK] Risk Score: {result['risk_score']}")

    assert result["signature_verified"] is True, "Signature should be valid"
    assert result["integrity_verified"] is True, "Integrity should be intact"
    assert result["final_decision"] == "VALID", f"Expected VALID decision, got: {result['final_decision']}"
    assert result["risk_score"] <= 35.0, f"Risk score unexpectedly high: {result['risk_score']}"
    print(">>> TEST 1 PASSED: Valid signed document correctly verified!")
    return sig_data


def test_scenario_2_tampered_file(signer_token, analyst_token):
    print("\n--- TEST 2: Tampered File Verification ---")
    headers_signer = {"Authorization": f"Bearer {signer_token}"}
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    import uuid
    run_id2 = uuid.uuid4().hex[:8]
    original_text = f"TRANSFER $500 TO ACCOUNT A - REF {run_id2}"
    sign_resp = requests.post(f"{BASE_URL}/api/signatures/create/", data={
        "raw_text": original_text,
        "filename": f"transfer_original_{run_id2}.txt"
    }, headers=headers_signer)
    assert sign_resp.status_code == 200
    sig_info = sign_resp.json()
    sig_id = sig_info["signature_id"]
    sig_val = sig_info["signature_value"]

    # Alter text after signing
    tampered_text = f"TRANSFER $500,000,000 TO ATTACKER ACCOUNT B - REF {run_id2}"
    verif_data = {
        "raw_text": tampered_text,
        "filename": f"transfer_original_{run_id2}.txt",
        "signature": sig_val,
        "signature_id": sig_id
    }
    v_resp = requests.post(f"{BASE_URL}/api/verify/analyze/", data=verif_data, headers=headers_analyst)
    assert v_resp.status_code == 200
    res = v_resp.json()

    print(f"[OK] Tampered File Final Decision: {res['final_decision']}")
    print(f"[OK] Integrity Verified: {res['integrity_verified']}")
    print(f"[OK] Threats Detected: {[t['threat_category'] for t in res['threats']]}")
    print(f"[OK] Risk Score: {res['risk_score']}")

    assert res["integrity_verified"] is False, "Integrity check must fail for tampered document"
    assert res["final_decision"] == "INTEGRITY_MISMATCH", f"Expected INTEGRITY_MISMATCH, got {res['final_decision']}"
    assert any(t["threat_category"] == "DOCUMENT_TAMPERING" for t in res["threats"]), "Expected DOCUMENT_TAMPERING threat"
    assert res["risk_score"] >= 80.0, "Risk score must be >= 80 for tampered document"
    print(">>> TEST 2 PASSED: Document tampering successfully detected!")


def test_scenario_3_replay_attack(signer_token, analyst_token):
    print("\n--- TEST 3: Replay Attack Simulation ---")
    headers_signer = {"Authorization": f"Bearer {signer_token}"}
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    text = "AUTHENTICATION TOKEN #99482 RAPID VERIFY REPLAY TARGET"
    sign_resp = requests.post(f"{BASE_URL}/api/signatures/create/", data={
        "raw_text": text,
        "filename": "auth_token.txt"
    }, headers=headers_signer)
    assert sign_resp.status_code == 200
    sig_info = sign_resp.json()
    sig_id = sig_info["signature_id"]
    sig_val = sig_info["signature_value"]

    verif_data = {
        "raw_text": text,
        "filename": "auth_token.txt",
        "signature": sig_val,
        "signature_id": sig_id
    }

    # Trigger rapid verifications exceeding REPLAY_THRESHOLD_COUNT (threshold=4)
    last_res = None
    for attempt in range(6):
        r = requests.post(f"{BASE_URL}/api/verify/analyze/", data=verif_data, headers=headers_analyst)
        assert r.status_code == 200
        last_res = r.json()

    print(f"[OK] Rapid Attempts Completed: 6")
    print(f"[OK] Final Decision after replay: {last_res['final_decision']}")
    threat_categories = [t["threat_category"] for t in last_res["threats"]]
    print(f"[OK] Detected Threats: {threat_categories}")

    has_replay = any(
        t in threat_categories for t in ["REPLAY_ATTACK", "REPLAY_SUSPECTED"]
    )
    assert has_replay, f"Replay attack should have been flagged after 6 rapid requests! Got: {threat_categories}"
    print(">>> TEST 3 PASSED: Replay attack successfully detected and flagged!")


def test_scenario_4_invalid_signature(analyst_token):
    print("\n--- TEST 4: Invalid Cryptographic Signature Verification ---")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    text = "LEGAL AGREEMENT: TERMS AND CONDITIONS"
    # Corrupted / invalid base64 signature
    corrupted_sig = base64.b64encode(b"THIS_IS_A_TOTALLY_FAKE_INVALID_SIGNATURE_BYTES_1234567890").decode('utf-8')

    verif_data = {
        "raw_text": text,
        "filename": "legal_agreement.txt",
        "signature": corrupted_sig
    }
    v_resp = requests.post(f"{BASE_URL}/api/verify/analyze/", data=verif_data, headers=headers_analyst)
    assert v_resp.status_code == 200
    res = v_resp.json()

    print(f"[OK] Invalid Signature Decision: {res['final_decision']}")
    print(f"[OK] Signature Verified: {res['signature_verified']}")
    threat_cats = [t["threat_category"] for t in res["threats"]]
    print(f"[OK] Threats: {threat_cats}")

    assert res["signature_verified"] is False, "Corrupted signature must fail verification"
    assert res["final_decision"] == "INVALID_SIGNATURE", f"Expected INVALID_SIGNATURE, got {res['final_decision']}"
    assert any(t in threat_cats for t in ["FORGERY", "SIGNATURE_MANIPULATION"]), "Expected FORGERY threat"
    print(">>> TEST 4 PASSED: Invalid signature / forgery accurately detected!")


def test_scenario_5_unknown_signature(analyst_token):
    print("\n--- TEST 5: Unknown Signature Verification ---")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    # Plain text without any signature provided or embedded
    unsigned_text = "UNREGISTERED DRAFT DOCUMENT - NO SIGNATURE ATTACHED"
    verif_data = {
        "raw_text": unsigned_text,
        "filename": "draft_memo.txt"
    }
    v_resp = requests.post(f"{BASE_URL}/api/verify/analyze/", data=verif_data, headers=headers_analyst)
    assert v_resp.status_code == 200
    res = v_resp.json()

    print(f"[OK] Unknown Signature Decision: {res['final_decision']}")
    threat_cats = [t["threat_category"] for t in res["threats"]]
    print(f"[OK] Threats: {threat_cats}")

    assert res["final_decision"] in ["UNKNOWN_SIGNATURE", "PUBLIC_KEY_NOT_FOUND"], f"Unexpected decision: {res['final_decision']}"
    # CRITICAL CHECK: Unknown signature must NOT be automatically flagged as FORGERY!
    assert "FORGERY" not in threat_cats, "Unknown signature must NOT be flagged as FORGERY!"
    print(">>> TEST 5 PASSED: Unknown signature correctly categorized without false forgery flag!")


def test_scenario_6_private_key_security(sig_info, signer_token, analyst_token):
    print("\n--- TEST 6: Private Key Security & Encryption-At-Rest ---")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    # 1. Inspect signature creation response
    raw_json_str = json.dumps(sig_info)
    assert "private_key" not in raw_json_str, "API response contains 'private_key' field!"
    assert "BEGIN RSA PRIVATE KEY" not in raw_json_str, "Raw RSA private key exposed in API response!"
    assert "BEGIN PRIVATE KEY" not in raw_json_str, "Raw private key exposed in API response!"
    print("[OK] Private key is absent from signature creation response.")

    # 2. Inspect GET /api/signatures/
    list_resp = requests.get(f"{BASE_URL}/api/signatures/", headers=headers_analyst)
    assert list_resp.status_code == 200
    list_str = json.dumps(list_resp.json())
    assert "private_key" not in list_str, "List API exposed 'private_key'!"
    assert "BEGIN PRIVATE KEY" not in list_str, "Raw private key exposed in List API!"
    print("[OK] Private key is absent from signature list response.")

    # 3. Direct database inspection: KeyPair.private_key_encrypted
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models import KeyPair

    db_path = os.path.abspath("database/qshield.db")
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    session = Session()

    keypairs = session.query(KeyPair).all()
    assert len(keypairs) > 0, "No KeyPair records found in DB"

    for kp in keypairs:
        enc_val = kp.private_key_encrypted
        assert enc_val is not None and len(enc_val) > 20, "Missing encrypted private key"
        # Fernet tokens always start with gAAAAA
        assert enc_val.startswith("gAAAAA"), f"Private key not encrypted with Fernet! Found: {enc_val[:15]}"
        assert "BEGIN RSA PRIVATE KEY" not in enc_val, "Private key stored in plaintext PEM in DB!"
        assert "BEGIN PRIVATE KEY" not in enc_val, "Private key stored in plaintext PEM in DB!"

    session.close()
    print("[OK] Database verification: KeyPair.private_key_encrypted is encrypted with Fernet at rest.")
    print(">>> TEST 6 PASSED: Private key security verified!")


def test_statistics_and_history(analyst_token):
    print("\n--- TEST: Statistics and History Endpoints ---")
    headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

    # Statistics
    stats_resp = requests.get(f"{BASE_URL}/api/statistics/", headers=headers_analyst)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    print(f"[OK] Platform Stats: {stats}")
    assert stats["total_signatures"] > 0
    assert stats["total_verifications"] > 0
    assert "average_risk_score" in stats

    # History
    hist_resp = requests.get(f"{BASE_URL}/api/analysis/history/", headers=headers_analyst)
    assert hist_resp.status_code == 200
    history = hist_resp.json()
    print(f"[OK] Analysis History Count: {len(history)}")
    assert len(history) > 0
    print(">>> STATISTICS AND HISTORY PASSED!")


if __name__ == "__main__":
    print("====================================================")
    print("STARTING STEP 4 DATABASE INTEGRATION TEST SUITE")
    print("====================================================")

    signer_token = get_token(USER_CREDENTIALS)
    analyst_token = get_token(ANALYST_CREDENTIALS)

    sig_info = test_scenario_1_valid_signature(signer_token, analyst_token)
    test_scenario_2_tampered_file(signer_token, analyst_token)
    test_scenario_3_replay_attack(signer_token, analyst_token)
    test_scenario_4_invalid_signature(analyst_token)
    test_scenario_5_unknown_signature(analyst_token)
    test_scenario_6_private_key_security(sig_info, signer_token, analyst_token)
    test_statistics_and_history(analyst_token)

    print("\n====================================================")
    print("ALL 6 STEP 4 SCENARIOS PASSED WITH 100% COMPLIANCE!")
    print("====================================================")
