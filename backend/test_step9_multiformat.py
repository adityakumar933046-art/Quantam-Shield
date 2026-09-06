import requests
import json
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api"

def run_step9_multiformat_tests():
    print("==================================================================")
    print("RUNNING STEP 9 - MULTI-FORMAT DIGITAL SIGNATURE & ANALYSIS TESTS")
    print("==================================================================")

    # 0. Authenticate Users
    login_user = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_user.status_code == 200, f"User login failed: {login_user.text}"
    token_user = login_user.json()["access_token"]
    headers_user = {"Authorization": f"Bearer {token_user}"}
    print("[AUTH] Logged in as user@qshield.com (Digital Signature User)")

    login_analyst = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_analyst.status_code == 200, f"Analyst login failed: {login_analyst.text}"
    token_analyst = login_analyst.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    print("[AUTH] Logged in as analyst@qshield.com (Security Analyst)")

    # ------------------------------------------------------------------
    # TEST 1: Sign TXT File
    # ------------------------------------------------------------------
    print("\n--- TEST 1: Sign TXT File ---")
    txt_content = "Hello World Q-SHIELD Security Platform"
    resp1 = requests.post(f"{BASE_URL}/documents/sign-text", headers=headers_user, json={
        "text_content": txt_content,
        "filename": "document.txt"
    })
    assert resp1.status_code == 200, f"Sign TXT failed: {resp1.text}"
    data1 = resp1.json()
    assert data1["content_type"] == "TEXT", f"Expected ContentType TEXT, got {data1['content_type']}"
    assert "signed_message_json" in data1, "Missing signed_message_json envelope"
    assert len(data1["signature_value"]) > 20, "Missing signature value"
    print(f"[SUCCESS] TXT File signed successfully! Hash: {data1['content_hash'][:16]}...")

    # ------------------------------------------------------------------
    # TEST 2: Modify One Character in TXT (Verification Mismatch)
    # ------------------------------------------------------------------
    print("\n--- TEST 2: Single Character Modification Tamper Check ---")
    tampered_txt = "Hello world Q-SHIELD Security Platform" # Lowercase 'w'
    signed_env1 = json.loads(data1["signed_message_json"])
    signed_env1["content"] = tampered_txt
    
    resp2 = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "SIGNED_MESSAGE",
        "content_text": json.dumps(signed_env1),
        "filename": "document.txt"
    })
    assert resp2.status_code == 200, f"Analyze tampered TXT failed: {resp2.text}"
    data2 = resp2.json()
    verif2 = data2["verifications"][0]
    assert verif2["verification_status"] == "INVALID", f"Expected INVALID, got {verif2['verification_status']}"
    assert verif2["integrity_status"] == "MODIFIED", f"Expected MODIFIED, got {verif2['integrity_status']}"
    print("[SUCCESS] Single character modification detected! Verification status: INVALID, Integrity: MODIFIED")

    # ------------------------------------------------------------------
    # TEST 3: Sign Raw Text & Verify Exact Match
    # ------------------------------------------------------------------
    print("\n--- TEST 3: Raw Text Sign & Verify ---")
    raw_text_payload = "Q-SHIELD Cryptographic Verification String #2026"
    resp3 = requests.post(f"{BASE_URL}/documents/sign-text", headers=headers_user, json={
        "text_content": raw_text_payload,
        "filename": "raw_input.txt"
    })
    assert resp3.status_code == 200, f"Sign raw text failed: {resp3.text}"
    data3 = resp3.json()
    
    resp3_verify = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "SIGNED_MESSAGE",
        "content_text": data3["signed_message_json"],
        "filename": "raw_input.txt"
    })
    assert resp3_verify.status_code == 200, f"Verify raw text failed: {resp3_verify.text}"
    verif3 = resp3_verify.json()["verifications"][0]
    assert verif3["verification_status"] == "VALID", f"Expected VALID, got {verif3['verification_status']}"
    assert verif3["integrity_status"] == "INTACT", f"Expected INTACT, got {verif3['integrity_status']}"
    print("[SUCCESS] Raw text signature verified successfully! Status: VALID, Integrity: INTACT")

    # ------------------------------------------------------------------
    # TEST 4: Whitespace Change in Exact-Byte Mode
    # ------------------------------------------------------------------
    print("\n--- TEST 4: Whitespace Alteration Exact-Byte Mode Check ---")
    whitespace_txt = raw_text_payload + " " # Trailing space added
    signed_env3 = json.loads(data3["signed_message_json"])
    signed_env3["content"] = whitespace_txt
    
    resp4 = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "SIGNED_MESSAGE",
        "content_text": json.dumps(signed_env3),
        "filename": "raw_input.txt"
    })
    assert resp4.status_code == 200, f"Analyze whitespace failed: {resp4.text}"
    verif4 = resp4.json()["verifications"][0]
    assert verif4["verification_status"] == "INVALID", f"Expected INVALID, got {verif4['verification_status']}"
    assert verif4["integrity_status"] == "MODIFIED", f"Expected MODIFIED, got {verif4['integrity_status']}"
    print("[SUCCESS] Whitespace alteration caught in exact-byte mode! Status: INVALID")

    # ------------------------------------------------------------------
    # TEST 5: Canonical JSON Formatting Change (Verification Remains Valid)
    # ------------------------------------------------------------------
    print("\n--- TEST 5: Canonical JSON Formatting Independence ---")
    json_data = {"user": "Alice", "balance": 1000, "role": "OPERATOR"}
    resp5 = requests.post(f"{BASE_URL}/documents/sign-json", headers=headers_user, json={
        "json_content": json_data,
        "filename": "account.json",
        "canonicalize": True
    })
    assert resp5.status_code == 200, f"Sign JSON failed: {resp5.text}"
    data5 = resp5.json()

    # Alter whitespace and key order in JSON string
    reformatted_json_str = '{\n  "role": "OPERATOR",\n  "user": "Alice",\n  "balance": 1000\n}'
    signed_env5 = json.loads(data5["signed_message_json"])
    signed_env5["content"] = reformatted_json_str

    resp5_verify = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "SIGNED_MESSAGE",
        "content_text": json.dumps(signed_env5),
        "filename": "account.json"
    })
    assert resp5_verify.status_code == 200, f"Verify reformatted JSON failed: {resp5_verify.text}"
    verif5 = resp5_verify.json()["verifications"][0]
    assert verif5["verification_status"] == "VALID", f"Expected VALID, got {verif5['verification_status']}"
    assert verif5["integrity_status"] == "INTACT", f"Expected INTACT, got {verif5['integrity_status']}"
    print("[SUCCESS] Canonical JSON re-formatting (whitespace/key order) preserved signature validity! Status: VALID")

    # ------------------------------------------------------------------
    # TEST 6: JSON Value Modification (Verification Fails)
    # ------------------------------------------------------------------
    print("\n--- TEST 6: JSON Value Modification Tamper Check ---")
    tampered_json_data = {"user": "Alice", "balance": 999999, "role": "OPERATOR"} # Altered balance value
    signed_env5_tampered = json.loads(data5["signed_message_json"])
    signed_env5_tampered["content"] = json.dumps(tampered_json_data)

    resp6 = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "SIGNED_MESSAGE",
        "content_text": json.dumps(signed_env5_tampered),
        "filename": "account.json"
    })
    assert resp6.status_code == 200, f"Analyze tampered JSON failed: {resp6.text}"
    verif6 = resp6.json()["verifications"][0]
    assert verif6["verification_status"] == "INVALID", f"Expected INVALID, got {verif6['verification_status']}"
    assert verif6["integrity_status"] == "MODIFIED", f"Expected MODIFIED, got {verif6['integrity_status']}"
    print("[SUCCESS] JSON value modification caught! Verification status: INVALID")

    # ------------------------------------------------------------------
    # TEST 7: Detached Signature with Incorrect Text
    # ------------------------------------------------------------------
    print("\n--- TEST 7: Detached Signature Mismatch Check ---")
    original_text = "Authentic Contract Body Text 2026"
    incorrect_text = "Altered Contract Body Text 2026"

    # Generate signature for original text
    resp7_sign = requests.post(f"{BASE_URL}/documents/sign-text", headers=headers_user, json={
        "text_content": original_text,
        "filename": "contract.txt"
    })
    assert resp7_sign.status_code == 200, f"Sign contract failed: {resp7_sign.text}"
    sig7 = resp7_sign.json()["signature_value"]

    # Verify detached signature against incorrect text
    resp7_verify = requests.post(f"{BASE_URL}/security/analyze-multiformat", headers=headers_analyst, json={
        "input_type": "DETACHED_SIGNATURE",
        "content_text": incorrect_text,
        "signature_text": sig7,
        "filename": "contract.txt"
    })
    assert resp7_verify.status_code == 200, f"Verify detached signature failed: {resp7_verify.text}"
    verif7 = resp7_verify.json()["verifications"][0]
    assert verif7["verification_status"] == "INVALID", f"Expected INVALID, got {verif7['verification_status']}"
    assert verif7["integrity_status"] == "MODIFIED", f"Expected MODIFIED, got {verif7['integrity_status']}"
    print("[SUCCESS] Detached signature mismatch caught! Verification status: INVALID")

    print("\n==================================================================")
    print("ALL STEP 9 MULTI-FORMAT SIGNATURE TESTS PASSED PERFECTLY!")
    print("==================================================================")

if __name__ == "__main__":
    run_step9_multiformat_tests()
