import requests
import sqlite3
from pathlib import Path
from pypdf import PdfWriter

BASE_URL = "http://127.0.0.1:8000/api"
DB_PATH = Path("database/qshield.db").resolve()
if not DB_PATH.exists():
    DB_PATH = Path("../database/qshield.db").resolve()

def run_step4_tests():
    print("==================================================")
    print("RUNNING STEP 4 - CRYPTOGRAPHIC VERIFICATION TESTS")
    print("==================================================")

    # 0. Authenticate as SECURITY_ANALYST (User 3)
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp.status_code == 200
    token_analyst = login_resp.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    print("[AUTH] Logged in as analyst@qshield.com (Security Analyst)")

    # Authenticate as DIGITAL_SIGNATURE_USER (User 2) for role check
    login_resp2 = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_resp2.status_code == 200
    token_user2 = login_resp2.json()["access_token"]
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    # Generate a fresh valid signed PDF via Step 2 API
    sample_pdf_path = Path("step4_blank.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(sample_pdf_path, "wb") as f:
        writer.write(f)

    with open(sample_pdf_path, "rb") as f:
        u_res = requests.post(f"{BASE_URL}/documents/upload", headers=headers_user2, files={"file": ("step4_blank.pdf", f, "application/pdf")})
    assert u_res.status_code == 200
    doc_id = u_res.json()["document_id"]
    
    s_res = requests.post(f"{BASE_URL}/documents/{doc_id}/sign", headers=headers_user2)
    assert s_res.status_code == 200
    
    d_res = requests.get(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_user2)
    signed_pdf_bytes = d_res.content
    valid_signed_pdf_path = Path("step4_valid_signed.pdf")
    valid_signed_pdf_path.write_bytes(signed_pdf_bytes)

    # TEST 1: Q-SHIELD Generated Signed PDF Verification
    print("\n--- TEST 1: Q-SHIELD Signed PDF Cryptographic Verification ---")
    with open(valid_signed_pdf_path, "rb") as f:
        ana_res = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step4_valid_signed.pdf", f, "application/pdf")})
    assert ana_res.status_code == 200
    ana_id1 = ana_res.json()["analysis_document_id"]

    verif_res1 = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/verify", headers=headers_analyst)
    assert verif_res1.status_code == 200
    v_data1 = verif_res1.json()
    assert v_data1["verifications"] is not None and len(v_data1["verifications"]) > 0
    v1 = v_data1["verifications"][0]
    assert v1["verification_status"] == "VALID", f"Expected VALID but got {v1['verification_status']}"
    assert v1["integrity_status"] == "INTACT", f"Expected INTACT but got {v1['integrity_status']}"
    print(f"[OK] Signature Cryptographically VALID! Status: {v1['verification_status']}")
    print(f"[OK] Document Integrity INTACT! Details: {v1['verification_details']}")

    # TEST 2: Modified Signed PDF Integrity Failure Test
    print("\n--- TEST 2: Modified Signed PDF Integrity Failure Test ---")
    # Mutate a byte inside the signed stream (replace 'Catalog' with 'Xatalog')
    modified_pdf_bytes = signed_pdf_bytes.replace(b'/Catalog', b'/Xatalog')
    modified_pdf_path = Path("step4_modified_signed.pdf")
    modified_pdf_path.write_bytes(modified_pdf_bytes)

    with open(modified_pdf_path, "rb") as f:
        ana_res2 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step4_modified_signed.pdf", f, "application/pdf")})
    assert ana_res2.status_code == 200
    ana_id2 = ana_res2.json()["analysis_document_id"]

    verif_res2 = requests.post(f"{BASE_URL}/security/analysis/{ana_id2}/verify", headers=headers_analyst)
    assert verif_res2.status_code == 200
    v_data2 = verif_res2.json()
    v2 = v_data2["verifications"][0]
    assert v2["verification_status"] == "INVALID", f"Expected INVALID but got {v2['verification_status']}"
    assert v2["integrity_status"] == "MODIFIED", f"Expected MODIFIED but got {v2['integrity_status']}"
    print(f"[OK] Document Modification Detected! Verification Status: {v2['verification_status']}")
    print(f"[OK] Integrity Status: {v2['integrity_status']} - {v2['verification_details']}")

    # TEST 3: Unsigned PDF Verification Check
    print("\n--- TEST 3: Unsigned PDF Verification Check ---")
    with open(sample_pdf_path, "rb") as f:
        ana_res3 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step4_blank.pdf", f, "application/pdf")})
    ana_id3 = ana_res3.json()["analysis_document_id"]

    verif_res3 = requests.post(f"{BASE_URL}/security/analysis/{ana_id3}/verify", headers=headers_analyst)
    assert verif_res3.status_code == 200
    v3 = verif_res3.json()["verifications"][0]
    assert v3["verification_status"] == "UNKNOWN"
    assert v3["integrity_status"] == "NOT_VERIFIABLE"
    print(f"[OK] Unsigned document correctly reported (Status: {v3['verification_status']}, Integrity: {v3['integrity_status']})")

    # TEST 4: Invalid / Corrupted Signature Structure Test
    print("\n--- TEST 4: Corrupted Signature Structure Test ---")
    # Mutate PKCS#7 signature bytes inside /Contents < ... >
    corrupted_bytes = signed_pdf_bytes.replace(b'00000000', b'FFFFFFFF')
    corrupt_pdf_path = Path("step4_corrupt.pdf")
    corrupt_pdf_path.write_bytes(corrupted_bytes)

    with open(corrupt_pdf_path, "rb") as f:
        ana_res4 = requests.post(f"{BASE_URL}/security/upload-analyze", headers=headers_analyst, files={"file": ("step4_corrupt.pdf", f, "application/pdf")})
    ana_id4 = ana_res4.json()["analysis_document_id"]

    verif_res4 = requests.post(f"{BASE_URL}/security/analysis/{ana_id4}/verify", headers=headers_analyst)
    assert verif_res4.status_code == 200
    v4 = verif_res4.json()["verifications"][0]
    assert v4["verification_status"] in ["INVALID", "MALFORMED", "VERIFICATION_ERROR"]
    print(f"[OK] Corrupted signature correctly reported as {v4['verification_status']}")

    # TEST 5: Certificate Time Validity Check
    print("\n--- TEST 5: Certificate Time Status Evaluation ---")
    assert v1["certificate_time_status"] == "VALID_TIME_RANGE"
    print(f"[OK] Certificate Time Status evaluated: {v1['certificate_time_status']}")

    # TEST 6: Multi-Signature Architecture Verification
    print("\n--- TEST 6: Multi-Signature Support ---")
    get_v_res = requests.get(f"{BASE_URL}/security/analysis/{ana_id1}/verifications", headers=headers_analyst)
    assert get_v_res.status_code == 200
    assert len(get_v_res.json()) >= 1
    print(f"[OK] Retrievable verifications list API verified (#{len(get_v_res.json())} signatures stored)")

    # TEST 7: Unauthorized Access Protection
    print("\n--- TEST 7: Unauthorized Access Protection ---")
    unauth_res = requests.post(f"{BASE_URL}/security/analysis/{ana_id1}/verify", headers=headers_user2)
    assert unauth_res.status_code == 403
    print(f"[OK] Access denied (403 Forbidden) when Digital Signature User calls verification API")

    # Clean up temporary test files
    sample_pdf_path.unlink(missing_ok=True)
    valid_signed_pdf_path.unlink(missing_ok=True)
    modified_pdf_path.unlink(missing_ok=True)
    corrupt_pdf_path.unlink(missing_ok=True)

    print("\n==================================================")
    print("ALL 7 STEP 4 VERIFICATION TESTS PASSED PERFECTLY!")
    print("==================================================")

if __name__ == "__main__":
    run_step4_tests()
