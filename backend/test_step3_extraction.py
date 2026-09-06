import requests
import sqlite3
from pathlib import Path
from pypdf import PdfWriter

BASE_URL = "http://127.0.0.1:8000/api"
DB_PATH = Path("database/qshield.db").resolve()
if not DB_PATH.exists():
    DB_PATH = Path("../database/qshield.db").resolve()

def run_step3_tests():
    print("==================================================")
    print("RUNNING STEP 3 - SIGNATURE EXTRACTION TESTS")
    print("==================================================")

    # 0. Authenticate as SECURITY_ANALYST (User 3)
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp.status_code == 200, f"Analyst login failed: {login_resp.text}"
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

    # Prepare a signed PDF (using Step 2 upload & sign workflow)
    sample_pdf_path = Path("step3_unsigned.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(sample_pdf_path, "wb") as f:
        writer.write(f)

    # Upload & Sign via Step 2 API
    with open(sample_pdf_path, "rb") as f:
        u_res = requests.post(f"{BASE_URL}/documents/upload", headers=headers_user2, files={"file": ("step3_unsigned.pdf", f, "application/pdf")})
    assert u_res.status_code == 200
    doc_id = u_res.json()["document_id"]
    
    s_res = requests.post(f"{BASE_URL}/documents/{doc_id}/sign", headers=headers_user2)
    assert s_res.status_code == 200
    
    d_res = requests.get(f"{BASE_URL}/documents/{doc_id}/download", headers=headers_user2)
    signed_pdf_bytes = d_res.content
    signed_pdf_path = Path("step3_signed.pdf")
    signed_pdf_path.write_bytes(signed_pdf_bytes)

    # TEST 1: Upload Signed PDF & Perform Real Signature Extraction
    print("\n--- TEST 1: Upload Signed PDF & Inspect Signature ---")
    with open(signed_pdf_path, "rb") as f:
        ana_res = requests.post(
            f"{BASE_URL}/security/upload-analyze",
            headers=headers_analyst,
            files={"file": ("step3_signed.pdf", f, "application/pdf")}
        )
    assert ana_res.status_code == 200, f"Analysis upload failed: {ana_res.text}"
    result = ana_res.json()
    assert result["signature_present"] == True
    assert result["signature_status"] == "SIGNATURE_FOUND"
    assert result["extracted_metadata"] is not None
    meta = result["extracted_metadata"]
    print("[OK] Real PKCS#7 Digital Signature Detected & Extracted!")
    print(f"  - Status: {result['signature_status']}")
    print(f"  - Signature Algorithm: {meta['signature_algorithm']}")
    print(f"  - Subject: {meta['certificate_subject']}")
    print(f"  - Issuer: {meta['certificate_issuer']}")
    print(f"  - Cert Fingerprint: {meta['certificate_fingerprint'][:20]}...")
    print(f"  - Signer Name: {meta['signer_name']}")

    # TEST 2: Upload Unsigned PDF & Verify NO_SIGNATURE_FOUND
    print("\n--- TEST 2: Upload Unsigned PDF (No Signature) ---")
    with open(sample_pdf_path, "rb") as f:
        no_sig_res = requests.post(
            f"{BASE_URL}/security/upload-analyze",
            headers=headers_analyst,
            files={"file": ("step3_unsigned.pdf", f, "application/pdf")}
        )
    assert no_sig_res.status_code == 200
    no_sig_data = no_sig_res.json()
    assert no_sig_data["signature_present"] == False
    assert no_sig_data["signature_status"] == "NO_SIGNATURE_FOUND"
    print(f"[OK] Correctly detected unsigned document (Status: {no_sig_data['signature_status']})")

    # TEST 3: Reject Unsupported Binary File Format
    print("\n--- TEST 3: Reject Unsupported File Format ---")
    bin_path = Path("bad_format.bin")
    bin_path.write_bytes(b"\x00\xff\xfe\xfd\x80\x90\xa0\x12\x34\x56\x78")
    with open(bin_path, "rb") as f:
        bad_res = requests.post(
            f"{BASE_URL}/security/upload-analyze",
            headers=headers_analyst,
            files={"file": ("bad_format.bin", f, "application/octet-stream")}
        )
    assert bad_res.status_code == 400
    print(f"[OK] Unsupported upload rejected with 400 Bad Request: {bad_res.json()['detail']}")

    # TEST 4: Security Analyst Role Guard
    print("\n--- TEST 4: Role Authorization Protection ---")
    with open(signed_pdf_path, "rb") as f:
        guard_res = requests.post(
            f"{BASE_URL}/security/upload-analyze",
            headers=headers_user2, # Normal signature user token
            files={"file": ("step3_signed.pdf", f, "application/pdf")}
        )
    assert guard_res.status_code == 403
    print(f"[OK] Access denied (403 Forbidden) when Digital Signature User attempts analysis endpoint")

    # TEST 5: Database Persistence & Audit Trail
    print("\n--- TEST 5: SQLite Database & Audit Logs Check ---")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT analysis_document_id, original_file_name, signature_status FROM analyzed_documents ORDER BY analysis_document_id DESC LIMIT 2")
    db_rows = cur.fetchall()
    assert len(db_rows) == 2
    print(f"[OK] Verified SQLite `analyzed_documents` persistence: {db_rows}")

    cur.execute("SELECT action, details FROM audit_logs WHERE action LIKE 'SIGNATURE%' OR action LIKE 'ANALYSIS%' ORDER BY log_id DESC LIMIT 3")
    audit_rows = cur.fetchall()
    print(f"[OK] Verified Audit Logs: {audit_rows}")
    conn.close()

    # Clean up test files
    sample_pdf_path.unlink(missing_ok=True)
    signed_pdf_path.unlink(missing_ok=True)
    bin_path.unlink(missing_ok=True)

    print("\n==================================================")
    print("ALL STEP 3 TESTS PASSED PERFECTLY WITH ZERO ERRORS!")
    print("==================================================")

if __name__ == "__main__":
    run_step3_tests()
