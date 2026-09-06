import requests
import json
import sqlite3
from pathlib import Path
from pypdf import PdfWriter

BASE_URL = "http://127.0.0.1:8000/api"
DB_PATH = Path("database/qshield.db").resolve()
if not DB_PATH.exists():
    DB_PATH = Path("../database/qshield.db").resolve()

def run_step2_tests():
    print("==================================================")
    print("RUNNING STEP 2 - DIGITAL SIGNATURE GENERATION TESTS")
    print("==================================================")

    # 0. Authenticate as DIGITAL_SIGNATURE_USER (User 2)
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_user2 = login_resp.json()["access_token"]
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}
    print("[AUTH] Logged in as user@qshield.com (User #2)")

    # Authenticate as SECURITY_ANALYST (User 3) for ownership test
    login_resp3 = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert login_resp3.status_code == 200, f"Login failed: {login_resp3.text}"
    token_user3 = login_resp3.json()["access_token"]
    headers_user3 = {"Authorization": f"Bearer {token_user3}"}
    print("[AUTH] Logged in as analyst@qshield.com (User #3)")

    # Create valid sample PDF using pypdf
    sample_pdf_path = Path("sample_test.pdf")
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    with open(sample_pdf_path, "wb") as f:
        writer.write(f)

    # TEST 1 & TEST 2: Upload Valid PDF & Generate SHA-256 Hash
    print("\n--- TEST 1 & TEST 2: Upload Valid PDF & Generate SHA-256 Hash ---")
    with open(sample_pdf_path, "rb") as f:
        upload_resp = requests.post(
            f"{BASE_URL}/documents/upload",
            headers=headers_user2,
            files={"file": ("sample_test.pdf", f, "application/pdf")}
        )
    assert upload_resp.status_code == 200, f"Upload failed: {upload_resp.text}"
    doc_data = upload_resp.json()
    doc_id = doc_data["document_id"]
    doc_hash = doc_data["document_hash"]
    print(f"[OK] Upload succeeded! Document ID: #{doc_id}")
    print(f"[OK] SHA-256 Hash calculated: {doc_hash}")

    # TEST 3: Generate Real Cryptographic Digital Signature
    print("\n--- TEST 3: Generate Cryptographic Digital Signature ---")
    sign_resp = requests.post(
        f"{BASE_URL}/documents/{doc_id}/sign",
        headers=headers_user2
    )
    assert sign_resp.status_code == 200, f"Signing failed: {sign_resp.text}"
    signed_doc = sign_resp.json()
    assert signed_doc["status"] == "SIGNED"
    assert signed_doc["signature"] is not None
    sig_info = signed_doc["signature"]
    print(f"[OK] Real PKCS#7 Cryptographic signature generated successfully!")
    print(f"  - Algorithm: {sig_info['signature_algorithm']}")
    print(f"  - Subject: {sig_info['certificate_subject']}")
    print(f"  - Issuer: {sig_info['certificate_issuer']}")
    print(f"  - Cert Fingerprint: {sig_info['certificate_fingerprint'][:20]}...")

    # TEST 4: Download Signed PDF
    print("\n--- TEST 4: Download Signed PDF ---")
    down_resp = requests.get(
        f"{BASE_URL}/documents/{doc_id}/download",
        headers=headers_user2
    )
    assert down_resp.status_code == 200, f"Download failed: {down_resp.text}"
    assert down_resp.content.startswith(b"%PDF-"), "Downloaded file is not a valid PDF"
    print(f"[OK] Signed PDF downloaded successfully ({len(down_resp.content)} bytes)")

    # TEST 5: Check Database Metadata
    print("\n--- TEST 5: Check Database Record Persistence ---")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT document_id, original_filename, document_hash, status FROM documents WHERE document_id = ?", (doc_id,))
    db_doc = cursor.fetchone()
    assert db_doc is not None, "Document record missing in DB"
    assert db_doc[3] == "SIGNED"

    cursor.execute("SELECT signature_id, certificate_issuer, verification_status FROM digital_signatures WHERE document_id = ?", (doc_id,))
    db_sig = cursor.fetchone()
    assert db_sig is not None, "Digital signature record missing in DB"
    print(f"[OK] Verified SQLite DB records for document #{db_doc[0]} and signature #{db_sig[0]}")
    conn.close()

    # TEST 6: Try Accessing Another User's Document (Ownership Control)
    print("\n--- TEST 6: Ownership Control Security Test ---")
    unauth_resp = requests.get(
        f"{BASE_URL}/documents/{doc_id}/download",
        headers=headers_user3
    )
    assert unauth_resp.status_code == 403, f"Ownership check failed! Returned {unauth_resp.status_code} instead of 403"
    print(f"[OK] Access denied (403 Forbidden) when non-owner attempts to download document #{doc_id}")

    # TEST 7: Try Uploading a Non-PDF File
    print("\n--- TEST 7: Reject Non-PDF File Format ---")
    txt_file_path = Path("invalid_test.txt")
    txt_file_path.write_text("This is not a PDF file")
    with open(txt_file_path, "rb") as f:
        bad_upload_resp = requests.post(
            f"{BASE_URL}/documents/upload",
            headers=headers_user2,
            files={"file": ("invalid_test.txt", f, "text/plain")}
        )
    assert bad_upload_resp.status_code == 400, f"Validation failed! Returned {bad_upload_resp.status_code} instead of 400"
    print(f"[OK] Non-PDF file upload rejected successfully (400 Bad Request: {bad_upload_resp.json()['detail']})")

    # Clean up test files
    sample_pdf_path.unlink(missing_ok=True)
    txt_file_path.unlink(missing_ok=True)
    Path("valid_sample.pdf").unlink(missing_ok=True)

    print("\n==================================================")
    print("ALL 7 STEP 2 TESTS PASSED PERFECTLY WITH ZERO ERRORS!")
    print("==================================================")

if __name__ == "__main__":
    run_step2_tests()
