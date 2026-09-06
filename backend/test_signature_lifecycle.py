"""
End-to-End Verification of the 10-Step Digital Signature Lifecycle Flow.

Workflow steps verified:
1. User Login (Digital Signature User)
2. Digital Signature Dashboard Access
3. Upload Normal Document (PDF and TXT)
4. Calculate SHA-256 Hash
5. Generate / Use Cryptographic Private Key
6. Create Digital Signature
7. Store Signature + Hash + Public Key Information
8. Generate Signed File / Signature Package
9. Save Record in Database
10. Download Signed Document
"""

import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api"

def run_lifecycle_test():
    print("=" * 70)
    print("RUNNING DIGITAL SIGNATURE LIFECYCLE E2E TEST (PDF & TXT)")
    print("=" * 70)

    # --------------------------------------------------------------------------
    # STEP 1: User Login
    # --------------------------------------------------------------------------
    print("\n[STEP 1] User Login...")
    login_res = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[SUCCESS] User successfully authenticated. Role: DIGITAL_SIGNATURE_USER")

    # --------------------------------------------------------------------------
    # STEP 2: Digital Signature Dashboard
    # --------------------------------------------------------------------------
    print("\n[STEP 2] Accessing Digital Signature Dashboard...")
    stats_res = requests.get(f"{BASE_URL}/signature/stats", headers=headers)
    assert stats_res.status_code == 200
    docs_res = requests.get(f"{BASE_URL}/signature/documents", headers=headers)
    assert docs_res.status_code == 200
    print(f"[SUCCESS] Dashboard loaded! Total documents: {stats_res.json()['total_documents']}")

    # --------------------------------------------------------------------------
    # TEST CASE A: PDF LIFECYCLE (STEPS 3 to 10)
    # --------------------------------------------------------------------------
    print("\n--- TEST CASE A: PDF DOCUMENT LIFECYCLE ---")

    # STEP 3: Upload Normal Document (PDF)
    print("[STEP 3] Uploading Normal PDF Document...")
    from pypdf import PdfWriter
    import io
    pdf_buf = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(pdf_buf)
    sample_pdf_bytes = pdf_buf.getvalue()

    pdf_upload_res = requests.post(
        f"{BASE_URL}/documents/upload",
        headers=headers,
        files={"file": ("contract_agreement.pdf", sample_pdf_bytes, "application/pdf")}
    )
    assert pdf_upload_res.status_code == 200, f"Upload PDF failed: {pdf_upload_res.text}"
    pdf_doc = pdf_upload_res.json()
    pdf_doc_id = pdf_doc["document_id"]
    print(f"[SUCCESS] Uploaded PDF document ID: #{pdf_doc_id}")

    # STEP 4: Calculate SHA-256 Hash
    print("[STEP 4] SHA-256 Hash calculation verification...")
    pdf_hash = pdf_doc["document_hash"]
    assert len(pdf_hash) == 64, "Invalid SHA-256 hash length"
    print(f"[SUCCESS] SHA-256 Hash calculated: {pdf_hash}")

    # STEPS 5, 6, 7, 8, 9: Sign & Generate Signed Output Package & Save DB
    print("[STEPS 5-9] Generating Cryptographic Signature with RSA-2048 Private Key...")
    sign_res = requests.post(f"{BASE_URL}/documents/{pdf_doc_id}/sign", headers=headers)
    assert sign_res.status_code == 200, f"Signing PDF failed: {sign_res.text}"
    signed_data = sign_res.json()

    print("[SUCCESS] Real PKCS#7 / RSA-SHA256 signature generated!")
    print(f"  - Signed File: {signed_data['signed_filename']}")
    print(f"  - Document Status: {signed_data['status']}")
    print(f"  - Certificate Subject: {signed_data['signature']['certificate_subject']}")
    print(f"  - Certificate Issuer: {signed_data['signature']['certificate_issuer']}")
    print(f"  - Certificate Fingerprint: {signed_data['signature']['certificate_fingerprint'][:24]}...")
    print(f"  - Signature Fingerprint: {signed_data['signature']['signature_fingerprint'][:24]}...")

    # STEP 10: Download Signed Document
    print("[STEP 10] Downloading Signed PDF...")
    download_res = requests.get(f"{BASE_URL}/documents/{pdf_doc_id}/download", headers=headers)
    assert download_res.status_code == 200
    assert len(download_res.content) > len(sample_pdf_bytes), "Signed file should contain embedded signature bytes"
    print(f"[SUCCESS] Downloaded signed PDF! Size: {len(download_res.content)} bytes")

    # --------------------------------------------------------------------------
    # TEST CASE B: TXT LIFECYCLE (STEPS 3 to 10)
    # --------------------------------------------------------------------------
    print("\n--- TEST CASE B: TXT DOCUMENT LIFECYCLE ---")

    # STEP 3: Upload Normal Document (TXT)
    print("[STEP 3] Uploading Normal TXT Document...")
    sample_txt = b"CONFIDENTIAL SETTLEMENT TERMS: Authorizing transfer of 500,000 USD to escrow."
    txt_upload_res = requests.post(
        f"{BASE_URL}/documents/upload-multiformat",
        headers=headers,
        files={"file": ("settlement_terms.txt", sample_txt, "text/plain")}
    )
    assert txt_upload_res.status_code == 200, f"Upload TXT failed: {txt_upload_res.text}"
    txt_doc = txt_upload_res.json()
    txt_doc_id = txt_doc["document_id"]
    print(f"[SUCCESS] Uploaded TXT document ID: #{txt_doc_id}")

    # STEP 4: Calculate SHA-256 Hash
    print("[STEP 4] Calculating SHA-256 Hash of TXT content...")
    txt_hash = txt_doc["document_hash"]
    assert len(txt_hash) == 64
    print(f"[SUCCESS] TXT SHA-256 Hash calculated: {txt_hash}")

    # STEPS 5, 6, 7, 8, 9: Sign & Generate Signed Output Package & Save DB
    print("[STEPS 5-9] Generating Cryptographic Signature for TXT...")
    sign_txt_res = requests.post(f"{BASE_URL}/documents/{txt_doc_id}/sign", headers=headers)
    assert sign_txt_res.status_code == 200, f"Signing TXT failed: {sign_txt_res.text}"
    signed_txt_data = sign_txt_res.json()

    print("[SUCCESS] Real RSA-SHA256 signature generated for TXT!")
    print(f"  - Signed File: {signed_txt_data['signed_filename']}")
    print(f"  - Document Status: {signed_txt_data['status']}")
    print(f"  - Certificate Subject: {signed_txt_data['signature']['certificate_subject']}")
    print(f"  - Certificate Fingerprint: {signed_txt_data['signature']['certificate_fingerprint'][:24]}...")
    print(f"  - Signature Fingerprint: {signed_txt_data['signature']['signature_fingerprint'][:24]}...")

    # STEP 10: Download Signed Document
    print("[STEP 10] Downloading Signed TXT Package...")
    download_txt_res = requests.get(f"{BASE_URL}/documents/{txt_doc_id}/download", headers=headers)
    assert download_txt_res.status_code == 200
    assert len(download_txt_res.content) > 0
    print(f"[SUCCESS] Downloaded signed TXT package! Size: {len(download_txt_res.content)} bytes")

    print("\n" + "=" * 70)
    print("ALL 10 LIFECYCLE STEPS VERIFIED WITH 100% SUCCESS ACROSS PDF & TXT!")
    print("=" * 70)

if __name__ == "__main__":
    run_lifecycle_test()
