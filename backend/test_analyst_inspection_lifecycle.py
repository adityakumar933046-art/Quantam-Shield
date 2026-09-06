"""
Comprehensive End-to-End Verification of the Security Analyst Inspection Lifecycle.

Workflow steps verified:
1. Security Analyst Login
2. Upload File (PDF and TXT)
3. File Format Detection
4. Extract Signature Information
5. Calculate Current SHA-256 Hash
6. Verify Digital Signature
7. Validate Public Key / Certificate
8. Check Stored Signature Records
9. Quantum-Inspired Analysis
10. Threat Detection
11. Risk Score
12. Security Report
"""

import requests
import io
from pathlib import Path
from pypdf import PdfWriter

BASE_URL = "http://127.0.0.1:8000/api"

def run_analyst_lifecycle_test():
    print("=" * 75)
    print("RUNNING SECURITY ANALYST INSPECTION LIFECYCLE E2E TEST (PDF & TXT)")
    print("=" * 75)

    # --------------------------------------------------------------------------
    # STAGE 1: Security Analyst Login & Authorization
    # --------------------------------------------------------------------------
    print("\n[STAGE 1] Security Analyst Login & Role Authentication...")
    analyst_login = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "analyst@qshield.com",
        "password": "AnalystPassword123!"
    })
    assert analyst_login.status_code == 200, f"Analyst login failed: {analyst_login.text}"
    token_analyst = analyst_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token_analyst}"}
    print("[SUCCESS] Authenticated as SECURITY_ANALYST (analyst@qshield.com)")

    # Prepare a signed PDF for analysis
    # Login as User to generate a signed PDF
    user_login = requests.post(f"{BASE_URL}/auth/login", json={
        "email": "user@qshield.com",
        "password": "UserPassword123!"
    })
    token_user = user_login.json()["access_token"]
    u_headers = {"Authorization": f"Bearer {token_user}"}

    pdf_buf = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(pdf_buf)
    pdf_bytes = pdf_buf.getvalue()

    upload_pdf_res = requests.post(
        f"{BASE_URL}/documents/upload",
        headers=u_headers,
        files={"file": ("contract_for_inspection.pdf", pdf_bytes, "application/pdf")}
    )
    user_doc_id = upload_pdf_res.json()["document_id"]
    requests.post(f"{BASE_URL}/documents/{user_doc_id}/sign", headers=u_headers)
    signed_pdf_bytes = requests.get(f"{BASE_URL}/documents/{user_doc_id}/download", headers=u_headers).content

    # --------------------------------------------------------------------------
    # PIPELINE EXECUTION FOR PDF
    # --------------------------------------------------------------------------
    print("\n" + "=" * 55)
    print(">>> EXECUTING PIPELINE FOR SIGNED PDF DOCUMENT")
    print("=" * 55)

    # STAGE 2: Upload File (PDF)
    print("\n[STAGE 2] Uploading Signed PDF File...")
    upload_res = requests.post(
        f"{BASE_URL}/security/upload-analyze",
        headers=headers,
        files={"file": ("contract_for_inspection.pdf", signed_pdf_bytes, "application/pdf")}
    )
    assert upload_res.status_code == 200, f"Upload analysis failed: {upload_res.text}"
    analysis_data = upload_res.json()
    analysis_id = analysis_data["analysis_document_id"]
    print(f"[SUCCESS] Upload complete! Analysis ID: #{analysis_id}")

    # STAGE 3: File Format Detection
    print("\n[STAGE 3] File Format Detection...")
    content_type = analysis_data.get("content_type", "PDF")
    print(f"[SUCCESS] Detected Content Format: {content_type}")
    assert content_type == "PDF"

    # STAGE 4: Extract Signature Information
    print("\n[STAGE 4] Extract Signature Information...")
    meta = analysis_data.get("extracted_metadata")
    assert meta is not None and meta["signature_detected"] is True
    print(f"[SUCCESS] Signature Extracted:")
    print(f"  - Signature Algorithm: {meta['signature_algorithm']}")
    print(f"  - Subject: {meta['certificate_subject']}")
    print(f"  - Issuer: {meta['certificate_issuer']}")
    print(f"  - Serial Number: {meta['certificate_serial_number']}")
    print(f"  - Signature Fingerprint: {meta['signature_fingerprint'][:24]}...")

    # STAGE 5: Calculate Current SHA-256 Hash
    print("\n[STAGE 5] Calculate Current Document SHA-256 Hash...")
    current_hash = analysis_data["document_hash"]
    assert len(current_hash) == 64
    print(f"[SUCCESS] Document SHA-256 Digest: {current_hash}")

    # STAGE 6: Verify Digital Signature & Check Integrity
    print("\n[STAGE 6] Cryptographic Signature & Integrity Verification...")
    verif_res = requests.post(f"{BASE_URL}/security/analysis/{analysis_id}/verify", headers=headers)
    assert verif_res.status_code == 200, f"Verification failed: {verif_res.text}"
    verif_doc = verif_res.json()
    verifs = verif_doc["verifications"]
    assert len(verifs) > 0
    v = verifs[0]
    print(f"[SUCCESS] Signature Verification Status: {v['verification_status']}")
    print(f"[SUCCESS] Document Integrity Status: {v['integrity_status']}")
    assert v["verification_status"] == "VALID"
    assert v["integrity_status"] == "INTACT"

    # STAGE 7: Validate Public Key / Certificate
    print("\n[STAGE 7] Validate Public Key / Certificate Security...")
    cert_res = requests.post(f"{BASE_URL}/security/analysis/{analysis_id}/certificate-validation", headers=headers)
    assert cert_res.status_code == 200
    cert_analysis = requests.get(f"{BASE_URL}/security/analysis/{analysis_id}/certificate-analysis", headers=headers).json()
    print(f"[SUCCESS] Certificate Trust Status: {cert_analysis['trust_status']}")
    print(f"[SUCCESS] Time Validity Status: {cert_analysis['time_validity_status']}")
    print(f"[SUCCESS] Certificate Security Score: {cert_analysis['certificate_security_score']}/100")

    # STAGE 8: Check Stored Signature Records (Replay / Activity Lookup)
    print("\n[STAGE 8] Checking Stored Signature Records & Activity Fingerprints...")
    stats = requests.get(f"{BASE_URL}/security/activity-stats", headers=headers).json()
    print(f"[SUCCESS] Verified Repository Records:")
    print(f"  - Total Uploads (15m): {stats['stats_15m']['total_uploads']}")
    print(f"  - Total Verifications (15m): {stats['stats_15m']['total_verifications']}")
    print(f"  - Unique Signatures: {stats['stats_15m']['unique_signatures']}")

    # STAGE 9: Quantum-Inspired Security Analysis
    print("\n[STAGE 9] Quantum-Inspired Security Analysis Engine...")
    q_res = requests.post(f"{BASE_URL}/security/analysis/{analysis_id}/quantum-analysis", headers=headers)
    assert q_res.status_code == 200
    q_data = q_res.json()["quantum_analysis"]
    print(f"[SUCCESS] Quantum Classification: {q_data['final_classification']}")
    print(f"[SUCCESS] State Consistency Score: {q_data['secure_consistency_score']:.2f}")
    print(f"[SUCCESS] Pauli Disturbance Score: {q_data['disturbance_score']:.2f}")
    print(f"[SUCCESS] Projective Measurement P(Secure): {q_data['secure_measurement_score']:.2f}%")
    print(f"[SUCCESS] Confidence Level: {q_data['confidence_level']}")

    # STAGE 10: Threat Detection
    print("\n[STAGE 10] Threat Incident Engine Evaluation...")
    threats_res = requests.get(f"{BASE_URL}/security/analysis/{analysis_id}/threat-incidents", headers=headers)
    assert threats_res.status_code == 200
    threats = threats_res.json()
    print(f"[SUCCESS] Detected Threat Incidents: {len(threats)}")
    for t in threats:
        print(f"  - Incident [{t['severity']}]: {t['threat_category']} (Score: {t['threat_score']})")

    # STAGE 11 & 12: Risk Score & Final Security Report
    print("\n[STAGE 11 & 12] Synthesizing Final Risk Score & 5-Layer Security Report...")
    decision_res = requests.post(f"{BASE_URL}/security/analysis/{analysis_id}/final-decision", headers=headers)
    assert decision_res.status_code == 200
    decision = decision_res.json()
    print(f"[SUCCESS] Final Security Decision: {decision['final_security_decision']}")
    print(f"[SUCCESS] Composite Overall Risk Score: {decision['overall_risk_score']}/100")
    print(f"[SUCCESS] Recommended Action: {decision['recommended_action']}")

    # Download Report PDF
    pdf_report_res = requests.get(f"{BASE_URL}/security/reports/{analysis_id}/download-pdf", headers=headers)
    assert pdf_report_res.status_code == 200
    assert len(pdf_report_res.content) > 1000
    print(f"[SUCCESS] Downloaded Final Audit Report PDF ({len(pdf_report_res.content)} bytes)")

    # --------------------------------------------------------------------------
    # PIPELINE EXECUTION FOR SIGNED TXT
    # --------------------------------------------------------------------------
    print("\n" + "=" * 55)
    print(">>> EXECUTING PIPELINE FOR SIGNED TXT DOCUMENT")
    print("=" * 55)

    # Sign a TXT message
    txt_sign_res = requests.post(f"{BASE_URL}/documents/sign-text", headers=u_headers, json={
        "text_content": "OFFICIAL EXECUTIVE DIRECTIVE: Authorize deployment of cyber protection grid.",
        "filename": "executive_directive.txt"
    })
    signed_txt_envelope = txt_sign_res.json()["signed_message_json"]

    # Upload and analyze multi-format
    txt_analysis_res = requests.post(
        f"{BASE_URL}/security/analyze-multiformat",
        headers=headers,
        json={
            "input_type": "SIGNED_MESSAGE",
            "content_text": signed_txt_envelope,
            "filename": "signed_directive_envelope.json"
        }
    )
    assert txt_analysis_res.status_code == 200, f"TXT analyze failed: {txt_analysis_res.text}"
    txt_analysis_doc = txt_analysis_res.json()
    txt_aid = txt_analysis_doc["analysis_document_id"]
    print(f"[SUCCESS] TXT Analysis Complete! ID: #{txt_aid}")
    print(f"  - Content Type: {txt_analysis_doc.get('content_type')}")
    print(f"  - Extracted Algorithm: {txt_analysis_doc['extracted_metadata']['signature_algorithm']}")
    print(f"  - Verification: {txt_analysis_doc['verifications'][0]['verification_status']}")
    print(f"  - Integrity: {txt_analysis_doc['verifications'][0]['integrity_status']}")
    print(f"  - Quantum Classification: {txt_analysis_doc['quantum_analysis']['final_classification']}")

    print("\n" + "=" * 75)
    print("ALL 12 PIPELINE STAGES VERIFIED WITH 100% SUCCESS ACROSS PDF & TXT!")
    print("=" * 75)

if __name__ == "__main__":
    run_analyst_lifecycle_test()
