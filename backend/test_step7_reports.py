import os
import sys
import unittest
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.db import SessionLocal
from app.models import User, AnalyzedDocument, ExtractedSignatureMetadata, SignatureVerification, QuantumInspiredAnalysis, ThreatIncident, CertificateSecurityAnalysis, SecurityReport
from app.core.cert_validator import validate_document_certificate_security, validate_certificate_security
from app.core.report_engine import synthesize_final_security_report, generate_pdf_security_report, compute_file_sha256

class TestStep7CertificateValidationAndReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = SessionLocal()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_trusted_demo_ca_certificate_validation(self):
        meta = {
            "signature_detected": True,
            "signature_status": "SIGNATURE_FOUND",
            "signature_algorithm": "sha256WithRSAEncryption",
            "hash_algorithm": "SHA-256",
            "signature_fingerprint": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "certificate_subject": "CN=Aditya User, OU=Digital Signature Unit, O=Q-SHIELD Security Platform",
            "certificate_issuer": "CN=Q-SHIELD Development CA (Demo), OU=Quantum Security, O=Q-SHIELD Platform",
            "certificate_serial_number": "1001",
            "certificate_fingerprint": "c1c2c3c4c5c67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "validity_start": "2026-01-01T00:00:00+00:00",
            "validity_end": "2030-01-01T00:00:00+00:00",
            "signing_time": "2026-09-05T12:00:00+00:00"
        }

        res = validate_certificate_security(meta)
        self.assertEqual(res["trust_status"], "TRUSTED_FOR_QSHIELD_DEMO")
        self.assertEqual(res["time_validity_status"], "VALID_TIME_RANGE")
        self.assertEqual(res["structure_status"], "STRUCTURALLY_VALID")
        self.assertEqual(res["algorithm_security_status"], "SECURE_PARAMETERS")
        self.assertGreaterEqual(res["certificate_security_score"], 80.0)

    def test_02_expired_certificate_validation(self):
        meta = {
            "signature_detected": True,
            "signature_status": "SIGNATURE_FOUND",
            "signature_algorithm": "sha256WithRSAEncryption",
            "hash_algorithm": "SHA-256",
            "signature_fingerprint": "b1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "certificate_subject": "CN=Old User, O=Legacy Corp",
            "certificate_issuer": "CN=Q-SHIELD Development CA (Demo)",
            "certificate_serial_number": "9999",
            "certificate_fingerprint": "e1e2e3e4e5e67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "validity_start": "2020-01-01T00:00:00+00:00",
            "validity_end": "2022-01-01T00:00:00+00:00",
            "signing_time": "2021-05-01T12:00:00+00:00"
        }

        res = validate_certificate_security(meta)
        self.assertEqual(res["time_validity_status"], "EXPIRED")
        self.assertLess(res["certificate_security_score"], 80.0)

    def test_03_unsigned_document_certificate_validation(self):
        meta = {
            "signature_detected": False,
            "signature_status": "NO_SIGNATURE_FOUND"
        }

        res = validate_certificate_security(meta)
        self.assertEqual(res["structure_status"], "UNSUPPORTED")
        self.assertEqual(res["time_validity_status"], "UNKNOWN")
        self.assertEqual(res["certificate_security_score"], 0.0)

    def test_04_synthesize_5_layer_secure_decision(self):
        doc = self.db.query(AnalyzedDocument).first()
        self.assertIsNotNone(doc, "AnalyzedDocument record required for test")

        dec = synthesize_final_security_report(self.db, doc, analyst_name="Test Analyst")
        self.assertIn("final_security_decision", dec)
        self.assertIn("overall_risk_score", dec)
        self.assertIn("summary_justification", dec)
        self.assertIn("recommended_action", dec)
        self.assertIn(dec["final_security_decision"], ["SECURE", "REQUIRES_CAUTION", "SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE"])

    def test_05_pdf_security_report_generation(self):
        doc = self.db.query(AnalyzedDocument).first()
        self.assertIsNotNone(doc, "AnalyzedDocument record required for test")

        report = generate_pdf_security_report(self.db, doc.analysis_document_id, analyst_name="Lead Analyst")
        self.assertIsNotNone(report)
        self.assertTrue(Path(report.report_path).exists())
        self.assertTrue(report.report_path.endswith(".pdf"))
        self.assertEqual(len(report.report_hash), 64) # SHA-256 length

        # Verify PDF header
        with open(report.report_path, "rb") as f:
            pdf_header = f.read(5)
            self.assertEqual(pdf_header, b"%PDF-")

    def test_06_report_hash_integrity(self):
        doc = self.db.query(AnalyzedDocument).first()
        report = self.db.query(SecurityReport).filter(SecurityReport.analysis_document_id == doc.analysis_document_id).first()
        self.assertIsNotNone(report)

        computed_hash = compute_file_sha256(Path(report.report_path))
        self.assertEqual(report.report_hash, computed_hash, "Report SHA-256 hash must match generated PDF file")

if __name__ == "__main__":
    unittest.main()
