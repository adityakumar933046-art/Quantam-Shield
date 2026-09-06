"""
Q-SHIELD DEMO DATA SEEDER (SIH Presentation Ready)
Creates clean, safe, non-sensitive, predictable demonstration data.
Strictly labeled as DEMO / TEST / SIMULATION.
"""

import sys
import os
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.db import SessionLocal, init_and_migrate_db
from app.core.security import get_password_hash
from app.models import (
    User,
    SignedDocument,
    DigitalSignature,
    AnalyzedDocument,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    AttackSimulation,
    AttackSimulationResult,
    SecurityReport,
    AuditLog
)
from app.core.audit_engine import log_audit_event, verify_audit_log_integrity


def seed_demo_environment():
    print("==================================================================")
    print("  SEEDING Q-SHIELD SIH DEMONSTRATION DATA")
    print("==================================================================")

    init_and_migrate_db()
    db = SessionLocal()

    try:
        # 1. Platform Roles & Users
        users_to_ensure = [
            ("Platform Super Admin", "admin@qshield.com", "AdminPassword123!", "SUPER_ADMIN"),
            ("Digital Signature Operator", "user@qshield.com", "UserPassword123!", "DIGITAL_SIGNATURE_USER"),
            ("Senior Security Analyst", "analyst@qshield.com", "AnalystPassword123!", "SECURITY_ANALYST"),
            ("Unauthorized Demo Guest", "guest@external.test", "GuestPassword123!", "GUEST")
        ]

        user_map = {}
        for name, email, pwd, role in users_to_ensure:
            u = db.query(User).filter(User.email == email).first()
            if not u:
                u = User(
                    full_name=name,
                    email=email,
                    password_hash=get_password_hash(pwd),
                    role=role,
                    status="ACTIVE",
                    created_at=datetime.now(timezone.utc)
                )
                db.add(u)
                db.commit()
                db.refresh(u)
                print(f"[+] Created User: {email} ({role})")
            user_map[email] = u

        sig_user = user_map["user@qshield.com"]
        analyst = user_map["analyst@qshield.com"]

        # 2. Demo Signed Document (Valid)
        doc_hash_valid = "4a18018e612c6a0eb292d3f38bc5b9df0d0b04e6c2780e90ea2189d2d8544c06"
        sig_id_demo = "QSHIELD-SIGN-DEMO001"

        existing_doc = db.query(SignedDocument).filter(SignedDocument.document_hash == doc_hash_valid).first()
        if not existing_doc:
            s_doc = SignedDocument(
                user_id=sig_user.user_id,
                original_filename="DEMO_sample_contract.txt",
                original_file_path="uploads/DEMO_sample_contract.txt",
                file_path="uploads/DEMO_sample_contract.txt",
                signed_filename="DEMO_sample_contract.signed.json",
                document_hash=doc_hash_valid,
                canonical_hash=doc_hash_valid,
                signature_algorithm="RSA-SHA256",
                status="SIGNED",
                created_at=datetime.now(timezone.utc) - timedelta(hours=2)
            )
            db.add(s_doc)
            db.commit()
            db.refresh(s_doc)

            sig_rec = DigitalSignature(
                document_id=s_doc.document_id,
                signature_algorithm="RSA-SHA256",
                hash_algorithm="SHA-256",
                certificate_subject="CN=DEMO Digital Signer, O=Q-SHIELD Defense, C=US",
                certificate_issuer="CN=Q-SHIELD Root CA, O=Q-SHIELD Security Platform",
                certificate_serial_number="2026-DEMO-9910",
                certificate_fingerprint="SHA256:4f8e21a0b3c79e658392019ab921c3fe",
                signature_fingerprint=sig_id_demo,
                verification_status="VALID",
                signing_timestamp=datetime.now(timezone.utc) - timedelta(hours=2)
            )
            db.add(sig_rec)
            db.commit()
            print("[+] Seeded Demo Signed Document and Active Signature Record")

        # 3. Demo Analyzed Document: Authentic (Low Risk, Clean)
        anl_doc_clean = db.query(AnalyzedDocument).filter(AnalyzedDocument.original_file_name == "DEMO_verified_agreement.txt").first()
        if not anl_doc_clean:
            anl_doc_clean = AnalyzedDocument(
                analysis_id="QSHIELD-ANALYSIS-DEMO-VALID",
                signature_id=sig_id_demo,
                analyst_user_id=analyst.user_id,
                original_file_name="DEMO_verified_agreement.txt",
                stored_file_name="DEMO_verified_agreement.txt",
                file_path="uploads/DEMO_verified_agreement.txt",
                file_type="TXT",
                document_hash=doc_hash_valid,
                canonical_hash=doc_hash_valid,
                signature_present=True,
                signature_status="VALID",
                signature_verified=True,
                integrity_verified=True,
                certificate_status="TRUSTED",
                public_key_status="VALID",
                risk_score=5.0,
                risk_level="LOW",
                final_decision="AUTHENTIC",
                analysis_summary="Document integrity verified. Cryptographic digital signature intact. No tampering detected.",
                created_at=datetime.now(timezone.utc) - timedelta(hours=1)
            )
            db.add(anl_doc_clean)
            db.commit()
            db.refresh(anl_doc_clean)

            ver_clean = SignatureVerification(
                analysis_document_id=anl_doc_clean.analysis_document_id,
                signature_identifier=sig_id_demo,
                verification_status="VALID",
                integrity_status="INTACT",
                signature_algorithm="RSA-SHA256",
                hash_algorithm="SHA-256",
                verification_details="Cryptographic verification passed. ByteRange integrity validated."
            )
            db.add(ver_clean)

            q_clean = QuantumInspiredAnalysis(
                analysis_document_id=anl_doc_clean.analysis_document_id,
                security_state_vector=json.dumps([1.0, 0.0, 0.0, 0.0, 0.0]),
                state_consistency=1.0,
                state_disturbance=0.0,
                measurement_secure_probability=1.0,
                measurement_threat_probability=0.0,
                pauli_x_disturbance=0.0,
                pauli_y_disturbance=0.0,
                pauli_z_disturbance=0.0,
                combined_pauli_disturbance=0.0,
                forgery_risk_score=0.0,
                forgery_risk_estimate=0.0,
                final_classification="AUTHENTIC_STATE",
                quantum_analysis_version="QIA-2.0"
            )
            db.add(q_clean)
            db.commit()
            print("[+] Seeded Clean Document Analysis (Authentic / Low Risk)")

        # 4. Demo Analyzed Document: Tampered (High Risk, Document Tampering)
        doc_hash_tampered = "8e9b671a5c43d2e0f19a0b8e7c654321fedcba9876543210abcdef0123456789"
        anl_doc_tampered = db.query(AnalyzedDocument).filter(AnalyzedDocument.original_file_name == "DEMO_tampered_procurement.txt").first()
        if not anl_doc_tampered:
            anl_doc_tampered = AnalyzedDocument(
                analysis_id="QSHIELD-ANALYSIS-DEMO-TAMPERED",
                signature_id=sig_id_demo,
                analyst_user_id=analyst.user_id,
                original_file_name="DEMO_tampered_procurement.txt",
                stored_file_name="DEMO_tampered_procurement.txt",
                file_path="uploads/DEMO_tampered_procurement.txt",
                file_type="TXT",
                document_hash=doc_hash_tampered,
                canonical_hash=doc_hash_tampered,
                signature_present=True,
                signature_status="INVALID",
                signature_verified=False,
                integrity_verified=False,
                certificate_status="TRUSTED",
                public_key_status="VALID",
                risk_score=88.5,
                risk_level="CRITICAL",
                final_decision="DOCUMENT_TAMPERED",
                analysis_summary="Document content altered after signing! SHA-256 digest does not match digital signature payload.",
                created_at=datetime.now(timezone.utc) - timedelta(minutes=40)
            )
            db.add(anl_doc_tampered)
            db.commit()
            db.refresh(anl_doc_tampered)

            ver_tampered = SignatureVerification(
                analysis_document_id=anl_doc_tampered.analysis_document_id,
                signature_identifier=sig_id_demo,
                verification_status="INVALID",
                integrity_status="MODIFIED",
                signature_algorithm="RSA-SHA256",
                hash_algorithm="SHA-256",
                verification_details="Hash mismatch: Expected 4a18018e... but document computed 8e9b671a..."
            )
            db.add(ver_tampered)

            thr_tamper = ThreatIncident(
                analysis_document_id=anl_doc_tampered.analysis_document_id,
                threat_category="DOCUMENT_TAMPERING",
                threat_type="BYTE_MODIFICATION",
                severity="CRITICAL",
                threat_score=92.0,
                confidence=0.99,
                threat_status="OPEN",
                description="Byte payload altered after digital signature timestamp. Critical content mismatch.",
                evidence_data=json.dumps({"expected_hash": doc_hash_valid, "computed_hash": doc_hash_tampered})
            )
            db.add(thr_tamper)

            q_tampered = QuantumInspiredAnalysis(
                analysis_document_id=anl_doc_tampered.analysis_document_id,
                security_state_vector=json.dumps([0.1, 0.9, 0.0, 0.0, 0.0]),
                state_consistency=0.15,
                state_disturbance=0.85,
                measurement_secure_probability=0.10,
                measurement_threat_probability=0.90,
                pauli_x_disturbance=0.95,
                pauli_y_disturbance=0.45,
                pauli_z_disturbance=0.10,
                combined_pauli_disturbance=0.55,
                forgery_risk_score=85.0,
                forgery_risk_estimate=85.0,
                final_classification="CRITICAL_DISTURBANCE",
                quantum_analysis_version="QIA-2.0"
            )
            db.add(q_tampered)
            db.commit()
            print("[+] Seeded Tampered Document Analysis (Critical Risk / Threat Logged)")

        # 5. Demo Controlled Attack Simulation
        sim_demo = db.query(AttackSimulation).filter(AttackSimulation.simulation_id == "SIM-DEMO-TAMPER-01").first()
        if not sim_demo:
            sim_demo = AttackSimulation(
                simulation_id="SIM-DEMO-TAMPER-01",
                initiated_by=analyst.email,
                attack_type="DOCUMENT_TAMPERING",
                target_document_reference="DEMO_sample_contract.txt",
                status="COMPLETED",
                started_at=datetime.now(timezone.utc) - timedelta(minutes=20),
                completed_at=datetime.now(timezone.utc) - timedelta(minutes=20)
            )
            db.add(sim_demo)
            db.commit()
            db.refresh(sim_demo)

            sim_res = AttackSimulationResult(
                simulation_id=sim_demo.id,
                attack_type="DOCUMENT_TAMPERING",
                detection_success=True,
                detection_status="DETECTED",
                signature_valid=False,
                integrity_valid=False,
                state_consistency=0.1,
                state_disturbance=0.9,
                pauli_disturbance=0.85,
                measurement_secure_probability=0.1,
                measurement_threat_probability=0.9,
                forgery_risk_estimate=88.0,
                final_risk_score=92.0,
                final_risk_level="CRITICAL",
                execution_time_ms=38.4,
                threats_detected=json.dumps([{"threat_category": "DOCUMENT_TAMPERING", "severity": "CRITICAL"}]),
                explanation=json.dumps({"method": "Controlled byte perturbation", "rule": "DETERMINISTIC_HASH_MISMATCH"}),
                created_at=datetime.now(timezone.utc) - timedelta(minutes=20)
            )
            db.add(sim_res)
            db.commit()
            print("[+] Seeded Controlled Attack Simulation Record")

        # 6. Demo Security Reports
        rep_demo = db.query(SecurityReport).filter(SecurityReport.report_reference == "QSHIELD-REPORT-DEMO001").first()
        if not rep_demo:
            rep_demo = SecurityReport(
                report_reference="QSHIELD-REPORT-DEMO001",
                report_type="ANALYSIS_REPORT",
                analysis_document_id=anl_doc_clean.analysis_document_id,
                document_name="DEMO_verified_agreement.txt",
                document_hash=doc_hash_valid,
                signature_id=sig_id_demo,
                overall_status="AUTHENTIC",
                final_security_decision="AUTHENTIC",
                risk_score=5.0,
                overall_risk_score=5.0,
                risk_level="LOW",
                summary="Full deterministic security evaluation report for DEMO_verified_agreement.txt: All cryptographic checks passed.",
                report_data=json.dumps({
                    "report_type": "ANALYSIS_REPORT",
                    "document_information": {
                        "document_name": "DEMO_verified_agreement.txt",
                        "file_type": "TXT",
                        "document_hash": doc_hash_valid,
                        "signature_id": sig_id_demo
                    },
                    "classical_verification": {
                        "digital_signature_status": "VALID",
                        "document_integrity": "INTACT",
                        "signature_algorithm": "RSA-SHA256",
                        "hash_algorithm": "SHA-256",
                        "certificate_status": "TRUSTED"
                    },
                    "quantum_inspired_analysis": {
                        "security_state": "AUTHENTIC_STATE",
                        "state_consistency_score": 100.0,
                        "state_disturbance_score": 0.0,
                        "secure_measurement_probability": 100.0,
                        "forgery_risk_estimate": 0.0,
                        "scientific_disclaimer": "Mathematical simulation in Hilbert space C^2. Classical digital signatures are software abstractions."
                    },
                    "recommendations": [
                        "Document integrity and cryptographic digital signature are valid. Safe for authorized business workflows."
                    ]
                }),
                report_version="QSR-2.0",
                generated_by=analyst.email,
                generated_at=datetime.now(timezone.utc) - timedelta(minutes=10),
                created_at=datetime.now(timezone.utc) - timedelta(minutes=10)
            )
            db.add(rep_demo)
            db.commit()
            print("[+] Seeded Demo Security Report (QSHIELD-REPORT-DEMO001)")

        # 7. Seed Demo Audit Logs
        log_audit_event(
            db=db,
            action="PLATFORM_DEMO_INITIALIZED",
            user_email=analyst.email,
            user_id=analyst.user_id,
            resource_type="SYSTEM",
            resource_id="SIH_DEMO_HARNESS",
            result="SUCCESS",
            details="Seeded SIH presentation demonstration data and verified cryptographic chain."
        )

        # Check audit chain integrity
        check = verify_audit_log_integrity(db)
        print(f"[+] Audit Log Chain Status: {check['status']} ({check['total_records_verified']} records verified intact)")

        print("==================================================================")
        print("  DEMO DATA SEEDING COMPLETE! READY FOR SIH PRESENTATION")
        print("==================================================================")

    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_environment()
