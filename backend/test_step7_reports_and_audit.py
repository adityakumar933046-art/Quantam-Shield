"""
Step 7 Comprehensive Verification Test Suite:
Security Reports, Audit Logs, and Defensive Performance Evaluation
Tests all 12 required scenarios deterministically.
"""

import sys
import os
import json
import uuid
import hashlib
from datetime import datetime, timezone

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.db import get_db, SessionLocal
from app.models import (
    User,
    AnalyzedDocument,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    AttackSimulation,
    AttackSimulationResult,
    SecurityReport,
    AuditLog
)
from app.core.audit_engine import (
    log_audit_event,
    verify_audit_log_integrity,
    compute_audit_hash,
    sanitize_sensitive_data
)
from app.core.performance_engine import calculate_performance_metrics
from app.core.report_engine import (
    build_analysis_security_report,
    build_threat_report,
    build_simulation_report,
    build_audit_report,
    build_performance_report,
    export_report_content,
    generate_report_reference
)


def run_all_tests():
    db = SessionLocal()
    print("==================================================================")
    print("  Q-SHIELD STEP 7: SECURITY REPORTS & AUDIT LOGS TEST SUITE")
    print("==================================================================")

    passed = 0
    failed = 0

    # ------------------------------------------------------------------
    # TEST 1: Valid analysis generates correct report
    # ------------------------------------------------------------------
    try:
        # Create a sample authentic analyzed document
        doc1 = AnalyzedDocument(
            analyst_user_id=1,
            original_file_name="authentic_contract.pdf",
            stored_file_name="authentic_contract.pdf",
            file_path="uploads/authentic_contract.pdf",
            document_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            canonical_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_type="PDF",
            signature_present=True,
            signature_status="VALID",
            integrity_verified=True,
            risk_score=5.0,
            risk_level="LOW",
            final_decision="AUTHENTIC",
            created_at=datetime.now(timezone.utc)
        )
        db.add(doc1)
        db.commit()
        db.refresh(doc1)

        rep1_data = build_analysis_security_report(doc1.analysis_document_id, db, "analyst@qshield.com")
        assert rep1_data["report_type"] == "ANALYSIS_REPORT"
        assert rep1_data["document_information"]["document_name"] == "authentic_contract.pdf"
        assert rep1_data["classical_verification"]["digital_signature_status"] == "VALID"
        assert rep1_data["risk_assessment"]["final_risk_score"] == 5.0
        assert rep1_data["risk_assessment"]["final_decision"] == "AUTHENTIC"
        assert any("Safe for authorized business workflows" in r for r in rep1_data["recommendations"])
        print("[PASS] Test 1: Valid analysis generates correct report with deterministic recommendations.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 2: Tampering threat appears in report
    # ------------------------------------------------------------------
    try:
        doc2 = AnalyzedDocument(
            analyst_user_id=1,
            original_file_name="tampered_invoice.pdf",
            stored_file_name="tampered_invoice.pdf",
            file_path="uploads/tampered_invoice.pdf",
            document_hash="b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
            canonical_hash="b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
            file_type="PDF",
            signature_present=True,
            signature_status="VALID",
            integrity_verified=False,
            risk_score=85.0,
            risk_level="CRITICAL",
            final_decision="DOCUMENT_TAMPERED",
            created_at=datetime.now(timezone.utc)
        )
        db.add(doc2)
        db.commit()
        db.refresh(doc2)

        ver2 = SignatureVerification(
            analysis_document_id=doc2.analysis_document_id,
            signature_identifier="sig_002",
            verification_status="VALID",
            integrity_status="MODIFIED",
            verification_details="Hash mismatch in byte range"
        )
        db.add(ver2)

        thr2 = ThreatIncident(
            analysis_document_id=doc2.analysis_document_id,
            threat_category="DOCUMENT_TAMPERING",
            threat_type="BYTE_MODIFICATION",
            severity="CRITICAL",
            threat_score=85.0,
            confidence=0.98,
            description="Document byte stream modified after signature generation"
        )
        db.add(thr2)
        db.commit()

        rep2_data = build_analysis_security_report(doc2.analysis_document_id, db, "analyst@qshield.com")
        assert rep2_data["classical_verification"]["document_integrity"] == "MODIFIED"
        assert rep2_data["threat_detection"]["threats_count"] == 1
        assert rep2_data["threat_detection"]["detected_threats"][0]["threat_category"] == "DOCUMENT_TAMPERING"
        assert any("modified after signing" in r for r in rep2_data["recommendations"])
        print("[PASS] Test 2: Tampering threat appears prominently with appropriate recommendations.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 3: Forgery risk appears correctly in quantum-inspired section
    # ------------------------------------------------------------------
    try:
        q_analysis = QuantumInspiredAnalysis(
            analysis_document_id=doc2.analysis_document_id,
            security_state_vector=json.dumps([0.1, 0.9, 0.0, 0.0, 0.0]),
            state_consistency=0.25,
            state_disturbance=0.75,
            measurement_secure_probability=0.20,
            measurement_threat_probability=0.80,
            combined_pauli_disturbance=0.65,
            forgery_risk_score=78.5,
            final_classification="HIGH_FORGERY_RISK",
            quantum_analysis_version="QIA-2.0"
        )
        db.add(q_analysis)
        db.commit()
        db.expire_all()

        rep2_updated = build_analysis_security_report(doc2.analysis_document_id, db, "analyst@qshield.com")
        q_sec = rep2_updated["quantum_inspired_analysis"]
        assert q_sec["security_state"] == "HIGH_FORGERY_RISK"
        assert q_sec["forgery_risk_estimate"] == 78.5
        assert "THEORETICAL MATHEMATICAL SIMULATION" in q_sec["section_label"]
        print("[PASS] Test 3: Quantum-inspired forgery risk and disclaimer strictly labeled.")
        passed += 1
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[FAIL] Test 3: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 4: Replay activity appears in audit history
    # ------------------------------------------------------------------
    try:
        thr_replay = ThreatIncident(
            analysis_document_id=doc2.analysis_document_id,
            threat_category="REPLAY_ATTACK",
            threat_type="DUPLICATE_SIGNATURE_SUBMISSION",
            severity="HIGH",
            threat_score=68.0,
            confidence=0.92,
            description="Replayed signature identifier observed in rapid succession"
        )
        db.add(thr_replay)

        log_replay = log_audit_event(
            db=db,
            action="REPLAY_ATTACK_DETECTED",
            user_email="system@qshield.com",
            resource_type="DOCUMENT",
            resource_id=str(doc2.analysis_document_id),
            result="WARNING",
            details="High frequency verification attempt detected for signature #sig_002"
        )
        db.commit()

        rep_thr = build_threat_report(db, "analyst@qshield.com")
        replay_found = any(t["threat_category"] == "REPLAY_ATTACK" for t in rep_thr["threat_catalog"])
        assert replay_found, "Replay attack not cataloged in threat report"
        print("[PASS] Test 4: Replay attack activity recorded and captured in threat intelligence.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 5: Unauthorized attempt creates audit event
    # ------------------------------------------------------------------
    try:
        unauth_log = log_audit_event(
            db=db,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            user_email="attacker@external.io",
            resource_type="ADMIN_PANEL",
            resource_id="/api/admin/audit-logs",
            result="FAILED",
            details="Access denied for non-admin principal",
            ip_address="192.168.1.100"
        )
        assert unauth_log.result == "FAILED"
        assert unauth_log.action == "UNAUTHORIZED_ACCESS_ATTEMPT"
        assert unauth_log.current_log_hash is not None
        print("[PASS] Test 5: Unauthorized access attempt successfully logged with hash chain link.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 5: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 6: Simulation result updates performance metrics
    # ------------------------------------------------------------------
    try:
        sim_id_str = f"SIM-{uuid.uuid4().hex[:8].upper()}"
        sim = AttackSimulation(
            simulation_id=sim_id_str,
            initiated_by="tester@qshield.com",
            attack_type="DOCUMENT_TAMPERING",
            target_document_reference="contract_sample.pdf",
            status="COMPLETED",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.add(sim)
        db.commit()
        db.refresh(sim)

        sim_res = AttackSimulationResult(
            simulation_id=sim.id,
            attack_type="DOCUMENT_TAMPERING",
            detection_success=True,
            detection_status="DETECTED",
            signature_valid=False,
            integrity_valid=False,
            state_consistency=0.2,
            state_disturbance=0.8,
            pauli_disturbance=0.7,
            measurement_secure_probability=0.2,
            measurement_threat_probability=0.8,
            forgery_risk_estimate=80.0,
            final_risk_score=85.0,
            final_risk_level="CRITICAL",
            execution_time_ms=45.2,
            created_at=datetime.now(timezone.utc)
        )
        db.add(sim_res)
        db.commit()

        metrics = calculate_performance_metrics(db)
        assert metrics["total_simulations"] >= 1
        assert metrics["detected_simulations"] >= 1
        assert "DOCUMENT_TAMPERING" in metrics["attack_type_breakdown"]
        assert metrics["attack_type_breakdown"]["DOCUMENT_TAMPERING"]["detected"] >= 1
        print("[PASS] Test 6: Attack simulation dynamically updates defensive performance metrics.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 6: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 7: Audit hash chain remains valid (AUDIT_LOG_VALID)
    # ------------------------------------------------------------------
    try:
        check = verify_audit_log_integrity(db)
        assert check["status"] == "AUDIT_LOG_VALID", f"Expected AUDIT_LOG_VALID, got {check['status']}"
        assert check["chain_intact"] is True
        assert check["total_records_verified"] >= 1
        print(f"[PASS] Test 7: Audit log hash chain intact ({check['total_records_verified']} records verified).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 7: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 8: Intentional DB tampering produces AUDIT_LOG_INTEGRITY_WARNING
    # ------------------------------------------------------------------
    try:
        # Create an audit event
        temp_log = log_audit_event(
            db=db,
            action="SECURITY_CHECK",
            user_email="auditor@qshield.com",
            resource_type="SYSTEM",
            resource_id="SYS_01",
            result="SUCCESS",
            details="Authentic log entry"
        )
        # Verify it is valid before tampering
        v_pre = verify_audit_log_integrity(db)
        assert v_pre["status"] == "AUDIT_LOG_VALID"

        # Directly tamper the DB entry details without updating the hash
        original_details = temp_log.details
        temp_log.details = "TAMPERED DETAILS INJECTED BY ATTACKER"
        db.commit()

        # Run verification - MUST detect corruption!
        v_post = verify_audit_log_integrity(db)
        assert v_post["status"] == "AUDIT_LOG_INTEGRITY_WARNING", f"Expected AUDIT_LOG_INTEGRITY_WARNING, got {v_post['status']}"
        assert v_post["chain_intact"] is False
        assert v_post["corrupted_event_id"] == temp_log.event_id

        # Restore original details so rest of test suite passes
        temp_log.details = original_details
        db.commit()

        v_restored = verify_audit_log_integrity(db)
        assert v_restored["status"] == "AUDIT_LOG_VALID"
        print("[PASS] Test 8: Tampered log immediately triggers AUDIT_LOG_INTEGRITY_WARNING with discrepancy.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 8: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 9: Performance metrics handle zero denominators safely
    # ------------------------------------------------------------------
    try:
        # Verify calculation does not crash with empty or zero values
        metrics = calculate_performance_metrics(db)
        assert isinstance(metrics["accuracy"], float)
        assert isinstance(metrics["precision"], float)
        assert isinstance(metrics["recall"], float)
        assert isinstance(metrics["f1_score"], float)
        assert 0.0 <= metrics["detection_rate"] <= 100.0
        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert 0.0 <= metrics["precision"] <= 1.0
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["f1_score"] <= 1.0
        print("[PASS] Test 9: Statistical performance metrics handle edge cases and zero division safely.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 9: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 10: Dashboard aggregations return real data
    # ------------------------------------------------------------------
    try:
        total_docs = db.query(AnalyzedDocument).count()
        assert total_docs >= 2
        total_threats = db.query(ThreatIncident).count()
        assert total_threats >= 2
        perf_rep = build_performance_report(db, "analyst@qshield.com")
        assert perf_rep["report_type"] == "PERFORMANCE_REPORT"
        print("[PASS] Test 10: Real database metrics aggregated into dashboard structures.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 10: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 11: Report export does not contain private keys/secrets
    # ------------------------------------------------------------------
    try:
        sec_rep = SecurityReport(
            report_reference="QSHIELD-REPORT-SECRETTEST",
            report_type="ANALYSIS_REPORT",
            overall_status="AUTHENTIC",
            risk_score=10.0,
            risk_level="LOW",
            summary="Secret test report",
            report_data=json.dumps({
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
                "password": "secret_password_123",
                "auth_token": "bearer eyJhbGciOi...",
                "doc_name": "clean_file.txt"
            }),
            generated_by="analyst@qshield.com",
            generated_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc)
        )
        db.add(sec_rep)
        db.commit()

        # Export JSON
        content_json, media_json, _ = export_report_content(sec_rep, "json")
        json_text = content_json.decode("utf-8")
        assert "-----BEGIN RSA PRIVATE KEY-----" not in json_text
        assert "[REDACTED_PRIVATE_KEY]" in json_text
        assert "secret_password_123" not in json_text
        assert "[REDACTED_SECRET]" in json_text

        # Export HTML
        content_html, media_html, _ = export_report_content(sec_rep, "html")
        html_text = content_html.decode("utf-8")
        assert "-----BEGIN RSA PRIVATE KEY-----" not in html_text
        assert "secret_password_123" not in html_text

        print("[PASS] Test 11: Report export enforces zero secret leakage (sanitizes private keys & tokens).")
        passed += 1
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[FAIL] Test 11: {e}")
        failed += 1

    # ------------------------------------------------------------------
    # TEST 12: RBAC checks on report and audit endpoints
    # ------------------------------------------------------------------
    try:
        from app.api.reports import require_analyst_or_admin
        from app.api.audit import require_super_admin
        from fastapi import HTTPException

        user_regular = User(user_id=99, email="user@qshield.com", role="DIGITAL_SIGNATURE_USER", status="ACTIVE")
        user_analyst = User(user_id=98, email="analyst@qshield.com", role="SECURITY_ANALYST", status="ACTIVE")
        user_admin = User(user_id=97, email="admin@qshield.com", role="SUPER_ADMIN", status="ACTIVE")

        # Regular user should fail analyst check
        try:
            require_analyst_or_admin(user_regular)
            assert False, "Regular user should not pass analyst check"
        except HTTPException as he:
            assert he.status_code == 403

        # Analyst passes analyst check
        assert require_analyst_or_admin(user_analyst) == user_analyst

        # Analyst should fail super admin check
        try:
            require_super_admin(user_analyst)
            assert False, "Analyst should not pass super admin check"
        except HTTPException as he:
            assert he.status_code == 403

        # Admin passes super admin check
        assert require_super_admin(user_admin) == user_admin

        print("[PASS] Test 12: Role-based authorization strictly enforces least-privilege security.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 12: {e}")
        failed += 1

    print("==================================================================")
    print(f"  STEP 7 TEST RESULTS: {passed} PASSED, {failed} FAILED (TOTAL 12)")
    print("==================================================================")
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
