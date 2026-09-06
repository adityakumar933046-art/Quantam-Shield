import os
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.config import UPLOADS_ANALYSIS
from app.models import (
    User,
    AnalyzedDocument,
    ExtractedSignatureMetadata,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    CertificateSecurityAnalysis,
    SecurityReport,
    AuditLog,
    VerificationActivity
)
from app.core.id_generator import generate_analysis_id
from app.schemas import (
    AnalysisDocumentResponse,
    ExtractedMetadataResponse,
    SignatureVerificationResponse,
    QuantumAnalysisResponse,
    AnalysisExplanationResponse,
    ThreatIncidentResponse,
    ThreatIncidentUpdateStatus,
    ReplayAnalysisResponse,
    ActivityStatsResponse,
    CertificateAnalysisResponse,
    FinalDecisionResponse,
    SecurityReportResponse
)
from app.api.auth import get_current_user
from app.core.extractor import extract_pdf_signature_info, extract_multiformat_signature_info, compute_sha256
from app.core.verifier import verify_pdf_signatures, verify_multiformat_signature
from app.core.format_processors import detect_content_format, ContentType
from app.schemas import MultiFormatAnalysisRequest
from app.core.quantum_engine import analyze_quantum_security_state
from app.core.threat_engine import (
    evaluate_and_generate_threats,
    analyze_replay_suspicion,
    calculate_activity_statistics
)
from app.core.cert_validator import validate_document_certificate_security
from app.core.report_engine import synthesize_final_security_report

router = APIRouter(prefix="/security", tags=["Security Analyst Inspection & Threat Engine"])

MAX_FILE_SIZE = 25 * 1024 * 1024 # 25 MB

def require_security_analyst(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN"]:
        audit = AuditLog(
            user_id=current_user.user_id,
            user_email=current_user.email,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            details=f"User '{current_user.email}' with role '{current_user.role}' attempted restricted security analyst API access."
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Only Security Analysts can access signature inspection modules."
        )
    return current_user

@router.post("/upload-analyze", response_model=AnalysisDocumentResponse)
async def upload_and_analyze_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes)."
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum limit of {MAX_FILE_SIZE // (1024*1024)}MB."
        )

    fmt = detect_content_format(content, file.filename or "")
    if fmt == ContentType.GENERIC_BINARY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported or invalid file format. Only PDF, TXT, JSON, and structured signature files are supported."
        )

    file_id = str(uuid.uuid4())[:8]
    safe_name = Path(file.filename or "analysis_input.txt").name.replace(" ", "_")
    saved_filename = f"analysis_{analyst.user_id}_{file_id}_{safe_name}"
    saved_filepath = UPLOADS_ANALYSIS / saved_filename

    with open(saved_filepath, "wb") as f:
        f.write(content)

    doc_hash = compute_sha256(saved_filepath)

    # Execute Multi-Format Signature Detection & Extraction Engine
    extraction_res = extract_multiformat_signature_info(content, file.filename or "")

    sig_detected = extraction_res.get("signature_detected", False)
    sig_status = extraction_res.get("signature_status", "EXTRACTION_ERROR")

    raw_text = None
    if fmt in [ContentType.TEXT, ContentType.JSON, ContentType.RAW_TEXT, ContentType.STRUCTURED_MESSAGE]:
        try:
            raw_text = content.decode('utf-8')
        except Exception:
            pass

    analyzed_doc = AnalyzedDocument(
        analysis_id=generate_analysis_id(),
        analyst_user_id=analyst.user_id,
        original_file_name=file.filename or "analysis_input.txt",
        stored_file_name=saved_filename,
        file_path=str(saved_filepath),
        uploaded_file=str(saved_filepath),
        content_type=fmt,
        file_type="PDF" if fmt == ContentType.PDF else ("JSON" if fmt == ContentType.JSON else "TXT"),
        raw_text_content=raw_text,
        file_size=len(content),
        document_hash=doc_hash,
        canonical_hash=doc_hash,
        signature_present=sig_detected,
        signature_status=sig_status
    )
    db.add(analyzed_doc)
    db.commit()
    db.refresh(analyzed_doc)

    # 7. Save ExtractedSignatureMetadata Record
    extracted_meta = ExtractedSignatureMetadata(
        analysis_document_id=analyzed_doc.analysis_document_id,
        signature_detected=sig_detected,
        signature_status=sig_status,
        signature_algorithm=extraction_res.get("signature_algorithm", "Not Available"),
        hash_algorithm=extraction_res.get("hash_algorithm", "Not Available"),
        signature_fingerprint=extraction_res.get("signature_fingerprint", "Not Available"),
        field_name=extraction_res.get("field_name", "Not Available"),
        signing_time=extraction_res.get("signing_time", None),
        certificate_subject=extraction_res.get("certificate_subject", "Not Available"),
        certificate_issuer=extraction_res.get("certificate_issuer", "Not Available"),
        certificate_serial_number=extraction_res.get("certificate_serial_number", "Not Available"),
        validity_start=extraction_res.get("validity_start", None),
        validity_end=extraction_res.get("validity_end", None),
        certificate_fingerprint=extraction_res.get("certificate_fingerprint", "Not Available"),
        public_key_algorithm=extraction_res.get("public_key_algorithm", "Not Available"),
        public_key_size=extraction_res.get("public_key_size", 0),
        signer_name=extraction_res.get("signer_name", "Not Available"),
        signer_organization=extraction_res.get("signer_organization", "Not Available")
    )
    db.add(extracted_meta)

    sig_fp = extraction_res.get("signature_fingerprint")
    analyzed_doc.signature_id = (sig_fp[:16] if sig_fp and sig_fp != "Not Available" else f"SIG-{analyzed_doc.analysis_document_id:04d}") if sig_detected else None
    db.commit()
    db.refresh(analyzed_doc)

    # 8. Audit Logging
    audit1 = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="ANALYSIS_DOCUMENT_UPLOAD",
        details=f"Uploaded signed PDF for analysis: {file.filename} ({len(content)} bytes)"
    )
    audit2 = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="SIGNATURE_DETECTION_COMPLETED",
        details=f"Completed signature detection for analysis #{analyzed_doc.analysis_document_id}. Status: {sig_status}"
    )
    db.add_all([audit1, audit2])
    db.commit()

    return analyzed_doc

@router.post("/analysis/{analysis_id}/verify", response_model=AnalysisDocumentResponse)
def trigger_signature_verification(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    file_path = Path(doc.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis PDF file missing on server storage")

    audit_start = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="SIGNATURE_VERIFICATION_STARTED",
        details=f"Started cryptographic verification for document #{analysis_id} ({doc.original_file_name})"
    )
    db.add(audit_start)
    db.commit()

    db.query(SignatureVerification).filter(SignatureVerification.analysis_document_id == analysis_id).delete()
    db.commit()

    with open(file_path, "rb") as f:
        content_bytes = f.read()
    verif_results = verify_multiformat_signature(content_bytes, doc.original_file_name)

    for v_res in verif_results:
        db_v = SignatureVerification(
            analysis_document_id=doc.analysis_document_id,
            signature_identifier=v_res.get("signature_identifier", "Signature1"),
            signature_index=v_res.get("signature_index", 0),
            verification_status=v_res["verification_status"],
            integrity_status=v_res["integrity_status"],
            signature_algorithm=v_res["signature_algorithm"],
            hash_algorithm=v_res["hash_algorithm"],
            certificate_time_status=v_res["certificate_time_status"],
            verification_timestamp=v_res.get("verification_timestamp", datetime.now(timezone.utc)),
            verification_details=v_res["verification_details"],
            error_details=v_res.get("error_details", None)
        )
        db.add(db_v)

        v_action = "SIGNATURE_VALID" if v_res["verification_status"] == "VALID" else (
            "SIGNATURE_INVALID" if v_res["verification_status"] == "INVALID" else "SIGNATURE_UNSUPPORTED"
        )
        i_action = "DOCUMENT_INTEGRITY_INTACT" if v_res["integrity_status"] == "INTACT" else "DOCUMENT_MODIFICATION_DETECTED"
        
        db.add_all([
            AuditLog(user_id=analyst.user_id, user_email=analyst.email, action=v_action, details=f"Verification status: {v_res['verification_status']}"),
            AuditLog(user_id=analyst.user_id, user_email=analyst.email, action=i_action, details=f"Integrity status: {v_res['integrity_status']}")
        ])

    audit_comp = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="SIGNATURE_VERIFICATION_COMPLETED",
        details=f"Completed verification for analysis #{analysis_id}."
    )
    db.add(audit_comp)

    # Log VerificationActivity (action=VERIFY)
    v_success = any(v.get("verification_status") == "VALID" and v.get("integrity_status") == "INTACT" for v in verif_results) if verif_results else False
    db.add(VerificationActivity(
        user_id=analyst.user_id,
        analysis_document_id=doc.analysis_document_id,
        document_hash=doc.document_hash,
        action="VERIFY",
        result="SUCCESS" if v_success else "FAIL",
        source_identifier=f"analyst_{analyst.user_id}"
    ))
    db.commit()

    db.refresh(doc)
    return doc

@router.post("/analysis/{analysis_id}/quantum-analysis", response_model=AnalysisDocumentResponse)
def run_quantum_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    # Prepare extraction metadata dict & verifications list
    meta_dict = None
    if doc.extracted_metadata:
        meta_dict = {
            "signature_detected": doc.extracted_metadata.signature_detected,
            "signature_status": doc.extracted_metadata.signature_status,
            "signature_algorithm": doc.extracted_metadata.signature_algorithm,
            "public_key_size": doc.extracted_metadata.public_key_size
        }

    verif_list = None
    if doc.verifications:
        verif_list = [
            {
                "verification_status": v.verification_status,
                "integrity_status": v.integrity_status,
                "certificate_time_status": v.certificate_time_status
            }
            for v in doc.verifications
        ]

    # Audit Logging for start
    audit_start = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="QUANTUM_ANALYSIS_STARTED",
        details=f"Started Quantum-Inspired Security Analysis for document #{analysis_id}"
    )
    db.add(audit_start)
    db.commit()

    # Execute Deterministic Quantum-Inspired Engine
    q_res = analyze_quantum_security_state(meta_dict, verif_list)

    # Delete previous quantum analysis record if re-running
    db.query(QuantumInspiredAnalysis).filter(QuantumInspiredAnalysis.analysis_document_id == analysis_id).delete()
    db.commit()

    db_q = QuantumInspiredAnalysis(
        analysis_document_id=doc.analysis_document_id,
        security_state_vector=json.dumps(q_res["security_state_vector"]),
        secure_consistency_score=q_res["secure_consistency_score"],
        disturbance_score=q_res["disturbance_score"],
        pauli_x_score=q_res["pauli_x_score"],
        pauli_y_score=q_res["pauli_y_score"],
        pauli_z_score=q_res["pauli_z_score"],
        secure_measurement_score=q_res["secure_measurement_score"],
        suspicious_measurement_score=q_res["suspicious_measurement_score"],
        high_risk_measurement_score=q_res["high_risk_measurement_score"],
        forgery_risk_score=q_res["forgery_risk_score"],
        analysis_confidence_score=q_res["analysis_confidence_score"],
        confidence_level=q_res["confidence_level"],
        final_classification=q_res["final_classification"],
        analysis_version=q_res["analysis_version"],
        state_consistency=q_res.get("state_consistency", 0.0),
        state_disturbance=q_res.get("state_disturbance", 0.0),
        measurement_secure_probability=q_res.get("measurement_secure_probability", 0.0),
        measurement_threat_probability=q_res.get("measurement_threat_probability", 0.0),
        pauli_x_disturbance=q_res.get("pauli_x_disturbance", 0.0),
        pauli_y_disturbance=q_res.get("pauli_y_disturbance", 0.0),
        pauli_z_disturbance=q_res.get("pauli_z_disturbance", 0.0),
        combined_pauli_disturbance=q_res.get("combined_pauli_disturbance", 0.0),
        forgery_risk_estimate=q_res.get("forgery_risk_estimate", 0.0),
        quantum_analysis_version=q_res.get("quantum_analysis_version", "QIA-2.0"),
        explanation_json=q_res.get("explanation_json", None)
    )
    db.add(db_q)

    # Detailed Audit Trail Logging
    db.add_all([
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="SECURITY_STATE_CONSTRUCTED", details=f"State vector: {q_res['security_state_vector']}"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="DISTURBANCE_ANALYSIS_COMPLETED", details=f"Disturbance score D={q_res['disturbance_score']}"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="PAULI_ANALYSIS_COMPLETED", details=f"Pauli X={q_res['pauli_x_score']}%, Y={q_res['pauli_y_score']}%, Z={q_res['pauli_z_score']}%"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="MEASUREMENT_ANALYSIS_COMPLETED", details=f"Projections: Secure={q_res['secure_measurement_score']}%, Suspicious={q_res['suspicious_measurement_score']}%, HighRisk={q_res['high_risk_measurement_score']}%"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="FORGERY_RISK_CALCULATED", details=f"Forgery Risk Score: {q_res['forgery_risk_score']}/100"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="QUANTUM_ANALYSIS_COMPLETED", details=f"Completed Quantum-Inspired Analysis #{analysis_id}. Final Classification: {q_res['final_classification']}")
    ])
    db.commit()

    db.refresh(doc)
    return doc

@router.get("/analysis-history", response_model=List[AnalysisDocumentResponse])
def get_analysis_history(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    docs = db.query(AnalyzedDocument).order_by(AnalyzedDocument.created_at.desc()).all()
    return docs

@router.get("/analysis/{analysis_id}", response_model=AnalysisDocumentResponse)
def get_analysis_details(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")
    return doc

@router.get("/analysis/{analysis_id}/verifications", response_model=List[SignatureVerificationResponse])
def get_analysis_verifications(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    verifs = db.query(SignatureVerification).filter(SignatureVerification.analysis_document_id == analysis_id).all()
    return verifs

@router.get("/analysis/{analysis_id}/quantum-analysis", response_model=QuantumAnalysisResponse)
def get_quantum_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    q_rec = db.query(QuantumInspiredAnalysis).filter(QuantumInspiredAnalysis.analysis_document_id == analysis_id).first()
    if not q_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Quantum analysis not performed for this document yet.")
    return q_rec

@router.get("/analysis/{analysis_id}/analysis-explanation", response_model=AnalysisExplanationResponse)
def get_analysis_explanation(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    meta_dict = None
    if doc.extracted_metadata:
        meta_dict = {
            "signature_detected": doc.extracted_metadata.signature_detected,
            "signature_status": doc.extracted_metadata.signature_status,
            "signature_algorithm": doc.extracted_metadata.signature_algorithm,
            "public_key_size": doc.extracted_metadata.public_key_size
        }

    verif_list = None
    if doc.verifications:
        verif_list = [
            {
                "verification_status": v.verification_status,
                "integrity_status": v.integrity_status,
                "certificate_time_status": v.certificate_time_status
            }
            for v in doc.verifications
        ]

    q_res = analyze_quantum_security_state(meta_dict, verif_list)
    exp = q_res["explanation"]

    return AnalysisExplanationResponse(
        analysis_id=doc.analysis_document_id,
        document_id=doc.analysis_document_id,
        final_classification=q_res["final_classification"],
        forgery_risk_score=q_res["forgery_risk_score"],
        confidence_level=q_res["confidence_level"],
        step1_feature_mapping=exp["step1_feature_mapping"],
        step2_state_vector=exp["step2_state_vector"],
        step3_pauli_analysis=exp["step3_pauli_analysis"],
        step4_measurement=exp["step4_measurement"],
        step5_decision=exp["step5_decision"]
    )

@router.post("/analysis/{analysis_id}/threat-detection", response_model=AnalysisDocumentResponse)
def trigger_threat_detection(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    incidents = evaluate_and_generate_threats(db, analysis_id)

    db.add(AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="THREAT_DETECTION_COMPLETED",
        details=f"Evaluated historical threats for document #{analysis_id}. Incidents generated: {len(incidents)}"
    ))
    db.commit()

    db.refresh(doc)
    return doc

@router.get("/analysis/{analysis_id}/threat-incidents", response_model=List[ThreatIncidentResponse])
def get_document_threat_incidents(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")
    return doc.threat_incidents or []

@router.get("/threat-incidents", response_model=List[ThreatIncidentResponse])
def get_all_threat_incidents(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    threat_status: Optional[str] = None,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    query = db.query(ThreatIncident)
    if category:
        query = query.filter(ThreatIncident.threat_category == category)
    if severity:
        query = query.filter(ThreatIncident.severity == severity)
    if threat_status:
        query = query.filter(ThreatIncident.threat_status == threat_status)

    incidents = query.order_by(ThreatIncident.detected_at.desc()).all()
    return incidents

@router.put("/threat-incidents/{incident_id}/status", response_model=ThreatIncidentResponse)
def update_threat_incident_status(
    incident_id: int,
    status_update: ThreatIncidentUpdateStatus,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if status_update.threat_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid threat status. Must be one of {valid_statuses}")

    incident = db.query(ThreatIncident).filter(ThreatIncident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Threat incident not found")

    incident.threat_status = status_update.threat_status
    db.add(AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="THREAT_INCIDENT_STATUS_UPDATED",
        details=f"Updated Threat Incident #{incident_id} status to '{status_update.threat_status}'"
    ))
    db.commit()
    db.refresh(incident)
    return incident

@router.get("/activity-stats", response_model=ActivityStatsResponse)
def get_platform_activity_stats(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    stats = calculate_activity_statistics(db)
    return stats

@router.post("/analysis/{analysis_id}/certificate-validation", response_model=AnalysisDocumentResponse)
def trigger_certificate_validation(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    audit_start = AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="CERTIFICATE_VALIDATION_STARTED",
        details=f"Started certificate security validation for document #{analysis_id}"
    )
    db.add(audit_start)
    db.commit()

    cert_res = validate_document_certificate_security(db, analysis_id)

    db.add_all([
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="CERTIFICATE_TRUST_EVALUATED", details=f"Trust status: {cert_res.get('trust_status')}"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="REVOCATION_CHECK_COMPLETED", details=f"Revocation status: {cert_res.get('revocation_status')}"),
        AuditLog(user_id=analyst.user_id, user_email=analyst.email, action="CERTIFICATE_VALIDATION_COMPLETED", details=f"Certificate Security Score: {cert_res.get('certificate_security_score')}/100")
    ])
    db.commit()

    db.refresh(doc)
    return doc

@router.get("/analysis/{analysis_id}/certificate-analysis", response_model=CertificateAnalysisResponse)
def get_certificate_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    cert_rec = db.query(CertificateSecurityAnalysis).filter(CertificateSecurityAnalysis.analysis_document_id == analysis_id).first()
    if not cert_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate validation has not been performed for this document yet.")
    return cert_rec

@router.post("/analysis/{analysis_id}/final-decision", response_model=FinalDecisionResponse)
def generate_final_security_decision(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found")

    decision_res = synthesize_final_security_report(
        db=db,
        doc=doc,
        analyst_name=analyst.full_name or analyst.email
    )

    db.add(AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="FINAL_SECURITY_REPORT_GENERATED",
        details=f"Synthesized 5-layer final decision '{decision_res['final_security_decision']}' with overall risk score {decision_res['overall_risk_score']}/100"
    ))
    db.commit()

    return FinalDecisionResponse(
        analysis_document_id=doc.analysis_document_id,
        final_security_decision=decision_res["final_security_decision"],
        overall_risk_score=decision_res["overall_risk_score"],
        summary_justification=decision_res["summary_justification"],
        recommended_action=decision_res["recommended_action"],
        layer1_signature_status=decision_res["layer1_signature_status"],
        layer2_integrity_status=decision_res["layer2_integrity_status"],
        layer3_certificate_status=decision_res["layer3_certificate_status"],
        layer4_quantum_status=decision_res["layer4_quantum_status"],
        layer5_threat_status=decision_res["layer5_threat_status"]
    )

@router.get("/analysis/{analysis_id}/security-report", response_model=SecurityReportResponse)
def get_security_report(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    report_rec = db.query(SecurityReport).filter(SecurityReport.analysis_document_id == analysis_id).first()
    if not report_rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Final security report has not been generated for this document yet.")
    return report_rec

@router.get("/reports/{analysis_id}/download-pdf")
def download_security_report_pdf(
    analysis_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    report_rec = db.query(SecurityReport).filter(SecurityReport.analysis_document_id == analysis_id).first()
    if not report_rec or not Path(report_rec.report_path).exists():
        doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
        if not doc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis document not found.")
        synthesize_final_security_report(db=db, doc=doc, analyst_name=analyst.full_name or analyst.email)
        report_rec = db.query(SecurityReport).filter(SecurityReport.analysis_document_id == analysis_id).first()
        if not report_rec or not Path(report_rec.report_path).exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Failed to locate or generate security report PDF.")

    db.add(AuditLog(
        user_id=analyst.user_id,
        user_email=analyst.email,
        action="SECURITY_REPORT_DOWNLOADED",
        details=f"Downloaded security PDF report for document #{analysis_id}. Report Hash: {report_rec.report_hash[:16]}..."
    ))
    db.commit()

    return FileResponse(
        path=report_rec.report_path,
        filename=f"Q-SHIELD_Security_Report_{analysis_id}.pdf",
        media_type="application/pdf"
    )

@router.post("/analyze-multiformat", response_model=AnalysisDocumentResponse)
def analyze_multiformat_input(
    req: MultiFormatAnalysisRequest,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    if not req.content_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Content text is required.")

    content_bytes = req.content_text.encode('utf-8')
    fmt = detect_content_format(content_bytes, req.filename or "input_content.txt")

    file_id = str(uuid.uuid4())[:8]
    safe_name = Path(req.filename or "input_content.txt").name.replace(" ", "_")
    saved_filename = f"analysis_{analyst.user_id}_{file_id}_{safe_name}"
    saved_filepath = UPLOADS_ANALYSIS / saved_filename

    with open(saved_filepath, "wb") as f:
        f.write(content_bytes)

    import hashlib
    doc_hash = hashlib.sha256(content_bytes).hexdigest()

    extraction_res = extract_multiformat_signature_info(
        content_bytes,
        req.filename or "",
        signature_detached_bytes=req.signature_text.encode('utf-8') if req.signature_text else None
    )

    sig_detected = extraction_res.get("signature_detected", False)
    sig_status = extraction_res.get("signature_status", "EXTRACTION_ERROR")

    analyzed_doc = AnalyzedDocument(
        analyst_user_id=analyst.user_id,
        original_file_name=req.filename or "input_content.txt",
        stored_file_name=saved_filename,
        file_path=str(saved_filepath),
        content_type=fmt,
        raw_text_content=req.content_text,
        file_size=len(content_bytes),
        document_hash=doc_hash,
        signature_present=sig_detected,
        signature_status=sig_status
    )
    db.add(analyzed_doc)
    db.commit()
    db.refresh(analyzed_doc)

    extracted_meta = ExtractedSignatureMetadata(
        analysis_document_id=analyzed_doc.analysis_document_id,
        signature_detected=sig_detected,
        signature_status=sig_status,
        signature_algorithm=extraction_res.get("signature_algorithm", "RSA-SHA256"),
        hash_algorithm=extraction_res.get("hash_algorithm", "SHA-256"),
        signature_fingerprint=extraction_res.get("signature_fingerprint", "Not Available"),
        field_name=extraction_res.get("field_name", "Signature1"),
        signing_time=extraction_res.get("signing_time", datetime.now(timezone.utc)),
        certificate_subject=extraction_res.get("certificate_subject", "Not Available"),
        certificate_issuer=extraction_res.get("certificate_issuer", "Not Available"),
        certificate_serial_number=extraction_res.get("certificate_serial_number", "Not Available"),
        certificate_fingerprint=extraction_res.get("certificate_fingerprint", "Not Available"),
        public_key_algorithm=extraction_res.get("public_key_algorithm", "RSA"),
        public_key_size=extraction_res.get("public_key_size", 2048),
        signer_name=extraction_res.get("signer_name", "Not Available"),
        signer_organization=extraction_res.get("signer_organization", "Not Available")
    )
    db.add(extracted_meta)

    verif_results = verify_multiformat_signature(content_bytes, req.filename or "", signature_input=req.signature_text)
    for v_res in verif_results:
        db_v = SignatureVerification(
            analysis_document_id=analyzed_doc.analysis_document_id,
            signature_identifier=v_res.get("signature_identifier", "Signature1"),
            signature_index=v_res.get("signature_index", 0),
            verification_status=v_res["verification_status"],
            integrity_status=v_res["integrity_status"],
            signature_algorithm=v_res["signature_algorithm"],
            hash_algorithm=v_res["hash_algorithm"],
            certificate_time_status=v_res["certificate_time_status"],
            verification_timestamp=v_res.get("verification_timestamp", datetime.now(timezone.utc)),
            verification_details=v_res["verification_details"],
            error_details=v_res.get("error_details", None)
        )
        db.add(db_v)

    db.commit()

    meta_dict = {"signature_detected": sig_detected, "signature_status": sig_status, "signature_algorithm": "RSA-SHA256", "public_key_size": 2048}
    verif_list = [{"verification_status": v["verification_status"], "integrity_status": v["integrity_status"], "certificate_time_status": v["certificate_time_status"]} for v in verif_results]
    q_res = analyze_quantum_security_state(meta_dict, verif_list)

    db_q = QuantumInspiredAnalysis(
        analysis_document_id=analyzed_doc.analysis_document_id,
        security_state_vector=json.dumps(q_res["security_state_vector"]),
        secure_consistency_score=q_res["secure_consistency_score"],
        disturbance_score=q_res["disturbance_score"],
        pauli_x_score=q_res["pauli_x_score"],
        pauli_y_score=q_res["pauli_y_score"],
        pauli_z_score=q_res["pauli_z_score"],
        secure_measurement_score=q_res["secure_measurement_score"],
        suspicious_measurement_score=q_res["suspicious_measurement_score"],
        high_risk_measurement_score=q_res["high_risk_measurement_score"],
        forgery_risk_score=q_res["forgery_risk_score"],
        analysis_confidence_score=q_res["analysis_confidence_score"],
        confidence_level=q_res["confidence_level"],
        final_classification=q_res["final_classification"],
        analysis_version="QIA-1.0",
        state_consistency=q_res.get("state_consistency", 0.0),
        state_disturbance=q_res.get("state_disturbance", 0.0),
        measurement_secure_probability=q_res.get("measurement_secure_probability", 0.0),
        measurement_threat_probability=q_res.get("measurement_threat_probability", 0.0),
        pauli_x_disturbance=q_res.get("pauli_x_disturbance", 0.0),
        pauli_y_disturbance=q_res.get("pauli_y_disturbance", 0.0),
        pauli_z_disturbance=q_res.get("pauli_z_disturbance", 0.0),
        combined_pauli_disturbance=q_res.get("combined_pauli_disturbance", 0.0),
        forgery_risk_estimate=q_res.get("forgery_risk_estimate", 0.0),
        quantum_analysis_version=q_res.get("quantum_analysis_version", "QIA-2.0"),
        explanation_json=q_res.get("explanation_json", None)
    )
    db.add(db_q)
    db.commit()

    evaluate_and_generate_threats(db=db, analysis_document_id=analyzed_doc.analysis_document_id)
    validate_document_certificate_security(db=db, analysis_id=analyzed_doc.analysis_document_id)
    synthesize_final_security_report(db=db, doc=analyzed_doc, analyst_name=analyst.full_name or analyst.email)

    db.refresh(analyzed_doc)
    return analyzed_doc
