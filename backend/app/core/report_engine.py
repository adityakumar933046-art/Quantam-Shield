import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

from app.core.config import UPLOADS_DIR
from app.models import (
    AnalyzedDocument,
    ExtractedSignatureMetadata,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    CertificateSecurityAnalysis,
    SecurityReport,
    AuditLog
)
from app.core.audit_engine import sanitize_sensitive_data

REPORTS_DIR = Path(UPLOADS_DIR) / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def compute_file_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def synthesize_final_security_decision(
    doc: AnalyzedDocument,
    verifs: List[SignatureVerification],
    quantum: Optional[QuantumInspiredAnalysis],
    cert_analysis: Optional[CertificateSecurityAnalysis],
    threats: List[ThreatIncident]
) -> Dict[str, Any]:
    """
    100% Deterministic 5-Layer Final Security Decision Engine.
    Combines:
    Layer 1: Cryptographic Signature Verification
    Layer 2: Document Integrity Verification
    Layer 3: Certificate Security & Trust Status
    Layer 4: Quantum-Inspired Security Analysis
    Layer 5: Historical Activity & Threat Analysis
    """
    # Layer 1: Cryptographic Signature Status
    v_status = "UNKNOWN"
    if verifs:
        v_status = verifs[0].verification_status
    elif not doc.signature_present:
        v_status = "NO_SIGNATURE"

    # Layer 2: Document Integrity Status
    i_status = "UNKNOWN"
    if verifs:
        i_status = verifs[0].integrity_status

    # Layer 3: Certificate Security Status
    c_status = cert_analysis.trust_status if cert_analysis else "UNKNOWN"
    c_time = cert_analysis.time_validity_status if cert_analysis else "UNKNOWN"

    # Layer 4: Quantum-Inspired Status
    q_status = quantum.final_classification if quantum else "UNKNOWN"
    forgery_risk = quantum.forgery_risk_score if quantum else 0.0

    # Layer 5: Historical Threat Status
    has_threat = len(threats) > 0
    max_threat_severity = "NONE"
    if threats:
        severities = [t.severity for t in threats]
        if "CRITICAL" in severities: max_threat_severity = "CRITICAL"
        elif "HIGH" in severities: max_threat_severity = "HIGH"
        elif "MEDIUM" in severities: max_threat_severity = "MEDIUM"
        else: max_threat_severity = "LOW"

    # Deterministic Decision Rule Classification
    reasons = []

    if not doc.signature_present or v_status == "NO_SIGNATURE":
        final_decision = "INSUFFICIENT_EVIDENCE"
        overall_risk_score = 50.0
        reasons.append("No digital signature extracted. Additional signature data required.")
        rec_action = "Additional certificate or signature data is required for a conclusive security assessment."

    elif v_status in ["INVALID", "MALFORMED"] or i_status == "MODIFIED" or q_status == "HIGH_RISK" or max_threat_severity in ["CRITICAL", "HIGH"]:
        final_decision = "HIGH_RISK"
        overall_risk_score = max(75.0, forgery_risk)
        if v_status == "INVALID":
            reasons.append("Cryptographic RSA/SHA signature mathematical verification FAILED.")
        if i_status == "MODIFIED":
            reasons.append("PDF ByteRange document content modification detected after signing.")
        if q_status == "HIGH_RISK":
            reasons.append("Quantum-Inspired analysis identified severe state disturbance D in feature space.")
        if max_threat_severity in ["CRITICAL", "HIGH"]:
            reasons.append(f"Historical threat detection triggered {max_threat_severity} severity incident.")
        rec_action = "Do not rely on this document. Digital signature verification failed or post-signature document modification was detected."

    elif q_status == "SUSPICIOUS" or max_threat_severity == "MEDIUM" or c_status == "UNTRUSTED" and c_time == "EXPIRED":
        final_decision = "SUSPICIOUS"
        overall_risk_score = max(45.0, forgery_risk)
        if q_status == "SUSPICIOUS":
            reasons.append("Quantum-Inspired analysis detected state disturbance anomalies.")
        if max_threat_severity == "MEDIUM":
            reasons.append("Historical activity analysis detected suspicious repeated activity.")
        if c_status == "UNTRUSTED":
            reasons.append("Certificate issuer is not in configured trusted root CA store.")
        rec_action = "Review document activity history, upload frequency, and certificate identity parameters before relying on document contents."

    elif c_status in ["UNTRUSTED", "SELF_SIGNED"] or c_time == "EXPIRED" or (cert_analysis and cert_analysis.revocation_status == "NOT_AVAILABLE"):
        final_decision = "REQUIRES_CAUTION"
        overall_risk_score = 25.0
        reasons.append("Cryptographic signature verification succeeded and document content integrity is INTACT.")
        if c_status in ["UNTRUSTED", "SELF_SIGNED"]:
            reasons.append(f"However, certificate trust status is '{c_status}' (not in corporate root CA store).")
        if c_time == "EXPIRED":
            reasons.append("Certificate validity date range has EXPIRED.")
        if cert_analysis and cert_analysis.revocation_status == "NOT_AVAILABLE":
            reasons.append("Certificate revocation status could not be verified in offline localhost environment.")
        rec_action = "Verify certificate trust through the relevant trusted CA or organizational trust policy."

    else:
        final_decision = "SECURE"
        overall_risk_score = 0.0
        reasons.append("Cryptographic signature is VALID and document content integrity is INTACT.")
        reasons.append(f"Certificate trust status is '{c_status}' and Quantum-Inspired analysis confirms SECURE state.")
        rec_action = "No immediate security anomaly requiring action was detected."

    justification_str = " ".join(reasons)

    return {
        "final_security_decision": final_decision,
        "overall_risk_score": overall_risk_score,
        "summary_justification": justification_str,
        "recommended_action": rec_action,
        "layer1_signature_status": v_status,
        "layer2_integrity_status": i_status,
        "layer3_certificate_status": c_status,
        "layer4_quantum_status": q_status,
        "layer5_threat_status": max_threat_severity if has_threat else "NORMAL"
    }


def generate_pdf_security_report(
    db: Session,
    analysis_id: int,
    analyst_name: str = "Security Analyst"
) -> SecurityReport:
    """
    Generates an official, comprehensive PDF Security Report using ReportLab.
    Computes report SHA-256 hash and stores SecurityReport record in DB.
    """
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise ValueError(f"Analysis document #{analysis_id} not found")

    meta = doc.extracted_metadata
    verifs = doc.verifications or []
    quantum = doc.quantum_analysis
    cert_analysis = doc.certificate_analysis
    threats = doc.threat_incidents or []

    # Synthesize decision
    dec = synthesize_final_security_decision(doc, verifs, quantum, cert_analysis, threats)

    # PDF Output File Setup
    pdf_filename = f"Q-SHIELD_Security_Report_Doc{doc.analysis_document_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = REPORTS_DIR / pdf_filename

    # Create ReportLab Document
    pdf_doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Report Typography Styles
    title_style = ParagraphStyle('ReportTitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=22, leading=26, textColor=colors.HexColor('#0F172A'))
    subtitle_style = ParagraphStyle('ReportSubtitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=colors.HexColor('#0284C7'))
    h2_style = ParagraphStyle('SectionHeader', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=13, leading=17, textColor=colors.HexColor('#0F172A'), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle('ReportBody', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#334155'))
    body_bold = ParagraphStyle('ReportBodyBold', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, leading=13, textColor=colors.HexColor('#0F172A'))
    mono_style = ParagraphStyle('ReportMono', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=11, textColor=colors.HexColor('#1E293B'))
    decision_style = ParagraphStyle('DecisionStyle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=14, leading=18, textColor=colors.HexColor('#FFFFFF'), alignment=TA_CENTER)

    story = []

    # HEADER BANNER
    header_data = [
        [
            Paragraph("<b>Q-SHIELD SECURITY PLATFORM</b><br/><font size=9 color='#64748B'>Digital Signature Security & Quantum-Inspired Analysis</font>", body_style),
            Paragraph(f"<b>REPORT VERSION:</b> QSR-1.0<br/><b>DATE:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", ParagraphStyle('HeadRight', parent=body_style, alignment=TA_RIGHT))
        ]
    ]
    header_table = Table(header_data, colWidths=[300, 240])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=4, spaceAfter=12))

    # REPORT TITLE
    story.append(Paragraph("COMPREHENSIVE DIGITAL SIGNATURE SECURITY REPORT", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Document: <b>{doc.original_file_name}</b> (Analysis Record #{doc.analysis_document_id})", subtitle_style))
    story.append(Spacer(1, 10))

    # SECTION 1: EXECUTIVE SUMMARY & FINAL SECURITY DECISION BANNER
    story.append(Paragraph("1. EXECUTIVE SUMMARY & FINAL DECISION", h2_style))

    # Decision Banner Color
    dec_color = "#059669" if dec["final_security_decision"] == "SECURE" else (
        "#D97706" if dec["final_security_decision"] == "REQUIRES_CAUTION" else (
            "#DC2626" if dec["final_security_decision"] == "HIGH_RISK" else "#475569"
        )
    )

    dec_banner_data = [
        [Paragraph(f"FINAL SECURITY DECISION: {dec['final_security_decision']}", decision_style)]
    ]
    dec_table = Table(dec_banner_data, colWidths=[540])
    dec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(dec_color)),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ]))
    story.append(dec_table)
    story.append(Spacer(1, 8))

    summary_data = [
        [Paragraph("<b>Document SHA-256 Digest:</b>", body_bold), Paragraph(doc.document_hash, mono_style)],
        [Paragraph("<b>Inspected File Size:</b>", body_bold), Paragraph(f"{doc.file_size} bytes ({(doc.file_size/1024):.1f} KB)", body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_bold), Paragraph(f"<b>{dec['overall_risk_score']:.1f} / 100</b>", body_style)],
        [Paragraph("<b>Decision Justification:</b>", body_bold), Paragraph(dec['summary_justification'], body_style)],
        [Paragraph("<b>Recommended Action:</b>", body_bold), Paragraph(dec['recommended_action'], body_style)],
    ]
    sum_table = Table(summary_data, colWidths=[140, 400])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 10))

    # SECTION 2: DIGITAL SIGNATURE VERIFICATION
    story.append(Paragraph("2. DIGITAL SIGNATURE VERIFICATION", h2_style))
    v_data = [
        [Paragraph("<b>Signature Field</b>", body_bold), Paragraph("<b>Status</b>", body_bold), Paragraph("<b>Signature Algorithm</b>", body_bold), Paragraph("<b>Hash Algorithm</b>", body_bold)]
    ]
    if verifs:
        for v in verifs:
            v_data.append([
                Paragraph(v.signature_identifier, body_style),
                Paragraph(f"<b>{v.verification_status}</b>", body_style),
                Paragraph(v.signature_algorithm, mono_style),
                Paragraph(v.hash_algorithm, mono_style)
            ])
    else:
        v_data.append([Paragraph("No verifications recorded", body_style), Paragraph(doc.signature_status, body_style), Paragraph("N/A", body_style), Paragraph("N/A", body_style)])

    v_table = Table(v_data, colWidths=[130, 130, 140, 140])
    v_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(v_table)
    story.append(Spacer(1, 10))

    # SECTION 3: DOCUMENT INTEGRITY CHECK
    story.append(Paragraph("3. DOCUMENT CONTENT INTEGRITY EVALUATION", h2_style))
    i_val = verifs[0].integrity_status if verifs else "UNKNOWN"
    i_details = verifs[0].verification_details if verifs else "No verification run."

    integ_data = [
        [Paragraph("<b>ByteRange Integrity Status:</b>", body_bold), Paragraph(f"<b>{i_val}</b>", body_style)],
        [Paragraph("<b>Integrity Evaluation Details:</b>", body_bold), Paragraph(i_details, body_style)]
    ]
    integ_table = Table(integ_data, colWidths=[160, 380])
    integ_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(integ_table)
    story.append(Spacer(1, 10))

    # SECTION 4: CERTIFICATE SECURITY & TRUST CHAIN
    story.append(Paragraph("4. X.509 CERTIFICATE SECURITY & TRUST EVALUATION", h2_style))
    cert_data = [
        [Paragraph("<b>Subject DN:</b>", body_bold), Paragraph(meta.certificate_subject if meta else "N/A", body_style)],
        [Paragraph("<b>Issuer CA:</b>", body_bold), Paragraph(meta.certificate_issuer if meta else "N/A", body_style)],
        [Paragraph("<b>Serial Number:</b>", body_bold), Paragraph(meta.certificate_serial_number if meta else "N/A", mono_style)],
        [Paragraph("<b>Structure Status:</b>", body_bold), Paragraph(cert_analysis.structure_status if cert_analysis else "N/A", body_style)],
        [Paragraph("<b>Time Validity Status:</b>", body_bold), Paragraph(cert_analysis.time_validity_status if cert_analysis else "N/A", body_style)],
        [Paragraph("<b>Trust Store Status:</b>", body_bold), Paragraph(f"<b>{cert_analysis.trust_status if cert_analysis else 'N/A'}</b>", body_style)],
        [Paragraph("<b>Revocation Status (OCSP/CRL):</b>", body_bold), Paragraph(cert_analysis.revocation_status if cert_analysis else "NOT_AVAILABLE", body_style)],
        [Paragraph("<b>Certificate Security Score:</b>", body_bold), Paragraph(f"{cert_analysis.certificate_security_score if cert_analysis else 0.0} / 100", body_style)],
    ]
    c_table = Table(cert_data, colWidths=[180, 360])
    c_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(c_table)
    story.append(Spacer(1, 10))

    # SECTION 5: QUANTUM-INSPIRED ANALYSIS
    story.append(Paragraph("5. QUANTUM-INSPIRED SECURITY ANALYSIS", h2_style))
    q_data_table = [
        [Paragraph("<b>Feature Vector S = [V, I, C, E, A]:</b>", body_bold), Paragraph(str(quantum.security_state_vector if quantum else "N/A"), mono_style)],
        [Paragraph("<b>Euclidean Disturbance (D):</b>", body_bold), Paragraph(f"{quantum.disturbance_score if quantum else 0.0:.4f}", body_style)],
        [Paragraph("<b>Pauli X (Bit Flip Anomaly):</b>", body_bold), Paragraph(f"{quantum.pauli_x_score if quantum else 0.0}%", body_style)],
        [Paragraph("<b>Pauli Z (Phase Anomaly):</b>", body_bold), Paragraph(f"{quantum.pauli_z_score if quantum else 0.0}%", body_style)],
        [Paragraph("<b>P(Secure Subspace):</b>", body_bold), Paragraph(f"{quantum.secure_measurement_score if quantum else 0.0}%", body_style)],
        [Paragraph("<b>Forgery Risk Score:</b>", body_bold), Paragraph(f"<b>{quantum.forgery_risk_score if quantum else 0.0:.1f} / 100</b>", body_style)],
        [Paragraph("<b>Quantum Classification:</b>", body_bold), Paragraph(f"<b>{quantum.final_classification if quantum else 'N/A'}</b>", body_style)],
    ]
    q_table = Table(q_data_table, colWidths=[180, 360])
    q_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(q_table)
    story.append(Spacer(1, 10))

    # SECTION 6 & 7: THREAT INCIDENTS & ACTIVITY FINDINGS
    story.append(Paragraph("6. THREAT FINDINGS & REPLAY ANALYSIS", h2_style))
    if threats:
        t_rows = [[Paragraph("<b>Category</b>", body_bold), Paragraph("<b>Severity</b>", body_bold), Paragraph("<b>Score</b>", body_bold), Paragraph("<b>Description</b>", body_bold)]]
        for t in threats:
            t_rows.append([
                Paragraph(t.threat_category.replace('_', ' '), body_style),
                Paragraph(f"<b>{t.severity}</b>", body_style),
                Paragraph(f"{t.threat_score:.1f}", body_style),
                Paragraph(t.description, body_style)
            ])
        t_table = Table(t_rows, colWidths=[130, 70, 50, 290])
        t_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#FEE2E2')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#FCA5A5')),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_table)
    else:
        story.append(Paragraph("No threat incidents or suspicious replay activity detected for this document.", body_style))

    story.append(Spacer(1, 15))

    # REPORT INTEGRITY & SIGNATURE SEAL
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceBefore=8, spaceAfter=8))
    
    # Save Report PDF file
    pdf_doc.build(story)

    # Calculate SHA-256 hash of generated report file
    report_hash = compute_file_sha256(pdf_path)

    # Save or update SecurityReport record in DB
    existing_rep = db.query(SecurityReport).filter(
        SecurityReport.analysis_document_id == doc.analysis_document_id,
        SecurityReport.report_type == "ANALYSIS_REPORT"
    ).first()

    import uuid
    from app.core.audit_engine import log_audit_event

    ref = existing_rep.report_reference if existing_rep and existing_rep.report_reference else f"QSHIELD-REPORT-{uuid.uuid4().hex[:8].upper()}"
    risk_level = "CRITICAL" if dec["overall_risk_score"] >= 75.0 else ("HIGH" if dec["overall_risk_score"] >= 50.0 else ("MEDIUM" if dec["overall_risk_score"] >= 25.0 else "LOW"))
    summary_text = f"Security analysis report for '{doc.file_name}': Decision {dec['final_security_decision']} with Risk Score {dec['overall_risk_score']:.1f}/100."

    # Build comprehensive analysis report payload with all data layers
    full_report_data = build_analysis_security_report(analysis_id, db, analyst_name)
    full_report_data.update({
        "report_reference": ref,
        "final_security_decision": dec["final_security_decision"],
        "overall_risk_score": dec["overall_risk_score"],
        "summary_justification": dec["summary_justification"],
        "recommended_action": dec["recommended_action"],
        "layer1_signature_status": dec["layer1_signature_status"],
        "layer2_integrity_status": dec["layer2_integrity_status"],
        "layer3_certificate_status": dec["layer3_certificate_status"],
        "layer4_quantum_status": dec["layer4_quantum_status"],
        "layer5_threat_status": dec["layer5_threat_status"]
    })
    serialized_report_data = json.dumps(full_report_data)

    doc_hash_val = doc.document_hash or doc.canonical_hash
    sig_id_val = doc.signature_id or (meta.signature_fingerprint[:16] if meta and meta.signature_fingerprint and meta.signature_fingerprint != "Not Available" else f"SIG-{doc.analysis_document_id:04d}")

    # Also persist decision and risk metrics directly onto AnalyzedDocument
    doc.final_decision = dec["final_security_decision"]
    doc.risk_score = dec["overall_risk_score"]
    doc.risk_level = risk_level
    doc.analysis_summary = dec["summary_justification"]
    if not doc.signature_id and sig_id_val:
        doc.signature_id = sig_id_val
    if not doc.canonical_hash and doc_hash_val:
        doc.canonical_hash = doc_hash_val

    if existing_rep:
        existing_rep.report_reference = ref
        existing_rep.document_name = doc.file_name
        existing_rep.document_hash = doc_hash_val
        existing_rep.signature_id = sig_id_val
        existing_rep.overall_status = dec["final_security_decision"]
        existing_rep.final_security_decision = dec["final_security_decision"]
        existing_rep.risk_score = dec["overall_risk_score"]
        existing_rep.overall_risk_score = dec["overall_risk_score"]
        existing_rep.risk_level = risk_level
        existing_rep.summary = summary_text
        existing_rep.report_data = serialized_report_data
        existing_rep.report_path = str(pdf_path)
        existing_rep.report_hash = report_hash
        existing_rep.report_version = "QSR-2.0"
        existing_rep.generated_by = analyst_name
        existing_rep.generated_at = datetime.now(timezone.utc)
        sec_report = existing_rep
    else:
        sec_report = SecurityReport(
            report_reference=ref,
            report_type="ANALYSIS_REPORT",
            analysis_document_id=doc.analysis_document_id,
            document_name=doc.file_name,
            document_hash=doc_hash_val,
            signature_id=sig_id_val,
            overall_status=dec["final_security_decision"],
            final_security_decision=dec["final_security_decision"],
            risk_score=dec["overall_risk_score"],
            overall_risk_score=dec["overall_risk_score"],
            risk_level=risk_level,
            summary=summary_text,
            report_data=serialized_report_data,
            report_path=str(pdf_path),
            report_hash=report_hash,
            report_version="QSR-2.0",
            generated_by=analyst_name,
            generated_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc)
        )
        db.add(sec_report)

    db.commit()
    db.refresh(sec_report)
    db.refresh(doc)

    log_audit_event(
        db=db,
        action="REPORT_GENERATED",
        user_email=analyst_name,
        user_id=doc.analyst_user_id,
        resource_type="REPORT",
        resource_id=ref,
        result="SUCCESS",
        details=f"Generated report {ref} (Decision: {dec['final_security_decision']}, Risk: {dec['overall_risk_score']:.1f}) for doc #{analysis_id}"
    )

    return sec_report

def synthesize_final_security_report(
    db: Session,
    doc: AnalyzedDocument,
    analyst_name: str = "Security Analyst"
) -> Dict[str, Any]:
    """
    Main entry point for Step 7: synthesizes 5-layer final decision, generates PDF report,
    saves SecurityReport DB record, updates AnalyzedDocument state, and returns full final decision dict.
    """
    # 1. Ensure certificate validation was run if signature present
    if doc.signature_present and not doc.certificate_analysis:
        from app.core.cert_validator import validate_document_certificate_security
        validate_document_certificate_security(db, doc.analysis_document_id)
        db.refresh(doc)

    meta = doc.extracted_metadata
    verifs = doc.verifications or []
    quantum = doc.quantum_analysis
    cert_analysis = doc.certificate_analysis
    threats = doc.threat_incidents or []

    dec = synthesize_final_security_decision(doc, verifs, quantum, cert_analysis, threats)
    
    # Generate PDF & persist SecurityReport
    generate_pdf_security_report(db, doc.analysis_document_id, analyst_name)

    return dec


def generate_report_reference() -> str:
    """Generates a unique report reference: QSHIELD-REPORT-XXXXXXXX."""
    import uuid
    return f"QSHIELD-REPORT-{uuid.uuid4().hex[:8].upper()}"


def build_analysis_security_report(
    analysis_id: int,
    db: Session,
    generated_by: str = "Security Analyst"
) -> Dict[str, Any]:
    """
    Builds a complete, deterministic, real-data Security Analysis Report.
    Includes:
    A. Document Information
    B. Classical Cryptographic Verification
    C. Quantum-Inspired Analysis (Strictly labeled)
    D. Threat Detection (with anomaly consistency)
    E. Final Risk Assessment
    F. Deterministic Recommendations
    G. Unified Analysis Record
    """
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise ValueError(f"Analyzed document #{analysis_id} not found.")

    meta = doc.extracted_metadata
    verifs = doc.verifications or []
    quantum = doc.quantum_analysis
    cert = doc.certificate_analysis
    threats = doc.threat_incidents or []

    v_status = verifs[0].verification_status if verifs else (doc.signature_status if doc.signature_present else "NO_SIGNATURE")
    i_status = verifs[0].integrity_status if verifs else ("INTACT" if doc.integrity_verified else "MODIFIED")

    doc_hash = doc.document_hash or doc.canonical_hash or "N/A"
    sig_id = doc.signature_id or (meta.signature_fingerprint[:16] if meta and meta.signature_fingerprint and meta.signature_fingerprint != "Not Available" else f"SIG-{doc.analysis_document_id:04d}")
    f_type = doc.file_type or doc.content_type or "PDF"

    # Document Information
    doc_info = {
        "document_name": doc.file_name,
        "file_type": f_type,
        "file_size_bytes": doc.file_size or (len(doc.raw_text_content.encode("utf-8")) if doc.raw_text_content else 0),
        "document_hash": doc_hash,
        "analysis_id": doc.analysis_id or f"ANL-{doc.analysis_document_id}",
        "signature_id": sig_id,
        "analysis_timestamp": doc.analysed_at.isoformat() if doc.analysed_at else datetime.now(timezone.utc).isoformat()
    }

    # Classical Cryptographic Verification
    sig_algo = meta.signature_algorithm if (meta and meta.signature_algorithm and meta.signature_algorithm != "Not Available") else (getattr(doc, "signature_type", None) or "RSA-SHA256")
    hash_algo = meta.hash_algorithm if (meta and meta.hash_algorithm and meta.hash_algorithm != "Not Available") else "SHA-256"
    cert_status = cert.trust_status if cert else (doc.certificate_status if doc.certificate_status != "UNKNOWN" else "Not Evaluated")

    classical_info = {
        "digital_signature_status": v_status,
        "signature_algorithm": sig_algo,
        "hash_algorithm": hash_algo,
        "document_integrity": i_status,
        "public_key_status": doc.public_key_status or "VALID",
        "certificate_status": cert_status,
        "verification_result": "VALID" if (v_status == "VALID" and i_status == "INTACT") else "INVALID"
    }

    # Quantum-Inspired Analysis (Strictly labeled, software mathematical model)
    quantum_info = {
        "section_label": "QUANTUM-INSPIRED ANALYSIS (THEORETICAL MATHEMATICAL SIMULATION)",
        "scientific_disclaimer": "Classical signatures are not physical quantum states; values represent normalized linear-algebraic abstractions in Hilbert space C^2. No real quantum hardware was used.",
        "security_state": quantum.final_classification if quantum else ("SECURE" if v_status == "VALID" else "UNKNOWN"),
        "state_consistency_score": round(quantum.state_consistency * 100.0, 2) if quantum else (100.0 if v_status == "VALID" else 0.0),
        "state_disturbance_score": round(quantum.state_disturbance, 4) if quantum else (0.0 if v_status == "VALID" else 1.0),
        "secure_measurement_probability": round(quantum.measurement_secure_probability * 100.0, 2) if quantum else (100.0 if v_status == "VALID" else 0.0),
        "threat_measurement_probability": round(quantum.measurement_threat_probability * 100.0, 2) if quantum else (0.0 if v_status == "VALID" else 100.0),
        "pauli_x_disturbance": round(quantum.pauli_x_disturbance * 100.0, 2) if quantum else 0.0,
        "pauli_y_disturbance": round(quantum.pauli_y_disturbance * 100.0, 2) if quantum else 0.0,
        "pauli_z_disturbance": round(quantum.pauli_z_disturbance * 100.0, 2) if quantum else 0.0,
        "combined_pauli_disturbance": round(quantum.combined_pauli_disturbance * 100.0, 2) if quantum else 0.0,
        "forgery_risk_estimate": round(getattr(quantum, "forgery_risk_estimate", 0.0) or getattr(quantum, "forgery_risk_score", 0.0), 2) if quantum else 0.0,
        "quantum_analysis_version": getattr(quantum, "quantum_analysis_version", "QIA-2.0") if quantum else "QIA-2.0"
    }

    # Threat Detection
    threat_list = []
    triggered_rules = []
    for t in threats:
        t_dict = {
            "threat_id": f"THR-{t.incident_id}",
            "threat_type": t.threat_type,
            "threat_category": t.threat_category,
            "severity": t.severity,
            "confidence": round(t.confidence * 100.0, 1) if hasattr(t, "confidence") and t.confidence is not None else 90.0,
            "description": t.description,
            "threat_status": t.threat_status
        }
        threat_list.append(t_dict)
        triggered_rules.append(f"RULE_{t.threat_category}_DETECTED")

    # Threat Findings Consistency: ensure findings reflect verification failures
    if not threat_list:
        if v_status in ["INVALID", "MALFORMED"]:
            threat_list.append({
                "threat_id": f"THR-SYN-{doc.analysis_document_id}-01",
                "threat_type": "CRYPTOGRAPHIC_SIGNATURE_MISMATCH",
                "threat_category": "SIGNATURE_FORGERY",
                "severity": "HIGH",
                "confidence": 95.0,
                "description": "Cryptographic signature verification failed: signature does not match document content or public key.",
                "threat_status": "ACTIVE"
            })
            triggered_rules.append("RULE_SIGNATURE_FORGERY_DETECTED")
        if i_status == "MODIFIED":
            threat_list.append({
                "threat_id": f"THR-SYN-{doc.analysis_document_id}-02",
                "threat_type": "DOCUMENT_MODIFICATION_DETECTED",
                "threat_category": "DOCUMENT_MODIFICATION",
                "severity": "CRITICAL",
                "confidence": 98.0,
                "description": "PDF ByteRange digest mismatch confirms document content was altered after digital signing.",
                "threat_status": "ACTIVE"
            })
            triggered_rules.append("RULE_DOCUMENT_MODIFICATION_DETECTED")
        if cert and cert.trust_status in ["UNTRUSTED", "REVOKED"]:
            threat_list.append({
                "threat_id": f"THR-SYN-{doc.analysis_document_id}-03",
                "threat_type": "UNTRUSTED_CERTIFICATE_AUTHORITY",
                "threat_category": "CERTIFICATE_ANOMALY",
                "severity": "MEDIUM",
                "confidence": 90.0,
                "description": f"Signing certificate status is '{cert.trust_status}' (not recognized by root trust store).",
                "threat_status": "FLAGGED"
            })
            triggered_rules.append("RULE_CERTIFICATE_ANOMALY_DETECTED")

    threat_info = {
        "threats_count": len(threat_list),
        "detected_threats": threat_list,
        "detection_rules_triggered": triggered_rules
    }

    # Risk Assessment
    risk_score = float(doc.risk_score or 0.0)
    risk_level = doc.risk_level or ("CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW")))
    decision = doc.final_decision or ("AUTHENTIC" if v_status == "VALID" and i_status == "INTACT" and not threat_list else ("THREAT_DETECTED" if threat_list else "VERIFICATION_FAILED"))

    risk_info = {
        "final_risk_score": risk_score,
        "risk_level": risk_level,
        "final_decision": decision
    }

    # Deterministic Recommendations based on actual results
    recommendations = []
    if v_status == "INVALID":
        recommendations.append("Do not trust this document until the signature is verified through the original trusted signing authority.")
    if i_status == "MODIFIED":
        recommendations.append("The document may have been modified after signing.")
    if any(t["threat_category"] == "REPLAY_ATTACK" for t in threat_list):
        recommendations.append("Review repeated verification activity and source history.")
    if cert and (cert.trust_status == "UNTRUSTED" or cert.time_validity_status == "EXPIRED"):
        recommendations.append("Validate the certificate through an approved trust source.")
    if any(t["threat_category"] == "IMPERSONATION" for t in threat_list):
        recommendations.append("Investigate signer identity mismatch against verified PKI subject.")
    if not recommendations:
        recommendations.append("Document integrity and cryptographic digital signature are valid. Safe for authorized business workflows.")

    # Unified Analysis Record (Single Source of Truth)
    analysis_record = {
        "id": doc.analysis_document_id,
        "report_id": doc.analysis_id or f"ANL-{doc.analysis_document_id}",
        "document_id": doc.analysis_document_id,
        "document": {
            "fileName": doc.original_file_name,
            "fileType": f_type,
            "fileSize": doc.file_size,
            "sha256": doc_hash,
            "documentFingerprint": doc.canonical_hash or (doc_hash[:16] if doc_hash != "N/A" else "N/A")
        },
        "signature": {
            "signaturePresent": doc.signature_present,
            "signatureId": sig_id,
            "signatureValueOrFingerprint": meta.signature_fingerprint if meta else "Not Available",
            "algorithm": sig_algo,
            "publicKeyFingerprint": meta.certificate_fingerprint if meta else "Not Available"
        },
        "certificate": {
            "subject": meta.certificate_subject if meta else "Not Available",
            "issuer": meta.certificate_issuer if meta else "Not Available",
            "serialNumber": meta.certificate_serial_number if meta else "Not Available",
            "validFrom": meta.validity_start.isoformat() if meta and meta.validity_start else None,
            "validTo": meta.validity_end.isoformat() if meta and meta.validity_end else None,
            "status": cert_status
        },
        "verification": {
            "signatureValid": doc.signature_verified,
            "documentIntegrity": i_status,
            "cryptographicVerificationStatus": v_status,
            "verificationTimestamp": doc.analysed_at.isoformat() if doc.analysed_at else datetime.now(timezone.utc).isoformat()
        },
        "quantumAnalysis": quantum_info,
        "threatFindings": threat_list,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "decision": decision
        },
        "timestamps": {
            "uploadedAt": doc.created_at.isoformat() if doc.created_at else None,
            "analyzedAt": doc.analysed_at.isoformat() if doc.analysed_at else None
        }
    }

    return {
        "report_type": "ANALYSIS_REPORT",
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "document_information": doc_info,
        "classical_verification": classical_info,
        "quantum_inspired_analysis": quantum_info,
        "threat_detection": threat_info,
        "risk_assessment": risk_info,
        "recommendations": recommendations,
        "analysis_record": analysis_record,
        "summary": f"Document '{doc.file_name}' evaluated with decision: {decision} (Risk Score: {risk_score}/100, Threats: {len(threat_list)})."
    }


def build_threat_report(db: Session, generated_by: str = "Security Analyst") -> Dict[str, Any]:
    """Builds a comprehensive Threat Intelligence Report from real database incidents."""
    threats: List[ThreatIncident] = db.query(ThreatIncident).order_by(ThreatIncident.incident_id.desc()).all()
    catalog = []
    for t in threats:
        catalog.append({
            "threat_id": f"THR-{t.incident_id}",
            "threat_type": t.threat_type,
            "threat_category": t.threat_category,
            "severity": t.severity,
            "confidence": round(t.confidence * 100.0, 1) if hasattr(t, "confidence") and t.confidence is not None else 90.0,
            "detection_time": t.created_at.isoformat() if t.created_at else None,
            "related_analysis_id": t.analysis_document_id,
            "description": t.description,
            "evidence": t.evidence_json,
            "triggered_rule": f"DETERMINISTIC_{t.threat_category}_RULE",
            "recommended_action": f"Quarantine document #{t.analysis_document_id} and notify security operations."
        })

    return {
        "report_type": "THREAT_REPORT",
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_threats": len(catalog),
        "threat_catalog": catalog,
        "critical_count": sum(1 for x in catalog if x["severity"] == "CRITICAL"),
        "high_count": sum(1 for x in catalog if x["severity"] == "HIGH"),
        "summary": f"Threat catalog containing {len(catalog)} recorded incident events across platform history."
    }


def build_simulation_report(simulation_id: int, db: Session, generated_by: str = "Security Analyst") -> Dict[str, Any]:
    """Builds a Controlled Attack Simulation Report from an executed simulation record."""
    from app.models import AttackSimulation
    sim = db.query(AttackSimulation).filter(
        (AttackSimulation.id == simulation_id) | (AttackSimulation.simulation_id == str(simulation_id))
    ).first()
    if not sim:
        raise ValueError(f"Attack simulation #{simulation_id} not found.")

    res = sim.result
    return {
        "report_type": "SIMULATION_REPORT",
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "simulation_id": sim.simulation_id,
        "attack_type": sim.attack_type,
        "status": sim.status,
        "initiated_by": sim.initiated_by,
        "target_reference": sim.target_document_reference,
        "detection_success": res.detection_success if res else False,
        "detection_status": res.detection_status if res else "UNKNOWN",
        "final_risk_score": res.final_risk_score if res else 0.0,
        "final_risk_level": res.final_risk_level if res else "LOW",
        "execution_time_ms": res.execution_time_ms if res else 0.0,
        "baseline_comparison": json.loads(res.baseline_comparison) if res and res.baseline_comparison else None,
        "explanation": json.loads(res.explanation) if res and res.explanation else None,
        "threats_detected": json.loads(res.threats_detected) if res and res.threats_detected else [],
        "disclaimer": "Simulations operate strictly in-memory on temporary copies; real signatures and cryptographic keys were unaffected.",
        "summary": f"Controlled attack simulation {sim.simulation_id} ({sim.attack_type}): Status {res.detection_status if res else 'N/A'}."
    }


def build_audit_report(db: Session, generated_by: str = "Security Analyst") -> Dict[str, Any]:
    """Builds an Audit Log Trail and Integrity Verification Report."""
    from app.core.audit_engine import verify_audit_log_integrity
    integrity = verify_audit_log_integrity(db)
    recent_logs = db.query(AuditLog).order_by(AuditLog.log_id.desc()).limit(25).all()

    logs_list = []
    for l in recent_logs:
        logs_list.append({
            "log_id": l.log_id,
            "event_id": l.event_id,
            "user_email": l.user_email,
            "action": l.action,
            "result": l.result,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "current_log_hash": l.current_log_hash[:16] + "..." if l.current_log_hash else None,
            "timestamp": l.created_at.isoformat() if l.created_at else None
        })

    return {
        "report_type": "AUDIT_REPORT",
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain_integrity": integrity,
        "recent_audit_records": logs_list,
        "summary": f"Audit log verification: {integrity['status']}. {integrity['total_records_verified']} records verified."
    }


def build_performance_report(db: Session, generated_by: str = "Security Analyst") -> Dict[str, Any]:
    """Builds a Defensive Performance Evaluation Report."""
    from app.core.performance_engine import calculate_performance_metrics
    metrics = calculate_performance_metrics(db)
    return {
        "report_type": "PERFORMANCE_REPORT",
        "generated_by": generated_by,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "performance_metrics": metrics,
        "summary": f"Performance evaluation: Detection Rate {metrics['detection_rate']}%, F1-Score {metrics['f1_score']:.4f} across {metrics['total_simulations']} simulations."
    }


def generate_html_security_report(report_data: Dict[str, Any], title: str = "Security Report") -> str:
    """
    Renders clean, self-contained, printable HTML for a report.
    Adheres strictly to the Q-SHIELD blue and white cybersecurity theme.
    Zero external CDN requests to maintain isolated operation.
    """
    clean_json_str = sanitize_sensitive_data(json.dumps(report_data, indent=2))
    rtype = report_data.get("report_type", "SECURITY_REPORT")
    gen_by = report_data.get("generated_by", "Q-SHIELD Security Engine")
    gen_at = report_data.get("generated_at", datetime.now(timezone.utc).isoformat())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Q-SHIELD - {title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 36px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0284c7; padding-bottom: 20px; margin-bottom: 24px; }}
  .brand {{ font-size: 24px; font-weight: 900; color: #0f172a; letter-spacing: 1px; }}
  .brand span {{ color: #0284c7; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: 800; text-transform: uppercase; background: #e0f2fe; color: #0369a1; }}
  .section-title {{ font-size: 14px; font-weight: 800; text-transform: uppercase; color: #0284c7; letter-spacing: 0.5px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 24px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 12px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #f1f5f9; }}
  th {{ background: #f8fafc; color: #64748b; font-weight: 700; text-transform: uppercase; font-size: 10px; }}
  .highlight {{ font-weight: 700; color: #0f172a; }}
  .recommendation {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px; border-radius: 6px; margin-bottom: 8px; font-size: 12px; color: #1e3a8a; }}
  .disclaimer {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 12px; font-size: 11px; color: #92400e; margin-top: 24px; }}
  .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between; }}
  @media print {{ body {{ background: #ffffff; padding: 0; }} .container {{ border: none; box-shadow: none; padding: 0; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="brand">Q-SHIELD <span>SECURITY</span></div>
      <p style="margin: 4px 0 0 0; font-size: 12px; color: #64748b;">Quantum-Inspired Digital Signature Security Platform</p>
    </div>
    <div style="text-align: right;">
      <span class="badge">{rtype}</span>
      <p style="margin: 4px 0 0 0; font-size: 11px; color: #94a3b8;">Generated: {gen_at[:19].replace('T', ' ')} UTC</p>
    </div>
  </div>

  <h2 style="font-size: 20px; color: #0f172a; margin-top: 0;">{title}</h2>
  <p style="font-size: 13px; color: #475569; margin-bottom: 20px;">{report_data.get('summary', 'Detailed security evaluation report generated by the Q-SHIELD Security Engine.')}</p>
"""

    # Check for Document Information
    if "document_information" in report_data:
        doc_i = report_data["document_information"]
        html += """<div class="section-title">A. Document & Analysis Identifiers</div>
        <table>
          <tr><th>Document Name</th><td>""" + str(doc_i.get("document_name")) + """</td><th>File Type</th><td>""" + str(doc_i.get("file_type")) + """</td></tr>
          <tr><th>Document Hash</th><td style="font-family:monospace;font-size:11px;">""" + str(doc_i.get("document_hash")) + """</td><th>Analysis ID</th><td style="font-family:monospace;">""" + str(doc_i.get("analysis_id")) + """</td></tr>
          <tr><th>Signature ID</th><td style="font-family:monospace;">""" + str(doc_i.get("signature_id")) + """</td><th>Timestamp</th><td>""" + str(doc_i.get("analysis_timestamp"))[:19].replace('T', ' ') + """</td></tr>
        </table>"""

    # Classical Verification
    if "classical_verification" in report_data:
        c_i = report_data["classical_verification"]
        html += """<div class="section-title">B. Classical Cryptographic Verification</div>
        <table>
          <tr><th>Signature Status</th><td class="highlight">""" + str(c_i.get("digital_signature_status")) + """</td><th>Document Integrity</th><td class="highlight">""" + str(c_i.get("document_integrity")) + """</td></tr>
          <tr><th>Signature Algorithm</th><td>""" + str(c_i.get("signature_algorithm")) + """</td><th>Hash Algorithm</th><td>""" + str(c_i.get("hash_algorithm")) + """</td></tr>
          <tr><th>Public Key Status</th><td>""" + str(c_i.get("public_key_status")) + """</td><th>Certificate Status</th><td>""" + str(c_i.get("certificate_status")) + """</td></tr>
        </table>"""

    # Quantum-Inspired Analysis
    if "quantum_inspired_analysis" in report_data:
        q_i = report_data["quantum_inspired_analysis"]
        html += """<div class="section-title">C. Quantum-Inspired Security Analysis</div>
        <table>
          <tr><th>Security State</th><td class="highlight">""" + str(q_i.get("security_state")) + """</td><th>State Consistency</th><td>""" + str(q_i.get("state_consistency_score")) + """%</td></tr>
          <tr><th>State Disturbance D</th><td>""" + str(q_i.get("state_disturbance_score")) + """</td><th>Pauli Combined Anomaly</th><td>""" + str(q_i.get("combined_pauli_disturbance")) + """%</td></tr>
          <tr><th>P(Secure)</th><td>""" + str(q_i.get("secure_measurement_probability")) + """%</td><th>P(Threat State)</th><td>""" + str(q_i.get("threat_measurement_probability")) + """%</td></tr>
          <tr><th>Forgery Risk Estimate</th><td class="highlight">""" + str(q_i.get("forgery_risk_estimate")) + """%</td><th>Engine Version</th><td>""" + str(q_i.get("quantum_analysis_version")) + """</td></tr>
        </table>"""

    # Threat Detection
    if "threat_detection" in report_data:
        t_i = report_data["threat_detection"]
        threats_arr = t_i.get("detected_threats", [])
        html += f"""<div class="section-title">D. Threat Detection ({len(threats_arr)} Identified)</div>"""
        if threats_arr:
            html += "<table><thead><tr><th>Threat Type</th><th>Severity</th><th>Confidence</th><th>Description</th></tr></thead><tbody>"
            for t in threats_arr:
                html += f"<tr><td class='highlight'>{t.get('threat_category', t.get('threat_type'))}</td><td>{t.get('severity')}</td><td>{t.get('confidence')}%</td><td>{t.get('description')}</td></tr>"
            html += "</tbody></table>"
        else:
            html += "<p style='font-size:12px;color:#10b981;font-weight:600;'>Zero threats or structural anomalies detected.</p>"

    # Risk Assessment
    if "risk_assessment" in report_data:
        r_i = report_data["risk_assessment"]
        html += f"""<div class="section-title">E. Final Risk Assessment</div>
        <table>
          <tr><th>Final Decision</th><td class="highlight" style="font-size:14px;color:#0284c7;">{r_i.get('final_decision')}</td><th>Composite Risk Score</th><td class="highlight" style="font-size:14px;">{r_i.get('final_risk_score')}/100 ({r_i.get('risk_level')})</td></tr>
        </table>"""

    # Recommendations
    recs = report_data.get("recommendations", [])
    if recs:
        html += """<div class="section-title">F. Security Recommendations</div>"""
        for r in recs:
            html += f"""<div class="recommendation">&bull; {r}</div>"""

    # Raw Structured Data fallback if no special sections
    if not any(k in report_data for k in ["document_information", "classical_verification", "quantum_inspired_analysis"]):
        html += f"""<div class="section-title">Report Structured Data</div>
        <pre style="background:#f8fafc;padding:16px;border-radius:8px;font-size:11px;overflow-x:auto;">{clean_json_str}</pre>"""

    html += f"""
  <div class="disclaimer">
    <strong>Notice:</strong> This report was deterministically generated by Q-SHIELD Security Engine for authorized audit inspection. Real cryptographic checks are strictly decoupled from quantum-inspired mathematical analytical models.
  </div>

  <div class="footer">
    <div>Generated by: {gen_by}</div>
    <div>Q-SHIELD Security Platform &copy; 2026</div>
  </div>
</div>
</body>
</html>"""
    return html


def export_report_content(report: SecurityReport, export_format: str = "json") -> Tuple[bytes, str, str]:
    """
    Exports a SecurityReport into the requested format (json, html, pdf).
    Guarantees strict secret sanitization.
    Returns (bytes_content, media_type, filename).
    """
    fmt = export_format.lower().strip()
    ref = report.report_reference or f"REPORT-{report.report_id}"
    data = json.loads(report.report_data) if report.report_data else {
        "report_id": report.report_id,
        "report_reference": ref,
        "report_type": report.report_type,
        "status": report.overall_status,
        "risk_score": report.risk_score,
        "summary": report.summary
    }

    if fmt == "html":
        html_str = generate_html_security_report(data, title=f"Report {ref}")
        clean_html = sanitize_sensitive_data(html_str)
        return clean_html.encode("utf-8"), "text/html", f"{ref}.html"

    elif fmt == "pdf":
        if report.report_path and Path(report.report_path).exists():
            with open(report.report_path, "rb") as f:
                pdf_bytes = f.read()
            return pdf_bytes, "application/pdf", f"{ref}.pdf"
        else:
            # Fallback: create PDF via ReportLab
            fallback_path = REPORTS_DIR / f"{ref}_exported.pdf"
            doc_tmpl = SimpleDocTemplate(str(fallback_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = [
                Paragraph(f"<b>Q-SHIELD Security Report: {ref}</b>", styles["Title"]),
                Spacer(1, 12),
                Paragraph(f"<b>Type:</b> {report.report_type} | <b>Status:</b> {report.overall_status}", styles["Normal"]),
                Paragraph(f"<b>Risk Score:</b> {report.risk_score:.1f}/100 ({report.risk_level})", styles["Normal"]),
                Spacer(1, 12),
                Paragraph(f"<b>Summary:</b> {report.summary or 'N/A'}", styles["Normal"])
            ]
            doc_tmpl.build(story)
            with open(fallback_path, "rb") as f:
                pdf_bytes = f.read()
            return pdf_bytes, "application/pdf", f"{ref}.pdf"

    else:
        # Default: JSON
        clean_json_str = sanitize_sensitive_data(json.dumps(data, indent=2))
        return clean_json_str.encode("utf-8"), "application/json", f"{ref}.json"

