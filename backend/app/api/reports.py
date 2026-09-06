from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from typing import List, Optional
import json
from datetime import datetime, timezone

from app.core.db import get_db
from app.models import User, SecurityReport, AnalyzedDocument, AttackSimulation
from app.schemas import SecurityReportResponse, ReportGenerateRequest
from app.api.auth import get_current_user
from app.core.audit_engine import log_audit_event
from app.core.report_engine import (
    generate_report_reference,
    build_analysis_security_report,
    build_threat_report,
    build_simulation_report,
    build_audit_report,
    build_performance_report,
    export_report_content,
    generate_pdf_security_report,
)

router = APIRouter(prefix="/reports", tags=["Security Reports"])


def require_analyst_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted to Security Analysts and Administrators"
        )
    return current_user


@router.get("", response_model=List[SecurityReportResponse])
def list_reports(
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """List generated security reports with optional filtering."""
    query = db.query(SecurityReport)
    if report_type:
        query = query.filter(SecurityReport.report_type == report_type)
    if risk_level:
        query = query.filter(SecurityReport.risk_level == risk_level)

    reports = query.order_by(SecurityReport.created_at.desc()).offset(offset).limit(limit).all()
    return reports


@router.post("/generate", response_model=SecurityReportResponse)
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """
    Deterministically generates a security report based on real database records.
    Report types: ANALYSIS_REPORT, THREAT_REPORT, SIMULATION_REPORT, AUDIT_REPORT, PERFORMANCE_REPORT.
    """
    ref = generate_report_reference()
    rpt_type = req.report_type.upper()

    if rpt_type == "ANALYSIS_REPORT":
        if not req.analysis_id:
            raise HTTPException(status_code=400, detail="analysis_id is required for ANALYSIS_REPORT")
        doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == req.analysis_id).first()
        if not doc:
            raise HTTPException(status_code=404, detail=f"Analyzed document #{req.analysis_id} not found")

        data = build_analysis_security_report(req.analysis_id, db, user.email)
        summary = data.get("summary", f"Analysis report for {doc.file_name}")
        overall_status = data.get("risk_assessment", {}).get("final_decision", "EVALUATED")
        risk_score = data.get("risk_assessment", {}).get("final_risk_score", 0.0)
        risk_level = data.get("risk_assessment", {}).get("risk_level", "LOW")
        doc_name = doc.file_name
        doc_hash = doc.document_hash or doc.canonical_hash
        sig_id = doc.signature_id or (doc.extracted_metadata.signature_fingerprint[:16] if doc.extracted_metadata and doc.extracted_metadata.signature_fingerprint and doc.extracted_metadata.signature_fingerprint != "Not Available" else f"SIG-{doc.analysis_document_id:04d}")
        sim_id = None
        analysis_id = doc.analysis_document_id

    elif rpt_type == "THREAT_REPORT":
        data = build_threat_report(db, user.email)
        summary = data.get("summary", "System-wide threat intelligence report")
        overall_status = "THREATS_IDENTIFIED" if data.get("total_threats", 0) > 0 else "CLEAN"
        risk_score = 75.0 if data.get("critical_count", 0) > 0 else (45.0 if data.get("high_count", 0) > 0 else 15.0)
        risk_level = "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))
        doc_name = None
        doc_hash = None
        sig_id = None
        sim_id = None
        analysis_id = None

    elif rpt_type == "SIMULATION_REPORT":
        if not req.simulation_id:
            raise HTTPException(status_code=400, detail="simulation_id is required for SIMULATION_REPORT")
        data = build_simulation_report(req.simulation_id, db, user.email)
        summary = data.get("summary", f"Attack simulation #{req.simulation_id} report")
        overall_status = data.get("detection_status", "COMPLETED")
        risk_score = data.get("final_risk_score", 0.0)
        risk_level = data.get("final_risk_level", "LOW")
        doc_name = data.get("target_reference")
        doc_hash = None
        sig_id = None
        sim_id = req.simulation_id
        analysis_id = None

    elif rpt_type == "AUDIT_REPORT":
        data = build_audit_report(db, user.email)
        integrity = data.get("chain_integrity", {})
        summary = data.get("summary", "Audit log hash chain integrity report")
        overall_status = integrity.get("status", "AUDIT_LOG_VALID")
        risk_score = 0.0 if integrity.get("chain_intact", True) else 90.0
        risk_level = "LOW" if integrity.get("chain_intact", True) else "CRITICAL"
        doc_name = None
        doc_hash = None
        sig_id = None
        sim_id = None
        analysis_id = None

    elif rpt_type == "PERFORMANCE_REPORT":
        data = build_performance_report(db, user.email)
        perf = data.get("performance_metrics", {})
        summary = data.get("summary", "Defensive performance evaluation report")
        overall_status = "EVALUATED"
        risk_score = 100.0 - perf.get("detection_rate", 100.0)
        risk_level = "LOW" if risk_score <= 25 else ("MEDIUM" if risk_score <= 50 else "HIGH")
        doc_name = None
        doc_hash = None
        sig_id = None
        sim_id = None
        analysis_id = None

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported report type: {req.report_type}")

    sec_report = SecurityReport(
        report_reference=ref,
        report_type=rpt_type,
        analysis_document_id=analysis_id,
        simulation_id=sim_id,
        document_name=doc_name,
        document_hash=doc_hash,
        signature_id=sig_id,
        overall_status=overall_status,
        final_security_decision=overall_status,
        risk_score=risk_score,
        overall_risk_score=risk_score,
        risk_level=risk_level,
        summary=summary,
        report_data=json.dumps(data),
        report_version="QSR-2.0",
        generated_by=user.email,
        generated_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc)
    )
    db.add(sec_report)
    db.commit()
    db.refresh(sec_report)

    log_audit_event(
        db=db,
        action="REPORT_GENERATED",
        user_email=user.email,
        user_id=user.user_id,
        resource_type="REPORT",
        resource_id=ref,
        result="SUCCESS",
        details=f"Generated {rpt_type} {ref}: {summary}"
    )

    return sec_report


@router.get("/threats/summary")
def get_threats_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Returns threat intelligence summary report."""
    return build_threat_report(db, user.email)


@router.get("/performance/summary")
def get_performance_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Returns defensive performance evaluation metrics summary."""
    return build_performance_report(db, user.email)


@router.get("/analysis/{analysis_id}", response_model=SecurityReportResponse)
def get_or_generate_analysis_report(
    analysis_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Fetches the latest analysis report for a document, or synthesizes one if none exists."""
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Analyzed document #{analysis_id} not found")

    existing = db.query(SecurityReport).filter(
        SecurityReport.analysis_document_id == analysis_id,
        SecurityReport.report_type == "ANALYSIS_REPORT"
    ).order_by(SecurityReport.created_at.desc()).first()

    if existing:
        return existing

    # Synthesize new report
    return generate_pdf_security_report(db, analysis_id, user.email)


@router.get("/{report_reference}", response_model=SecurityReportResponse)
def get_report_by_reference(
    report_reference: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Fetches a specific security report by reference or id."""
    report = None
    if report_reference.isdigit():
        report = db.query(SecurityReport).filter(SecurityReport.report_id == int(report_reference)).first()

    if not report:
        report = db.query(SecurityReport).filter(SecurityReport.report_reference == report_reference).first()

    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_reference}' not found")

    return report


@router.get("/{report_reference}/export")
def export_report(
    report_reference: str,
    format: str = Query("pdf", description="Export format: json, html, or pdf"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Exports the specified report in JSON, HTML, or PDF format.
    Secrets and private keys are strictly sanitized before delivery.
    """
    report = None
    if report_reference.isdigit():
        report = db.query(SecurityReport).filter(SecurityReport.report_id == int(report_reference)).first()

    if not report:
        report = db.query(SecurityReport).filter(SecurityReport.report_reference == report_reference).first()

    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_reference}' not found")

    content, media_type, filename = export_report_content(report, format)

    log_audit_event(
        db=db,
        action="REPORT_EXPORTED",
        user_email=user.email,
        user_id=user.user_id,
        resource_type="REPORT",
        resource_id=report.report_reference,
        result="SUCCESS",
        details=f"Exported report {report.report_reference} in {format.upper()} format"
    )

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
