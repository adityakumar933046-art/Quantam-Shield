from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List

from app.core.db import get_db
from app.models import (
    User,
    AnalyzedDocument,
    ThreatIncident,
    QuantumInspiredAnalysis,
    AttackSimulation,
    SecurityReport,
    AuditLog
)
from app.schemas import (
    DashboardOverviewResponse,
    DashboardRiskResponse,
    DashboardThreatsResponse,
    DashboardActivityResponse,
    DashboardQuantumAnalysisResponse,
    PerformanceMetricsResponse
)
from app.api.auth import get_current_user
from app.core.performance_engine import calculate_performance_metrics

router = APIRouter(prefix="/dashboard", tags=["Security Dashboard Aggregations"])


@router.get("/overview", response_model=DashboardOverviewResponse)
def get_dashboard_overview(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns top-level real aggregated metrics across analyzed documents and signatures."""
    total_docs = db.query(AnalyzedDocument).count()
    verified_docs = db.query(AnalyzedDocument).filter(
        (AnalyzedDocument.signature_status == "VALID") & (AnalyzedDocument.integrity_verified == True)
    ).count()
    failed_verifications = db.query(AnalyzedDocument).filter(
        (AnalyzedDocument.signature_status != "VALID") | (AnalyzedDocument.integrity_verified == False)
    ).count()
    total_threats = db.query(ThreatIncident).count()
    high_risk = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "HIGH").count()
    critical_risk = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "CRITICAL").count()

    return DashboardOverviewResponse(
        total_documents_analyzed=total_docs,
        verified_documents=verified_docs,
        failed_verifications=failed_verifications,
        threats_detected=total_threats,
        high_risk_documents=high_risk,
        critical_risk_documents=critical_risk,
        system_status="OPERATIONAL"
    )


@router.get("/risk", response_model=DashboardRiskResponse)
def get_dashboard_risk(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns risk distribution and average risk score across all evaluated documents."""
    low = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "LOW").count()
    medium = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "MEDIUM").count()
    high = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "HIGH").count()
    critical = db.query(AnalyzedDocument).filter(AnalyzedDocument.risk_level == "CRITICAL").count()

    avg_score_res = db.query(func.avg(AnalyzedDocument.risk_score)).scalar()
    avg_score = float(avg_score_res) if avg_score_res is not None else 0.0

    return DashboardRiskResponse(
        low_risk_count=low,
        medium_risk_count=medium,
        high_risk_count=high,
        critical_risk_count=critical,
        average_risk_score=round(avg_score, 2)
    )


@router.get("/threats", response_model=DashboardThreatsResponse)
def get_dashboard_threats(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns threat type distributions, recent threats, and highest severity incidents."""
    incidents = db.query(ThreatIncident).all()
    dist: Dict[str, int] = {}
    for inc in incidents:
        cat = inc.threat_category or "UNKNOWN"
        dist[cat] = dist.get(cat, 0) + 1

    recent = db.query(ThreatIncident).order_by(ThreatIncident.incident_id.desc()).limit(10).all()
    recent_list = [
        {
            "incident_id": t.incident_id,
            "threat_category": t.threat_category,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "threat_score": t.threat_score,
            "description": t.description,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        for t in recent
    ]

    highest = db.query(ThreatIncident).filter(
        ThreatIncident.severity.in_(["CRITICAL", "HIGH"])
    ).order_by(ThreatIncident.threat_score.desc()).limit(10).all()
    highest_list = [
        {
            "incident_id": t.incident_id,
            "threat_category": t.threat_category,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "threat_score": t.threat_score,
            "description": t.description,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        for t in highest
    ]

    return DashboardThreatsResponse(
        threat_type_distribution=dist,
        recent_threats=recent_list,
        highest_severity_threats=highest_list
    )


@router.get("/activity", response_model=DashboardActivityResponse)
def get_dashboard_activity(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns unified recent operational security events."""
    recent_uploads = [
        {
            "id": d.analysis_document_id,
            "name": d.file_name,
            "hash": d.canonical_hash[:16] + "..." if d.canonical_hash else None,
            "timestamp": d.created_at.isoformat() if d.created_at else None
        }
        for d in db.query(AnalyzedDocument).order_by(AnalyzedDocument.created_at.desc()).limit(5).all()
    ]

    recent_analyses = [
        {
            "id": d.analysis_document_id,
            "name": d.file_name,
            "decision": d.final_decision,
            "risk_score": d.risk_score,
            "timestamp": d.analysed_at.isoformat() if d.analysed_at else None
        }
        for d in db.query(AnalyzedDocument).filter(AnalyzedDocument.final_decision.isnot(None)).order_by(AnalyzedDocument.analysed_at.desc()).limit(5).all()
    ]

    recent_threats = [
        {
            "id": t.incident_id,
            "category": t.threat_category,
            "severity": t.severity,
            "score": t.threat_score,
            "timestamp": t.created_at.isoformat() if t.created_at else None
        }
        for t in db.query(ThreatIncident).order_by(ThreatIncident.created_at.desc()).limit(5).all()
    ]

    recent_simulations = [
        {
            "id": s.id,
            "simulation_id": s.simulation_id,
            "attack_type": s.attack_type,
            "status": s.status,
            "timestamp": s.created_at.isoformat() if s.created_at else None
        }
        for s in db.query(AttackSimulation).order_by(AttackSimulation.created_at.desc()).limit(5).all()
    ]

    recent_reports = [
        {
            "id": r.report_id,
            "reference": r.report_reference,
            "type": r.report_type,
            "status": r.overall_status,
            "risk_score": r.risk_score,
            "timestamp": r.created_at.isoformat() if r.created_at else None
        }
        for r in db.query(SecurityReport).order_by(SecurityReport.created_at.desc()).limit(5).all()
    ]

    return DashboardActivityResponse(
        recent_uploads=recent_uploads,
        recent_analyses=recent_analyses,
        recent_threats=recent_threats,
        recent_simulations=recent_simulations,
        recent_reports=recent_reports
    )


@router.get("/quantum-analysis", response_model=DashboardQuantumAnalysisResponse)
def get_dashboard_quantum_analysis(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns aggregated mathematical quantum-inspired metrics across analyzed documents."""
    q_records = db.query(QuantumInspiredAnalysis).all()
    count = len(q_records)

    if count == 0:
        return DashboardQuantumAnalysisResponse(
            average_state_consistency=0.0,
            average_state_disturbance=0.0,
            average_threat_probability=0.0,
            average_pauli_disturbance=0.0,
            analyzed_sample_count=0
        )

    avg_consistency = sum(getattr(q, "state_consistency", 1.0) for q in q_records) / count
    avg_disturbance = sum(getattr(q, "state_disturbance", 0.0) or getattr(q, "disturbance_score", 0.0) for q in q_records) / count
    avg_threat_p = sum(getattr(q, "measurement_threat_probability", 0.0) for q in q_records) / count
    avg_pauli = sum(getattr(q, "combined_pauli_disturbance", 0.0) for q in q_records) / count

    return DashboardQuantumAnalysisResponse(
        average_state_consistency=round(avg_consistency * 100.0, 2),
        average_state_disturbance=round(avg_disturbance, 4),
        average_threat_probability=round(avg_threat_p * 100.0, 2),
        average_pauli_disturbance=round(avg_pauli * 100.0, 2),
        analyzed_sample_count=count
    )


@router.get("/simulation-performance", response_model=PerformanceMetricsResponse)
def get_simulation_performance(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Returns defensive performance evaluation metrics computed deterministically."""
    return calculate_performance_metrics(db)
