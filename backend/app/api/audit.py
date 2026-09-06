from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.db import get_db
from app.models import User, AuditLog, SignedDocument, SecurityIncident
from app.schemas import (
    AuditLogResponse,
    AuditLogDetailedResponse,
    AuditIntegrityVerificationResponse,
    SuperAdminStats
)
from app.api.auth import get_current_user
from app.core.audit_engine import verify_audit_log_integrity, log_audit_event

router = APIRouter(prefix="/admin", tags=["Super Admin Platform"])


def require_super_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Platform administrative actions require SUPER_ADMIN privileges. Current role: '{current_user.role}'."
        )
    return current_user


def require_audit_viewer(current_user: User = Depends(get_current_user)):
    """
    Authorizes Security Analysts, Admins, and Super Administrators to inspect system audit logs.
    Restricts access from standard digital signature users.
    """
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. User '{current_user.email}' with role '{current_user.role}' is not authorized to inspect security audit logs. Required roles: SECURITY_ANALYST, SUPER_ADMIN."
        )
    return current_user


@router.get("/stats", response_model=SuperAdminStats)
def get_super_admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_super_admin)):
    total_users = db.query(User).count()
    active_analysts = db.query(User).filter(User.role == "SECURITY_ANALYST", User.status == "ACTIVE").count()
    total_signed = db.query(SignedDocument).count()
    total_analyzed = db.query(SecurityIncident).count()

    return SuperAdminStats(
        total_users=total_users,
        active_analysts=active_analysts,
        total_signed_documents=total_signed,
        total_analyzed_documents=total_analyzed,
        system_status="OPERATIONAL"
    )


@router.get("/audit-logs", response_model=List[AuditLogResponse])
@router.get("/audit-logs/", response_model=List[AuditLogResponse], include_in_schema=False)
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_audit_viewer)
):
    """Fetches list of tamper-evident audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs


@router.get("/audit-logs/detailed", response_model=List[AuditLogDetailedResponse])
@router.get("/audit-logs/detailed/", response_model=List[AuditLogDetailedResponse], include_in_schema=False)
def get_detailed_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action code"),
    user_email: Optional[str] = Query(None, description="Filter by user email"),
    result: Optional[str] = Query(None, description="Filter by result (SUCCESS, FAILED, WARNING)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_audit_viewer)
):
    """Fetches detailed audit log records with hash chain pointers and JSON metadata."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    if user_email:
        query = query.filter(AuditLog.user_email == user_email)
    if result:
        query = query.filter(AuditLog.result == result)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return logs


@router.get("/audit-logs/verify-integrity", response_model=AuditIntegrityVerificationResponse)
@router.get("/audit-logs/verify-integrity/", response_model=AuditIntegrityVerificationResponse, include_in_schema=False)
def verify_logs_integrity(
    db: Session = Depends(get_db),
    user: User = Depends(require_audit_viewer)
):
    """
    Cryptographically verifies the append-only SHA-256 hash chain of the audit log.
    Returns chain validity status, total records, and any discrepancy details.
    """
    res = verify_audit_log_integrity(db)

    # Log the verification action itself
    log_audit_event(
        db=db,
        action="AUDIT_VERIFICATION_CHECK",
        user_email=user.email,
        user_id=user.user_id,
        resource_type="AUDIT_CHAIN",
        resource_id="GLOBAL_LOG_CHAIN",
        result=res["status"],
        details=f"Audit chain verification executed by '{user.email}': {res['status']} ({res['total_records_verified']} records verified)"
    )

    return res


@router.get("/audit-logs/document/{document_id}", response_model=List[AuditLogDetailedResponse])
@router.get("/audit-logs/document/{document_id}/", response_model=List[AuditLogDetailedResponse], include_in_schema=False)
def get_document_audit_trail(
    document_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_audit_viewer)
):
    """Fetches complete forensic audit trail for a specific document or signature identifier."""
    logs = db.query(AuditLog).filter(
        (AuditLog.resource_id == str(document_id)) | (AuditLog.details.like(f"%{document_id}%"))
    ).order_by(AuditLog.created_at.asc()).all()
    return logs
