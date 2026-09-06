from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models import User, AnalyzedDocument, SecurityIncident
from app.schemas import SecurityAnalystStats
from app.api.auth import get_current_user

router = APIRouter(prefix="/security", tags=["Security Analysis Overview"])

@router.get("/stats", response_model=SecurityAnalystStats)
def get_security_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total = db.query(AnalyzedDocument).count()
    valid = db.query(AnalyzedDocument).filter(AnalyzedDocument.signature_status == "SIGNATURE_FOUND").count()
    threats = db.query(SecurityIncident).filter(SecurityIncident.threat_level.in_(["MEDIUM", "HIGH", "CRITICAL"])).count()
    high_risk = db.query(SecurityIncident).filter(SecurityIncident.threat_level.in_(["HIGH", "CRITICAL"])).count()

    return SecurityAnalystStats(
        total_analyzed=total,
        valid_signatures=valid,
        threats_detected=threats,
        high_risk_incidents=high_risk
    )

@router.get("/incidents")
def get_incidents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    incidents = db.query(SecurityIncident).all()
    return incidents
