from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.models import User, SignedDocument
from app.schemas import DigitalSignatureStats
from app.api.auth import get_current_user

router = APIRouter(prefix="/signature", tags=["Digital Signature Workspace"])

@router.get("/stats", response_model=DigitalSignatureStats)
def get_signature_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    total = db.query(SignedDocument).filter(SignedDocument.user_id == current_user.user_id).count()
    signed = db.query(SignedDocument).filter(SignedDocument.user_id == current_user.user_id, SignedDocument.status == "SIGNED").count()
    pending = db.query(SignedDocument).filter(SignedDocument.user_id == current_user.user_id, SignedDocument.status == "UPLOADED").count()

    return DigitalSignatureStats(
        total_documents=total,
        signed_documents=signed,
        pending_signatures=pending,
        recent_activity_count=total
    )

@router.get("/documents")
def get_user_documents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    docs = db.query(SignedDocument).filter(SignedDocument.user_id == current_user.user_id).order_by(SignedDocument.created_at.desc()).all()
    return docs
