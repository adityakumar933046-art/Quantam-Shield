import sys
from pathlib import Path

# Ensure backend directory is in python path
sys.path.append(str(Path(__file__).resolve().parent))

from app.core.db import engine, SessionLocal, Base
from app.core.security import get_password_hash
from app.models import User, SignedDocument, SecurityIncident, AuditLog

def seed_database():
    print("Initializing Q-SHIELD-SECURITY-PLATFORM SQLite Database...")
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if users exist
        user_count = db.query(User).count()
        if user_count == 0:
            print("Seeding initial platform users...")
            
            admin_user = User(
                full_name="Platform Super Admin",
                email="admin@qshield.com",
                password_hash=get_password_hash("AdminPassword123!"),
                role="SUPER_ADMIN",
                status="ACTIVE"
            )
            
            sig_user = User(
                full_name="Digital Signature Operator",
                email="user@qshield.com",
                password_hash=get_password_hash("UserPassword123!"),
                role="DIGITAL_SIGNATURE_USER",
                status="ACTIVE"
            )
            
            sec_analyst = User(
                full_name="Senior Security Analyst",
                email="analyst@qshield.com",
                password_hash=get_password_hash("AnalystPassword123!"),
                role="SECURITY_ANALYST",
                status="ACTIVE"
            )
            
            db.add_all([admin_user, sig_user, sec_analyst])
            db.commit()
            print("Seeded 3 primary roles: SUPER_ADMIN, DIGITAL_SIGNATURE_USER, SECURITY_ANALYST.")
        else:
            print(f"Database already contains {user_count} users.")

        # Seed initial documents and incidents if empty
        if db.query(SignedDocument).count() == 0:
            sig_user = db.query(User).filter(User.role == "DIGITAL_SIGNATURE_USER").first()
            if sig_user:
                doc1 = SignedDocument(
                    user_id=sig_user.user_id,
                    original_filename="Contract_v1.pdf",
                    signed_filename="Contract_v1_signed.pdf",
                    file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    signature_algorithm="RSA-SHA256",
                    status="SIGNED"
                )
                db.add(doc1)
                db.commit()
                print("Seeded initial signed document.")

        if db.query(SecurityIncident).count() == 0:
            analyst = db.query(User).filter(User.role == "SECURITY_ANALYST").first()
            if analyst:
                inc1 = SecurityIncident(
                    analyst_id=analyst.user_id,
                    document_name="Financial_Report_2026_signed.pdf",
                    signature_validity="VALID",
                    integrity_status="VERIFIED",
                    threat_level="LOW",
                    risk_score=12.5,
                    details="Classical RSA-2048 signature valid. No anomaly detected."
                )
                inc2 = SecurityIncident(
                    analyst_id=analyst.user_id,
                    document_name="Modified_Agreement_signed.pdf",
                    signature_validity="INVALID",
                    integrity_status="TAMPERED",
                    threat_level="HIGH",
                    risk_score=87.3,
                    details="Signature manipulation detected. Byte offset mismatch."
                )
                db.add_all([inc1, inc2])
                db.commit()
                print("Seeded initial security incidents.")

        # Initial audit log
        if db.query(AuditLog).count() == 0:
            log = AuditLog(
                user_email="admin@qshield.com",
                action="SYSTEM_INIT",
                details="Q-SHIELD Security Platform database initialized successfully."
            )
            db.add(log)
            db.commit()

        print("Database seed complete successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
