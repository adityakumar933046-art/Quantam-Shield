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

        # Ensure clean audit log genesis if empty
        if db.query(AuditLog).count() == 0:
            log = AuditLog(
                user_email="admin@qshield.com",
                action="SYSTEM_INIT",
                details="Q-SHIELD Security Platform database initialized successfully."
            )
            db.add(log)
            db.commit()

        print("Database authentication setup complete successfully!")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
