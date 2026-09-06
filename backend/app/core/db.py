from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import SQLALCHEMY_DATABASE_URL

# SQLite Engine with check_same_thread=False for FastAPI concurrency
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_and_migrate_db():
    """Ensures tables are created and missing columns are added automatically for SQLite."""
    Base.metadata.create_all(bind=engine)
    
    with engine.connect() as conn:
        inspector = inspect(engine)
        
        # Migrations for 'documents' table
        if inspector.has_table("documents"):
            existing_cols = {c["name"] for c in inspector.get_columns("documents")}
            doc_migrations = [
                ("signature_id", "VARCHAR(100)"),
                ("content_type", "VARCHAR(50) DEFAULT 'PDF'"),
                ("file_type", "VARCHAR(50) DEFAULT 'PDF'"),
                ("file_path", "VARCHAR(500)"),
                ("raw_text_content", "TEXT"),
                ("canonical_hash", "VARCHAR(128)"),
                ("hash_algorithm", "VARCHAR(50) DEFAULT 'SHA-256'"),
                ("signature_type", "VARCHAR(50) DEFAULT 'EMBEDDED_PKCS7'"),
                ("signature_algorithm", "VARCHAR(50) DEFAULT 'RSA-SHA256'"),
                ("signature_value", "TEXT"),
                ("public_key_fingerprint", "VARCHAR(128)"),
                ("key_reference", "VARCHAR(100)"),
                ("nonce", "VARCHAR(100)"),
                ("message_id", "VARCHAR(100)"),
                ("signed_at", "DATETIME")
            ]
            for col_name, col_type in doc_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE documents ADD COLUMN {col_name} {col_type}"))
                    
        # Migrations for 'analyzed_documents' table
        if inspector.has_table("analyzed_documents"):
            existing_cols = {c["name"] for c in inspector.get_columns("analyzed_documents")}
            analyzed_migrations = [
                ("analysis_id", "VARCHAR(100)"),
                ("signature_id", "VARCHAR(100)"),
                ("content_type", "VARCHAR(50) DEFAULT 'PDF'"),
                ("file_type", "VARCHAR(50) DEFAULT 'PDF'"),
                ("uploaded_file", "VARCHAR(500)"),
                ("raw_text_content", "TEXT"),
                ("canonical_hash", "VARCHAR(128)"),
                ("signature_type", "VARCHAR(50) DEFAULT 'EMBEDDED_PKCS7'"),
                ("signature_verified", "BOOLEAN DEFAULT 0"),
                ("integrity_verified", "BOOLEAN DEFAULT 0"),
                ("certificate_status", "VARCHAR(50) DEFAULT 'UNKNOWN'"),
                ("public_key_status", "VARCHAR(50) DEFAULT 'UNKNOWN'"),
                ("risk_score", "FLOAT DEFAULT 0.0"),
                ("risk_level", "VARCHAR(20) DEFAULT 'LOW'"),
                ("final_decision", "VARCHAR(50) DEFAULT 'REQUIRES_CAUTION'"),
                ("analysis_summary", "TEXT"),
                ("analysed_at", "DATETIME")
            ]
            for col_name, col_type in analyzed_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE analyzed_documents ADD COLUMN {col_name} {col_type}"))

        # Migrations for 'threat_incidents' table
        if inspector.has_table("threat_incidents"):
            existing_cols = {c["name"] for c in inspector.get_columns("threat_incidents")}
            threat_migrations = [
                ("threat_type", "VARCHAR(50)"),
                ("confidence", "FLOAT DEFAULT 0.0")
            ]
            for col_name, col_type in threat_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE threat_incidents ADD COLUMN {col_name} {col_type}"))

        # Migrations for 'quantum_inspired_analyses' table
        if inspector.has_table("quantum_inspired_analyses"):
            existing_cols = {c["name"] for c in inspector.get_columns("quantum_inspired_analyses")}
            q_migrations = [
                ("state_consistency", "FLOAT DEFAULT 0.0"),
                ("state_disturbance", "FLOAT DEFAULT 0.0"),
                ("measurement_secure_probability", "FLOAT DEFAULT 0.0"),
                ("measurement_threat_probability", "FLOAT DEFAULT 0.0"),
                ("pauli_x_disturbance", "FLOAT DEFAULT 0.0"),
                ("pauli_y_disturbance", "FLOAT DEFAULT 0.0"),
                ("pauli_z_disturbance", "FLOAT DEFAULT 0.0"),
                ("combined_pauli_disturbance", "FLOAT DEFAULT 0.0"),
                ("forgery_risk_estimate", "FLOAT DEFAULT 0.0"),
                ("quantum_analysis_version", "VARCHAR(20) DEFAULT 'QIA-2.0'"),
                ("explanation_json", "TEXT")
            ]
            for col_name, col_type in q_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE quantum_inspired_analyses ADD COLUMN {col_name} {col_type}"))

        # Migrations for 'security_reports' table
        # Migrations for 'security_reports' table
        if inspector.has_table("security_reports"):
            existing_cols = {c["name"] for c in inspector.get_columns("security_reports")}
            report_migrations = [
                ("report_reference", "VARCHAR(100)"),
                ("report_type", "VARCHAR(50) DEFAULT 'ANALYSIS_REPORT'"),
                ("simulation_id", "INTEGER"),
                ("document_name", "VARCHAR(255)"),
                ("document_hash", "VARCHAR(128)"),
                ("signature_id", "VARCHAR(128)"),
                ("overall_status", "VARCHAR(50) DEFAULT 'AUTHENTIC'"),
                ("risk_score", "FLOAT DEFAULT 0.0"),
                ("risk_level", "VARCHAR(20) DEFAULT 'LOW'"),
                ("summary", "TEXT"),
                ("report_data", "TEXT"),
                ("created_at", "DATETIME")
            ]
            for col_name, col_type in report_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE security_reports ADD COLUMN {col_name} {col_type}"))

            # Ensure analysis_document_id allows NULL
            for c in inspector.get_columns("security_reports"):
                if c["name"] == "analysis_document_id" and not c["nullable"]:
                    conn.execute(text("""
                        CREATE TABLE security_reports_new (
                            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            report_reference VARCHAR(100),
                            report_type VARCHAR(50) DEFAULT 'ANALYSIS_REPORT',
                            analysis_document_id INTEGER,
                            simulation_id INTEGER,
                            generated_by VARCHAR(150),
                            document_name VARCHAR(255),
                            document_hash VARCHAR(128),
                            signature_id VARCHAR(128),
                            overall_status VARCHAR(50) DEFAULT 'AUTHENTIC',
                            final_security_decision VARCHAR(50) DEFAULT 'AUTHENTIC',
                            risk_score FLOAT DEFAULT 0.0,
                            overall_risk_score FLOAT DEFAULT 0.0,
                            risk_level VARCHAR(20) DEFAULT 'LOW',
                            summary TEXT,
                            report_data TEXT,
                            report_path VARCHAR(500) DEFAULT '',
                            report_hash VARCHAR(128) DEFAULT '',
                            report_version VARCHAR(20) DEFAULT 'SR-2.0',
                            generated_at DATETIME,
                            created_at DATETIME
                        );
                    """))
                    conn.execute(text("""
                        INSERT INTO security_reports_new (
                            report_id, report_reference, report_type, analysis_document_id,
                            simulation_id, generated_by, document_name, document_hash, signature_id,
                            overall_status, final_security_decision, risk_score, overall_risk_score,
                            risk_level, summary, report_data, report_path, report_hash,
                            report_version, generated_at, created_at
                        )
                        SELECT
                            report_id, report_reference, report_type, analysis_document_id,
                            simulation_id, generated_by, document_name, document_hash, signature_id,
                            overall_status, final_security_decision, risk_score, overall_risk_score,
                            risk_level, summary, report_data, report_path, report_hash,
                            report_version, generated_at, created_at
                        FROM security_reports;
                    """))
                    conn.execute(text("DROP TABLE security_reports;"))
                    conn.execute(text("ALTER TABLE security_reports_new RENAME TO security_reports;"))
                    break

        # Migrations for 'audit_logs' table
        if inspector.has_table("audit_logs"):
            existing_cols = {c["name"] for c in inspector.get_columns("audit_logs")}
            audit_migrations = [
                ("event_id", "VARCHAR(100)"),
                ("resource_type", "VARCHAR(50)"),
                ("resource_id", "VARCHAR(100)"),
                ("result", "VARCHAR(50) DEFAULT 'SUCCESS'"),
                ("previous_log_hash", "VARCHAR(64)"),
                ("current_log_hash", "VARCHAR(64)"),
                ("metadata_json", "TEXT")
            ]
            for col_name, col_type in audit_migrations:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE audit_logs ADD COLUMN {col_name} {col_type}"))

        conn.commit()

