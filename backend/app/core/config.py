import os
from pathlib import Path

# Base Directory: Q-SHIELD-SECURITY-PLATFORM root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR

# Database URL (Dynamic PostgreSQL / SQLite Support)
raw_db_url = os.getenv("DATABASE_URL", "").strip()
if raw_db_url:
    # Render and Heroku provide postgres:// which SQLAlchemy 2.0 requires as postgresql://
    if raw_db_url.startswith("postgres://"):
        raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = raw_db_url
else:
    DATABASE_DIR = PROJECT_ROOT / "database"
    DATABASE_DIR.mkdir(exist_ok=True)
    DATABASE_PATH = DATABASE_DIR / "qshield.db"
    SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

# JWT Security Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "qshield_secret_key_quantum_inspired_cybersecurity_2026_super_secure")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

# Storage Directories (Configurable for persistent disk or local fallback)
custom_uploads = os.getenv("UPLOADS_DIR") or os.getenv("MEDIA_ROOT")
UPLOADS_DIR = Path(custom_uploads) if custom_uploads else PROJECT_ROOT / "uploads"
UPLOADS_ORIGINAL = UPLOADS_DIR / "original"
UPLOADS_SIGNED = UPLOADS_DIR / "signed"
UPLOADS_ANALYSIS = UPLOADS_DIR / "analysis"

custom_reports = os.getenv("REPORTS_DIR")
REPORTS_DIR = Path(custom_reports) if custom_reports else PROJECT_ROOT / "reports"

# Organized Media Storage Hierarchy
MEDIA_DIR = PROJECT_ROOT / "media"
MEDIA_ORIGINALS = MEDIA_DIR / "originals"
MEDIA_SIGNED = MEDIA_DIR / "signed_documents"
MEDIA_PACKAGES = MEDIA_DIR / "signature_packages"
MEDIA_ANALYSIS = MEDIA_DIR / "analysis_uploads"

ALL_STORAGE_DIRS = [
    UPLOADS_ORIGINAL,
    UPLOADS_SIGNED,
    UPLOADS_ANALYSIS,
    REPORTS_DIR,
    MEDIA_DIR,
    MEDIA_ORIGINALS,
    MEDIA_SIGNED,
    MEDIA_PACKAGES,
    MEDIA_ANALYSIS
]

for dir_path in ALL_STORAGE_DIRS:
    dir_path.mkdir(parents=True, exist_ok=True)

# Configurable Replay Attack Detection Thresholds
REPLAY_WINDOW_MINUTES = int(os.getenv("REPLAY_WINDOW_MINUTES", "15"))
REPLAY_THRESHOLD_COUNT = int(os.getenv("REPLAY_THRESHOLD_COUNT", "4"))

