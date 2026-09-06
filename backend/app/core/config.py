import os
from pathlib import Path

# Base Directory: Q-SHIELD-SECURITY-PLATFORM root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR

# Database URL (SQLite)
DATABASE_DIR = PROJECT_ROOT / "database"
DATABASE_DIR.mkdir(exist_ok=True)
DATABASE_PATH = DATABASE_DIR / "qshield.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

# JWT Security Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "qshield_secret_key_quantum_inspired_cybersecurity_2026_super_secure")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 hours

# Storage Directories (Legacy uploads and structured media)
UPLOADS_DIR = PROJECT_ROOT / "uploads"
UPLOADS_ORIGINAL = UPLOADS_DIR / "original"
UPLOADS_SIGNED = UPLOADS_DIR / "signed"
UPLOADS_ANALYSIS = UPLOADS_DIR / "analysis"
REPORTS_DIR = PROJECT_ROOT / "reports"

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

