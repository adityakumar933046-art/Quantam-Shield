import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.db import engine, Base, init_and_migrate_db
from app.api import auth, users, signature, security, audit, documents, security_analysis, qds_simulation, canonical_routes, attack_simulations, reports, dashboard

# Ensure database tables are created and migrated
init_and_migrate_db()

app = FastAPI(
    title="Q-SHIELD Security Platform API",
    description="Backend APIs for Quantum-Inspired Digital Signature Cyber Threat Detection Platform",
    version="3.0.0"
)

# Dynamic CORS Configuration for Local Development and Production (Vercel / Render)
raw_cors = os.getenv("CORS_ORIGINS", "").strip()
if raw_cors:
    allowed_origins = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]

# Vercel preview environments support regex (e.g. https://<project-name>-<hash>.vercel.app)
cors_regex = os.getenv("CORS_ORIGIN_REGEX", r"https://.*\.vercel\.app")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=cors_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(documents.router, prefix="/api")
app.include_router(signature.router, prefix="/api")
app.include_router(security.router, prefix="/api")
app.include_router(security_analysis.router, prefix="/api")
app.include_router(canonical_routes.router, prefix="/api")
app.include_router(attack_simulations.router, prefix="/api")
app.include_router(qds_simulation.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")

@app.get("/")
def root():
    env_mode = os.getenv("ENVIRONMENT", "production" if os.getenv("RENDER") else "development")
    return {
        "status": "online",
        "platform": "Q-SHIELD Security Platform",
        "version": "3.0.0",
        "mode": env_mode
    }

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "Q-SHIELD-API"}
