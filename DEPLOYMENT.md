# Q-SHIELD Security Platform — Production Deployment Guide

This document provides complete instructions for deploying the **Q-SHIELD Security Platform** in production:
- **Frontend**: [Vercel](https://vercel.com) (React + TypeScript + Vite)
- **Backend**: [Render](https://render.com) (Python + FastAPI + Uvicorn)
- **Database**: [Render Managed PostgreSQL](https://render.com/docs/databases) (with SQLite maintained for local development)
- **Repository**: [Quantam-Shield on GitHub](https://github.com/adityakumar933046-art/Quantam-Shield.git)

---

## Architecture Overview

```mermaid
graph LR
    User[Web Browser] -->|HTTPS| Vercel[Vercel Frontend: React + Vite SPA]
    Vercel -->|REST API / HTTPS| Render[Render Web Service: FastAPI + Uvicorn]
    Render -->|SQL Connection| Postgres[(Render Managed PostgreSQL)]
    Render -->|Storage| Disk[Storage: /uploads & /media]
```

---

## Part A: Local Development Setup

### 1. Backend Setup (Local)
```bash
cd backend
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Local SQLite database will be initialized automatically at `backend/database/qshield.db`.
- Default credentials will be seeded on first launch:
  - **Super Admin**: `admin@qshield.com` / `Admin@123`
  - **Security Analyst**: `analyst@qshield.com` / `Analyst@123`
  - **Digital Signature User**: `user@qshield.com` / `User@123`

### 2. Frontend Setup (Local)
```bash
cd frontend
npm install
npm run dev
```
- Open `http://localhost:5173`.
- Requests to `/api` are automatically proxied by Vite to `http://127.0.0.1:8000`.

---

## Part B: GitHub Repository Preparation

Ensure your latest production-ready changes are committed and pushed to GitHub:

```bash
git status
git add .
git commit -m "Prepare Q-SHIELD for Render, Vercel, and PostgreSQL deployment"
git push origin main
```

Verified `.gitignore` ensures that:
- `.env` files, credentials, and private keys are never committed.
- Local SQLite `.db` files and ephemeral uploads are excluded.

---

## Part C: Backend Deployment on Render

### Method 1: Blueprint Deployment via `render.yaml` (Recommended)
1. Log in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\to$ **Blueprint**.
3. Connect your repository: `https://github.com/adityakumar933046-art/Quantam-Shield.git`.
4. Render will read `render.yaml` and automatically configure:
   - Managed PostgreSQL database (`qshield-db`)
   - Web Service (`qshield-backend`) linked to the database
5. Click **Apply**.

### Method 2: Manual Web Service Setup
1. **Create PostgreSQL Database on Render**:
   - Go to **New +** $\to$ **PostgreSQL**.
   - Name: `qshield-postgres`
   - Database: `qshield_db`
   - User: `qshield_user`
   - Region: Select closest to your users (e.g. `Oregon (US West)`).
   - Plan: Free or Starter.
   - Click **Create Database**.
   - Copy the **Internal Database URL** (or External Database URL if needed).

2. **Create Web Service on Render**:
   - Go to **New +** $\to$ **Web Service**.
   - Connect repository: `Quantam-Shield`.
   - Configure settings:
     | Setting | Value |
     | :--- | :--- |
     | **Name** | `qshield-backend` |
     | **Region** | Same region as your database |
     | **Branch** | `main` |
     | **Root Directory** | `backend` |
     | **Runtime** | `Python 3` |
     | **Build Command** | `pip install -r requirements.txt` |
     | **Start Command** | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
     | **Health Check Path**| `/api/health` |

3. **Configure Backend Environment Variables** in Render Dashboard:
   | Variable | Example / Description |
   | :--- | :--- |
   | `DATABASE_URL` | Value copied from Render PostgreSQL (e.g., `postgresql://...`) |
   | `SECRET_KEY` | Strong random 64-char string (e.g. `openssl rand -hex 32`) |
   | `ENVIRONMENT` | `production` |
   | `CORS_ORIGINS` | Your Vercel frontend URL, e.g. `https://quantam-shield.vercel.app` |

4. Click **Create Web Service**. Wait for the build to finish. Once live, copy your backend URL (e.g. `https://qshield-backend.onrender.com`).

---

## Part D: PostgreSQL Environment Variables & Automated Seeding

When Render provisions PostgreSQL, it provides a connection string formatted as:
```text
postgres://qshield_user:password@dpg-xxx.render.com/qshield_db
```
Q-SHIELD automatically converts legacy `postgres://` protocols to `postgresql://` as required by SQLAlchemy 2.0.

### Database Initialization
- On first startup, `init_and_migrate_db()` executes `Base.metadata.create_all(bind=engine)` to create all tables.
- If the user database is clean, the platform idempotently seeds the default credentials:
  - **Super Admin**: `admin@qshield.com` / `Admin@123`
  - **Security Analyst**: `analyst@qshield.com` / `Analyst@123`
  - **Digital Signature User**: `user@qshield.com` / `User@123`
- Genesis audit event `SYSTEM_INIT` is recorded.

---

## Part E: Frontend Deployment on Vercel

1. Log in to [Vercel](https://vercel.com).
2. Click **Add New...** $\to$ **Project**.
3. Import the GitHub repository: `Quantam-Shield`.
4. In the project configuration modal:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click **Edit** and select `frontend` (or leave default if deploying root monorepo).
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. **Environment Variables**:
   Add the following environment variable:
   | Variable Name | Value |
   | :--- | :--- |
   | `VITE_API_URL` | `https://qshield-backend.onrender.com` (Your Render backend URL) |
6. Click **Deploy**.
7. Once deployed, note your Vercel URL (e.g., `https://quantam-shield.vercel.app`).

---

## Part F: Connecting Frontend to Backend & CORS Synchronization

1. Return to your **Render Dashboard** $\to$ **qshield-backend** $\to$ **Environment**.
2. Update the `CORS_ORIGINS` variable with your actual Vercel domain:
   ```env
   CORS_ORIGINS=https://quantam-shield.vercel.app,http://localhost:5173
   ```
3. Save changes. Render will perform an automated zero-downtime rolling restart.
4. Open your Vercel URL in your browser:
   - Navigate to `/login`.
   - Log in as `analyst@qshield.com` / `Analyst@123`.
   - Verify that the Security Dashboard, Report Catalog, and QDS Simulation load live data from your Render backend.

---

## Part G: Master Environment Variable Reference

### Backend (`Render`):
| Key | Required | Default / Description |
| :--- | :---: | :--- |
| `DATABASE_URL` | Yes (Prod) | PostgreSQL connection URI. If omitted, falls back to local SQLite. |
| `SECRET_KEY` | Yes (Prod) | Random 64-byte hex string used for JWT signature generation. |
| `ENVIRONMENT` | Optional | `production` or `development`. |
| `CORS_ORIGINS` | Yes (Prod) | Comma-separated list of allowed frontend origins (e.g. `https://your-app.vercel.app`). |
| `CORS_ORIGIN_REGEX` | Optional | Regex pattern for preview deployments (default: `https://.*\.vercel\.app`). |
| `PORT` | Auto (Render) | Port on which FastAPI listens (assigned automatically by Render). |
| `UPLOADS_DIR` | Optional | Custom path if using a persistent volume disk. |
| `REPORTS_DIR` | Optional | Custom path for generated PDF reports. |

### Frontend (`Vercel`):
| Key | Required | Default / Description |
| :--- | :---: | :--- |
| `VITE_API_URL` | Yes (Prod) | URL of your deployed Render backend (e.g. `https://qshield-backend.onrender.com`). |

---

## Verification Checklist

- [x] Backend dependency tree includes `psycopg2-binary>=2.9.9`.
- [x] Backend dynamically configures SQLite (local) or PostgreSQL (Render).
- [x] Start command binds to `$PORT` via `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- [x] CORS properly configured without unrestricted wildcard when credentials are exchanged.
- [x] Frontend `VITE_API_URL` dynamically routed through `frontend/src/services/api.ts`.
- [x] `vercel.json` SPA rewrites redirect all client routes to `/index.html`.
- [x] Zero sensitive credentials or private keys in repository.
- [x] `npm run build` passes with 0 TypeScript/bundler errors.
