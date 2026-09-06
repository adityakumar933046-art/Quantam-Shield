# Q-SHIELD Deployment & Production Hardening Guide

## 1. Production Architecture Overview

In a production environment, Q-SHIELD is deployed using containerized microservices behind an Nginx reverse proxy with HTTPS termination:

```
Clients (HTTPS :443) ──► Nginx Reverse Proxy ──┬──► Frontend SPA Container (Static files)
                                                └──► Backend FastAPI Container (:8000)
                                                           │
                                                           └──► PostgreSQL DB Container (:5432)
```

---

## 2. Docker Compose Quickstart

The easiest way to deploy Q-SHIELD in production is via Docker Compose.

### 2.1 Clone Repository and Prepare Environment
```bash
cp .env.example .env
```
Edit `.env` to supply strong secrets:
```ini
SECRET_KEY="generate-strong-64-character-random-hex"
FERNET_KEY="generate-valid-fernet-key"
DATABASE_URL="postgresql://qshield_user:qshield_secure_pass@db:5432/qshield"
```

### 2.2 Launch Multi-Container Stack
```bash
docker-compose up -d --build
```
This builds and starts:
1. `qshield-backend` (FastAPI, Uvicorn, Python 3.11)
2. `qshield-frontend` (Nginx serving compiled React bundle)
3. `qshield-db` (PostgreSQL 15)

---

## 3. Security Hardening Checklist

1. **Secret Key Isolation**:
   - Never commit `.env` or production private keys to version control.
   - Use secrets management (e.g., Docker Secrets, HashiCorp Vault, AWS Secrets Manager).

2. **Database At-Rest Encryption**:
   - User private keys in the `keypairs` table are encrypted using 256-bit AES via cryptography Fernet keys.

3. **Tamper-Evident Audit Logs**:
   - Keep audit logs on an immutable volume or forward logs via syslog to an external SIEM (Splunk, Elastic).

4. **HTTPS / TLS Configuration**:
   - Ensure TLS 1.3 is enforced with modern cipher suites in `nginx.conf`.
   - Forward `X-Forwarded-For` headers so the backend audit engine records authentic client IP addresses.
