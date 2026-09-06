# Q-SHIELD Security Platform

**Quantum-Inspired Cyber Threat Detection for Digital Signature Security**
*Smart India Hackathon (SIH) Defense & Cybersecurity Prototype*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)](https://www.typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🛡️ Executive Summary

**Q-SHIELD** is an enterprise-grade cybersecurity platform engineered to protect critical digital signature infrastructure against tampering, forgery, identity impersonation, and high-frequency replay attacks.

The platform uniquely unifies **rigorous classical public-key cryptography (RSA-2048, X.509, SHA-256)** with a **100% deterministic, zero-AI/ML quantum-inspired mathematical analytical core** operating on complex Hilbert space state vectors.

---

## 📑 Comprehensive Documentation Suite

| Document | Description |
|:---|:---|
| **[System Architecture](docs/ARCHITECTURE.md)** | 5-layer defensive pipeline, data flow diagrams, database schema, audit chain |
| **[Quantum-Inspired Model](docs/QUANTUM_INSPIRED_MODEL.md)** | Hilbert space formulation, basis states, Pauli operators, Born rule, disclaimers |
| **[Threat Detection Engine](docs/THREAT_DETECTION.md)** | Threat catalog, deterministic detection rules, composite risk scoring formula |
| **[Attack Simulation Module](docs/ATTACK_SIMULATION.md)** | Controlled attack testing environment, supported attack modes, defensive metrics |
| **[REST API Reference](docs/API_DOCUMENTATION.md)** | Complete OpenAPI / Swagger endpoints, request/response structures, auth |
| **[Installation & Setup](docs/INSTALLATION.md)** | Step-by-step local setup for Windows, Linux, and macOS |
| **[SIH Demonstration Guide](docs/DEMO_GUIDE.md)** | 7 SIH jury demonstration scenarios with concrete clicks and expected outputs |
| **[SIH Presentation Notes](docs/SIH_PRESENTATION_NOTES.md)** | Pitch script, USP summary, defense jury FAQs, answering tough questions |
| **[Testing & Verification](docs/TESTING.md)** | Automated test suites across all components with instructions |
| **[Production Deployment](docs/DEPLOYMENT.md)** | Docker Compose multi-container deployment, Nginx proxy, hardening guide |

---

## 🏛️ Five-Layer Defensive Architecture

```
                      Uploaded Document / Signature Package
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Classical Cryptographic Verification (RSA / PyHanko / X.509)        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Multi-Format Document Integrity (SHA-256 Digest Verification)      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: PKI Certificate & Key Status Validation                            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 4: Quantum-Inspired Hilbert Space Analysis (Pauli Disturbance Metrics)│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 5: Historical Threat & Replay Anomaly Detector                        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
                     Deterministic Verdict & Risk Score (0-100)
                     Tamper-Evident SHA-256 Audit Log Record
```

---

## ⚡ Quickstart Guide

### 1. Backend Setup & Seeding
```bash
cd backend
python -m pip install -r requirements.txt
python seed_demo_data.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend API**: `http://127.0.0.1:8000`
- **Swagger Documentation**: `http://127.0.0.1:8000/docs`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
- **Web Application**: `http://localhost:5173`

### 3. Docker Compose (Alternative)
```bash
docker-compose up -d --build
```

---

## 👥 Demonstration Credentials

| Role | Email | Password | Primary Dashboard |
|:---|:---|:---|:---|
| **Super Admin** | `admin@qshield.com` | `AdminPassword123!` | Audit Chain, System Metrics, User Management |
| **Security Analyst** | `analyst@qshield.com` | `AnalystPassword123!` | Document Analysis, Threat Engine, Simulations |
| **Digital Signer** | `user@qshield.com` | `UserPassword123!` | Digital Signature Generator, Document Registry |
| **Guest / External** | `guest@external.test` | `GuestPassword123!` | RBAC Unauthorized Access Testing |

---

## 🧪 Automated Testing

Q-SHIELD includes an end-to-end automated testing suite with 100% pass rate:
```bash
cd backend
# Final Integration Suite (20-step lifecycle & 7 SIH scenarios)
python test_step8_final_integration.py

# Quantum Mathematical Core Tests
python quantum_engine/test_quantum_core.py

# Database & Cryptographic Verification Tests
python test_step4_db_integration.py

# Quantum Threat Engine Tests
python test_step5_quantum_threat_engine.py

# Controlled Attack Simulation Tests
python test_step6_attack_simulation.py

# Security Reports & Tamper-Evident Audit Hash Chain Tests
python test_step7_reports_and_audit.py
```

---

## ⚖️ Scientific Disclaimer

> Q-SHIELD's quantum-inspired engine is a pure software mathematical simulation executing deterministic operations in linear algebra. It does not require or claim the existence of physical quantum hardware or cryogenic QPUs. Classical documents and cryptographic signatures exist as classical data, but their security parameters are mathematically mapped into Hilbert space to exploit quantum analytical constructs (orthogonality, fidelity, projective disturbance).
