# Q-SHIELD REST API Documentation

## 1. API Conventions & Authentication

- **Base URL**: `http://127.0.0.1:8000/api`
- **Interactive Swagger UI**: `http://127.0.0.1:8000/docs`
- **Interactive ReDoc**: `http://127.0.0.1:8000/redoc`
- **Authentication**: HTTP Authorization Header with Bearer JWT:
  ```http
  Authorization: Bearer <access_token>
  ```

---

## 2. Authentication & Identity Endpoints

### `POST /api/auth/login`
Authenticates user and returns JWT bearer token.
- **Request Body**:
  ```json
  {
    "email": "analyst@qshield.com",
    "password": "AnalystPassword123!"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "user": {
      "user_id": 3,
      "email": "analyst@qshield.com",
      "full_name": "Senior Security Analyst",
      "role": "SECURITY_ANALYST"
    }
  }
  ```

### `GET /api/auth/me`
Returns current authenticated user profile.

---

## 3. Digital Signature Generation Endpoints

### `POST /api/signatures/create/`
Generates a real cryptographic signature for an uploaded file or raw text string.
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file`: (Optional UploadFile) Binary document (PDF, TXT, JSON).
  - `raw_text`: (Optional string) Direct text string to sign.
  - `filename`: (Optional string) Preferred document name.
- **Response (200 OK)**:
  ```json
  {
    "signature_id": "QSHIELD-SIGN-8F32A1C9",
    "document_id": 142,
    "original_filename": "contract.txt",
    "file_type": "TXT",
    "hash_algorithm": "SHA-256",
    "document_hash": "4a18018e612c6a0eb292d3f38bc5b9df0d0b04e6c2780e90ea2189d2d8544c06",
    "signature_algorithm": "RSA-SHA256",
    "signature_value": "c2lnbmF0dXJlX2J5dGVzX2Jhc2U2NA==",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
    "public_key_fingerprint": "SHA256:4f8e21a0b3c79e658392019ab921c3fe",
    "status": "SIGNED",
    "signed_at": "2026-09-06T09:15:00Z",
    "download_url": "/api/signatures/QSHIELD-SIGN-8F32A1C9/download"
  }
  ```

---

## 4. Verification & Security Analysis Endpoints

### `POST /api/verify/analyze/`
Full 5-layer end-to-end cryptographic and quantum-inspired threat inspection.
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file`: (Optional UploadFile) Document file (PDF, TXT, signed JSON).
  - `raw_text`: (Optional string) Raw payload or signed message.
  - `signature`: (Optional string) Detached signature base64.
  - `signature_id`: (Optional string) Target signature ID reference.
- **Response (200 OK)**:
  ```json
  {
    "analysis_id": "QSHIELD-ANALYSIS-3982A1B7",
    "analysis_document_id": 184,
    "signature_id": "QSHIELD-SIGN-8F32A1C9",
    "original_file_name": "contract.signed.txt",
    "file_type": "TXT",
    "current_hash": "4a18018e612c6a0eb292d3f38bc5b9df0d0b04e6c2780e90ea2189d2d8544c06",
    "stored_hash": "4a18018e612c6a0eb292d3f38bc5b9df0d0b04e6c2780e90ea2189d2d8544c06",
    "signature_verified": true,
    "integrity_verified": true,
    "certificate_status": "VALID",
    "public_key_status": "VALID",
    "risk_score": 10.0,
    "risk_level": "LOW",
    "final_decision": "VALID",
    "threats": []
  }
  ```

---

## 5. Controlled Attack Simulation Endpoints

### `POST /api/simulations/execute/`
Executes an isolated attack simulation and benchmarks detection accuracy.
- **Request Body**:
  ```json
  {
    "attack_type": "DOCUMENT_TAMPERING",
    "target_document_reference": "sample_contract.txt",
    "parameters": {
      "tamper_mode": "CHAR_FLIP"
    }
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "simulation_id": "SIM-8492019A",
    "attack_type": "DOCUMENT_TAMPERING",
    "status": "COMPLETED",
    "result": {
      "detection_success": true,
      "detection_status": "DETECTED",
      "signature_valid": false,
      "integrity_valid": false,
      "state_disturbance": 0.95,
      "final_risk_score": 92.0,
      "final_risk_level": "CRITICAL",
      "threats_detected": [
        {
          "threat_category": "DOCUMENT_TAMPERING",
          "severity": "CRITICAL"
        }
      ]
    }
  }
  ```

---

## 6. Audit Logs & Reports Endpoints

### `POST /api/reports/generate`
Generates an audit report (`ANALYSIS_REPORT`, `THREAT_REPORT`, `SIMULATION_REPORT`, `PERFORMANCE_REPORT`).

### `GET /api/admin/audit-logs`
Retrieves cryptographically chained tamper-evident audit logs (Admin only).

### `GET /api/admin/audit-logs/verify-integrity`
Verifies SHA-256 hash pointer integrity across the entire audit journal:
```json
{
  "status": "AUDIT_LOG_VALID",
  "total_records_verified": 2553,
  "chain_intact": true,
  "verified_at": "2026-09-06T09:20:00Z"
}
```
