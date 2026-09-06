# Q-SHIELD Installation & Setup Guide

## 1. System Requirements

- **Operating System**: Windows 10/11, Ubuntu 20.04/22.04 LTS, or macOS 12+
- **Python**: Version 3.11 or higher
- **Node.js**: Version 18.x or 20.x LTS
- **Package Managers**: `pip` and `npm`

---

## 2. Backend Setup

### 2.1 Navigate to Backend Directory
```bash
cd backend
```

### 2.2 Create and Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 2.3 Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 2.4 Initialize Database & Seed Demonstration Data
Initialize tables, schemas, and pre-load realistic demonstration contracts, attack simulations, and audit records:
```bash
python seed_demo_data.py
```

### 2.5 Start Backend Application Server
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API is now online at:
- **API Base**: `http://127.0.0.1:8000`
- **Swagger Documentation**: `http://127.0.0.1:8000/docs`

---

## 3. Frontend Setup

### 3.1 Navigate to Frontend Directory
Open a second terminal window:
```bash
cd frontend
```

### 3.2 Install NPM Packages
```bash
npm install
```

### 3.3 Start Frontend Development Server
```bash
npm run dev
```
The user interface will be accessible at:
- **Local URL**: `http://localhost:5173`

---

## 4. Pre-Configured Demonstration Credentials

| Role | Email | Password | Allowed Functions |
|:---|:---|:---|:---|
| **Super Admin** | `admin@qshield.com` | `AdminPassword123!` | System config, user management, audit log verification |
| **Security Analyst** | `analyst@qshield.com` | `AnalystPassword123!` | Threat inspection, attack simulations, audit reports |
| **Digital Signer** | `user@qshield.com` | `UserPassword123!` | Upload, sign, and download signed documents |
| **Guest / External** | `guest@external.test` | `GuestPassword123!` | Read-only / test unauthorized RBAC block |
