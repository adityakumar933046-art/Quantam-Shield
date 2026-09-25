# Q-SHIELD

**Quantum-Inspired Cyber Threat Detection for Digital Signature Security**  
*Smart India Hackathon (SIH) Cybersecurity Prototype*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)](https://www.typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![NumPy](https://img.shields.io/badge/NumPy-1.26+-013243?logo=numpy)](https://numpy.org)
[![Vite](https://img.shields.io/badge/Vite-6.x-646CFF?logo=vite)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.x-38B2D9?logo=tailwind-css)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 1. Project Title
**Q-SHIELD: Quantum-Inspired Cyber Threat Detection for Digital Signature Security**

---

## 2. Problem Statement
Digitally signed documents (PDFs, contracts, financial instruments, government filings) form the backbone of modern electronic trust. While classical digital signature algorithms (such as RSA, ECDSA, and X.509 PKI) verify integrity and signer authenticity under static conditions, standard systems struggle to detect dynamic operational threats, including:
- **Digital signature forgery attempts** and surrogate key generation.
- **Signer impersonation** and unauthorized verification attempts.
- **High-frequency replay attacks** utilizing previously signed tokens.
- **Transmission channel manipulation** and eavesdropper interception.
- **Subtle statistical disturbances** that bypass binary pass/fail verification checks.

Q-SHIELD provides an advanced defensive security layer that unifies rigorous classical cryptographic verification with a mathematically modeled, quantum-inspired threat detection and risk-scoring engine.

---

## 3. Core Idea

```
Document / Payload
       │
       ▼
Q-SHIELD Security Engine
       ├── Classical Cryptographic Verification (RSA-2048, X.509, SHA-256)
       │     └── Bit-level document integrity & PKI certificate status
       └── Quantum-Inspired Analytical Simulation (Multi-Qubit QDS Core)
             └── Hilbert space states, Bell entanglement, Born-rule measurements
       │
       ▼
Threat Evidence Aggregator (Fidelity, Disturbance, Mismatch Rate, TVD, Chi-Square)
       │
       ▼
Deterministic Composite Risk Engine (0 – 100 Score & Tier Classification)
       │
       ▼
Tamper-Evident SHA-256 Cryptographic Audit Log & Security Report
```

> **Scientific Basis & Disclaimer:**  
> The quantum component of Q-SHIELD is a **pure software mathematical simulation** executing deterministic linear algebra on complex vectors in Hilbert space ($\mathbb{C}^2$ and $\mathbb{C}^4$). It models Bell-state entanglement, quantum teleportation, and projective Born-rule measurements using classical algorithms. **It does NOT require physical quantum hardware or cryogenic QPUs, and does NOT claim physical or unconditional quantum security.**

---

## 4. Key Features

- **Multi-Qubit Quantum Digital Signature (QDS) Simulation**: Maps cryptographic hash digests into conjugate-basis quantum states.
- **Bell-State Entanglement**: Utilizes normalized Bell pairs ($|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$) for signature teleportation.
- **Quantum Teleportation & Pauli Corrections**: Simulates joint Bell measurements and applies classical Pauli corrections ($00 \to I, 01 \to X, 10 \to Z, 11 \to XZ$).
- **Projective Measurements & Born Rule**: Evaluates detection probabilities $P = |\langle \psi | \phi \rangle|^2$ and conjugate basis measurements ($Z$ and $X$).
- **Quantum State Fidelity & Disturbance**: Quantifies transmission disturbance ($D = 1 - F$).
- **Statistical Measurement Analysis**:
  - Mismatch rate calculation ($\epsilon = \frac{\text{mismatches}}{\text{total qubits}}$).
  - Total Variation Distance ($\text{TVD} = \frac{1}{2} \sum |p_i - q_i|$).
  - Pearson's Chi-Square ($\chi^2$) goodness-of-fit with Cochran minimum sample constraints ($N \ge 20$).
- **Deterministic Threat Classification**: Flags channel manipulation, forgery attempts, eavesdropping, and repudiation discrepancies.
- **Composite Risk Scoring (0–100)**: Multi-parameter weighted risk engine with bounded risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Controlled Attack Simulation Pipeline**: Five discrete attack scenarios (`none`, `bit_flip`, `phase_flip`, `intercept_resend`, `random_state_substitution`).
- **RESTful API Architecture**: FastAPI endpoints for key generation, signing, teleportation, verification, and benchmark matrices.
- **Interactive React Dashboard**: Sequential 5-step UI, live attack simulation controls, and comparative benchmark views.
- **Role-Based Access Control (RBAC)**: Enforced authentication across Analyst, User, and Super Admin roles.
- **Classical PDF Cryptographic Verification**: Isolated PyHanko/X.509 signature analysis.

---

## 5. System Architecture

```
                                 [ User / Browser ]
                                         │
                                         ▼
                            [ React Frontend (Vite) ]
                                         │
                      REST API Calls (Bearer JWT Authorization)
                                         │
                                         ▼
                            [ FastAPI Application ]
                                         │
           ┌─────────────────────────────┼─────────────────────────────┐
           ▼                             ▼                             ▼
 [ Authentication & RBAC ]    [ Classical Security ]       [ Quantum-Inspired Core ]
 ├── JWT Token Verification   ├── PDF Signature (PyHanko)  ├── QDS Key Generation
 ├── Role Enforcement (RBAC)  ├── X.509 PKI Certificates   ├── Hash-to-Qubit Mapping
 └── Audit Log Chain          └── SHA-256 Digest Check     ├── Bell Pair Teleportation
                                                           ├── Pauli Corrections
                                                           ├── Projective Verification
                                                           ├── Statistical Engine (TVD, χ²)
                                                           ├── Threat Detector
                                                           └── Composite Risk Engine
```

---

## 6. QDS Protocol Workflow

1. **Step 1: Key Generation**  
   Alice generates a multi-qubit QDS key pair. Alice selects random conjugate bases ($Z$ or $X$) and prepares private reference states. Public reference state amplitudes and basis sequences are published; private quantum states remain server-side.
2. **Step 2: Message Digest Mapping**  
   The external payload hash digest (e.g., `a1b2c3d4`) is converted into a binary sequence $M = (m_0, m_1, \dots)$. For each bit, Alice maps $m_i = 0$ to the base state and $m_i = 1$ to the flipped basis state ($X$ flip for $Z$-basis, $Z$ flip for $X$-basis).
3. **Step 3: Bell-State Teleportation**  
   Alice shares Bell pairs $|\Phi^+\rangle$ with Bob. Alice performs joint Bell measurements, yielding classical bits ($00, 01, 10, 11$). Bob applies Pauli corrections ($I, X, Z, XZ$) to reconstruct the signature states.
4. **Step 4: Projective Measurement Verification**  
   Bob projects each received qubit onto the expected state. Mismatch count and mismatch rate $\epsilon = \frac{\text{mismatches}}{N}$ are calculated. If $\epsilon \le S_a$ (default $0.10$), verification is accepted.
5. **Step 5: Multi-Verifier Non-Repudiation**  
   A second verifier (Charlie) independently verifies the transmitted states. Bob and Charlie cross-verify results: if $|m_B - m_C| \le S_v$ (default $0.05$), non-repudiation holds.
6. **Step 6: Statistical & Threat Analysis**  
   The statistical engine evaluates fidelity $F$, disturbance $D = 1 - F$, $\text{TVD}$, and $\chi^2$ goodness-of-fit.
7. **Step 7: Composite Risk Scoring**  
   The risk engine synthesizes all findings into a deterministic risk score ($0–100$) and risk tier.

---

## 7. Mathematical Model

### Qubit Representation
$$|\psi\rangle = \alpha |0\rangle + \beta |1\rangle, \quad \alpha, \beta \in \mathbb{C}, \quad |\alpha|^2 + |\beta|^2 = 1.0$$

### Canonical Basis States
$$|0\rangle = \begin{pmatrix} 1 \\ 0 \end{pmatrix}, \quad |1\rangle = \begin{pmatrix} 0 \\ 1 \end{pmatrix}, \quad |+\rangle = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ 1 \end{pmatrix}, \quad |-\rangle = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ -1 \end{pmatrix}$$

### Bell States
$$|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle), \quad |\Phi^-\rangle = \frac{1}{\sqrt{2}}(|00\rangle - |11\rangle)$$
$$|\Psi^+\rangle = \frac{1}{\sqrt{2}}(|01\rangle + |10\rangle), \quad |\Psi^-\rangle = \frac{1}{\sqrt{2}}(|01\rangle - |10\rangle)$$

### State Fidelity
$$F(|\psi\rangle, |\phi\rangle) = |\langle \psi | \phi \rangle|^2 = \left| \sum_{k} \psi_k^* \cdot \phi_k \right|^2, \quad 0.0 \le F \le 1.0$$

### State Disturbance
$$D(|\psi\rangle, |\phi\rangle) = 1.0 - F(|\psi\rangle, |\phi\rangle), \quad 0.0 \le D \le 1.0$$

### Mismatch Rate
$$\epsilon = \frac{\text{Number of Mismatched Projective Outcomes}}{\text{Total Qubits Evaluated}}$$

### Total Variation Distance (TVD)
$$\text{TVD}(P, Q) = \frac{1}{2} \sum_{i} |p_i - q_i|$$

### Pearson's Chi-Square Goodness-of-Fit
$$\chi^2 = \sum_{i} \frac{(O_i - E_i)^2}{E_i}, \quad \text{valid if } N \ge 20 \text{ and } E_i \ge 5.0$$

### Composite Risk Score Formula
$$\text{Raw Score} = \sum_{i} \frac{w_i \cdot r_i}{\sum w_k} + c_{\text{QDS}}$$
- Weighted parameters ($w_i$): Classical Signature (0.25), Integrity (0.25), Public Key (0.10), Certificate (0.08), Replay (0.08), Activity (0.06), State Disturbance (0.08), Pauli Disturbance (0.05), Forgery Estimate (0.05).
- Additive QDS evidence penalty ($c_{\text{QDS}}$): Up to $+20$ for mismatch rate exceeding $S_a$ and $+10$ for disturbance exceeding threshold.
- Floored overrides: Severe mismatch ($\epsilon \ge 0.40$) floors raw score to $\ge 85.0$; severe disturbance ($D \ge 0.50$) floors to $\ge 80.0$.
$$\text{Final Score} = \text{round}(\max(0.0, \min(100.0, \text{Raw Score})), 2)$$

---

## 8. Attack Models

Q-SHIELD models five distinct transmission and adversarial scenarios:

| Attack Model | Mathematical Operator | Target | Description | Expected Outcome |
|---|---|---|---|---|
| `none` | $I$ (Identity) | Channel | Honest baseline transmission. | $F = 1.0$, $\epsilon = 0.0$, Accepted, Low Risk ($0.0$). |
| `bit_flip` | $X = \begin{pmatrix} 0 & 1 \\ 1 & 0 \end{pmatrix}$ | Channel | Inverts $|0\rangle \leftrightarrow |1\rangle$ via Pauli $X$. Orthogonal in $Z$-basis. | $F \approx 0.50$, $\epsilon \approx 0.50$, Rejected, Critical Risk. |
| `phase_flip` | $Z = \begin{pmatrix} 1 & 0 \\ 0 & -1 \end{pmatrix}$ | Channel | Inverts phase on $|1\rangle$. Orthogonal in $X$-basis ($|+\rangle \leftrightarrow |-\rangle$). | $F \approx 0.50$, $\epsilon \approx 0.50$, Rejected, Critical Risk. |
| `intercept_resend` | $P_0, P_1$ | Eavesdropper | Measures in computational basis, collapsing superpositions to classical states. | $F \approx 0.75$, $D \approx 0.25$, Rejected, High Risk. |
| `random_state_substitution` | Random $\{|0\rangle, |1\rangle, |+\rangle, |-\rangle\}$ | Forger | Forger substitutes qubits with random unentangled basis vectors. | $F \approx 0.50$, $\epsilon \approx 0.75$, Rejected, Critical Risk. |

*Note: Results are evaluated and detected under the current simulation model and threshold configuration.*

---

## 9. Security Thresholds

Live operational limits returned by `GET /api/qds/thresholds`:

| Threshold Constant | Backend Value | Description |
|---|---|---|
| `verification_threshold` ($S_a$) | `0.10` | Maximum acceptable projective measurement mismatch rate (10%). |
| `repudiation_threshold` ($S_v$) | `0.05` | Maximum allowable discrepancy between Bob and Charlie (5%). |
| `channel_disturbance_threshold` | `0.20` | State disturbance ($D \ge 0.20$) triggering channel manipulation alerts. |
| `minimum_acceptable_fidelity` | `0.90` | Minimum fidelity for acceptable teleportation quality. |
| `distribution_distance_anomaly_threshold` | `0.15` | Total Variation Distance threshold for statistical anomaly detection. |
| `chi_square_min_sample_size` | `20` | Minimum observations required for valid asymptotic $\chi^2$ testing. |
| `chi_square_min_expected_count` | `5.0` | Cochran criterion for minimum expected bin count. |

---

## 10. REST API Documentation

### 1. QDS Module Health
- **Endpoint**: `GET /api/qds/health`
- **Auth**: Public
- **Response**:
```json
{
  "status": "healthy",
  "protocol": "QDS",
  "quantum_engine": "available",
  "statistical_analysis": "available",
  "attack_pipeline": "available",
  "ai_ml": false
}
```

### 2. Security Thresholds
- **Endpoint**: `GET /api/qds/thresholds`
- **Auth**: Public
- **Response**:
```json
{
  "verification_threshold": 0.1,
  "repudiation_threshold": 0.05,
  "channel_disturbance_threshold": 0.2,
  "minimum_acceptable_fidelity": 0.9,
  "distribution_distance_anomaly_threshold": 0.15,
  "chi_square_min_sample_size": 20,
  "chi_square_min_expected_count": 5.0
}
```

### 3. Generate QDS Key Pair
- **Endpoint**: `POST /api/qds/key-generation`
- **Auth**: Bearer JWT (Any logged-in user)
- **Request**:
```json
{ "key_length": 32, "seed": 42 }
```
- **Response**:
```json
{
  "key_id": "qds-key-4a9f1c8e2b0d",
  "key_length": 32,
  "protocol_version": "QDS-TP-1.0",
  "public_key": [[0.707107, 0.0, 0.707107, 0.0], "..."],
  "basis_information": ["Z", "X", "Z", "..."],
  "seed": 42
}
```

### 4. Create Quantum Signature
- **Endpoint**: `POST /api/qds/sign`
- **Auth**: Bearer JWT
- **Request**:
```json
{ "key_id": "qds-key-4a9f1c8e2b0d", "message_hash": "a1b2c3d4" }
```
- **Response**:
```json
{
  "signature_id": "qds-sig-7f3c2e1a9b0d",
  "message_hash": "a1b2c3d4",
  "qubit_count": 32,
  "protocol_version": "QDS-TP-1.0"
}
```

### 5. Teleport Quantum Signature
- **Endpoint**: `POST /api/qds/teleport`
- **Auth**: Bearer JWT
- **Request**:
```json
{ "signature_id": "qds-sig-7f3c2e1a9b0d", "seed": 42 }
```
- **Response**:
```json
{
  "signature_id": "qds-sig-7f3c2e1a9b0d",
  "qubit_count": 32,
  "average_fidelity": 1.0,
  "fidelities": [1.0, 1.0, "..."],
  "measurement_bits": ["00", "01", "..."],
  "pauli_corrections": ["I", "X", "..."],
  "success": true
}
```

### 6. Verify Quantum Signature
- **Endpoint**: `POST /api/qds/verify`
- **Auth**: Bearer JWT
- **Request**:
```json
{ "signature_id": "qds-sig-7f3c2e1a9b0d", "threshold": 0.10 }
```
- **Response**:
```json
{
  "verification": {
    "accepted": true,
    "mismatch_rate": 0.0,
    "threshold": 0.1,
    "matches": 32,
    "mismatches": 0
  },
  "statistics": {
    "accuracy": 1.0,
    "distribution_distance": 0.0,
    "chi_square": null,
    "chi_square_status": "insufficient_sample_size"
  },
  "threat": {
    "detected": false,
    "type": null,
    "severity": "LOW",
    "explanation": "No significant disturbance or basis mismatch detected."
  },
  "risk": {
    "score": 0.0,
    "tier": "LOW"
  }
}
```

### 7. Run Attack Simulation
- **Endpoint**: `POST /api/qds/attack-simulation`
- **Auth**: Bearer JWT
- **Request**:
```json
{
  "message_hash": "a1b2c3d4",
  "attack_type": "bit_flip",
  "key_length": 32,
  "seed": 42
}
```

### 8. Run Attack Benchmark Matrix
- **Endpoint**: `POST /api/qds/attack-scenarios`
- **Auth**: Bearer JWT
- **Request**:
```json
{ "message_hash": "a1b2c3d4", "key_length": 32, "seed": 42 }
```

---

## 11. Frontend Demonstration Workflow

Access the web interface at `http://localhost:5173`:
1. **Login**: Authenticate at `/login` with credentials (e.g., `analyst@qshield.com` / `AnalystPassword123!`).
2. **Navigate**: Select **Quantum Simulation** (`/security/qds-simulation`).
3. **Step 2 (Key Gen)**: Select 32 qubits, generate QDS key pair, review basis distribution.
4. **Step 3 (Sign)**: Provide or select hex digest `a1b2c3d4`, generate signature.
5. **Step 4 (Teleport)**: Execute Bell-state teleportation, observe $100\%$ fidelity and Pauli corrections.
6. **Step 5 (Verify)**: Run projective verification, observe "Verification Accepted", $0\%$ mismatch, Low Risk.
7. **Tab 2 (Attacks)**: Select `bit_flip`, execute attack simulation, observe "Verification Rejected", disturbance $50\%$, Critical Risk.
8. **Tab 3 (Benchmark)**: Run the 5-scenario benchmark matrix, compare detection rates and metrics side-by-side.
9. **Tab 4 (Thresholds)**: View live mathematical thresholds retrieved from the backend API.

---

## 12. Technology Stack

### Backend
- **Python**: 3.11+
- **FastAPI**: 0.115+ (Asynchronous ASGI Web Framework)
- **Uvicorn**: 0.34+ (ASGI Server)
- **Pydantic**: 2.10+ (Data Validation & Serialization)
- **NumPy**: 1.26+ (Vector & Matrix Linear Algebra)
- **SQLAlchemy**: 2.0+ (Database ORM)
- **PyJWT & Passlib / Bcrypt**: Cryptographic Token & Password Hashing
- **PyHanko & Cryptography**: Classical PDF & X.509 Cryptographic Verification

### Frontend
- **React**: 18.3+ (Single Page Application)
- **TypeScript**: 5.7+ (Strict Type-Safe Frontend Architecture)
- **Vite**: 6.1+ (Frontend Build Tool & Dev Server)
- **Tailwind CSS**: 3.4+ (Responsive Visual Design System)
- **Axios**: 1.7+ (HTTP Client with JWT Interceptors)
- **Lucide React**: 0.475+ (UI Icons)

---

## 13. Zero AI/ML Declaration

Q-SHIELD does **NOT** use:
- Machine learning or deep learning models
- Neural networks, classifiers, or heuristics
- Large Language Models (LLMs)
- Stochastic or non-deterministic AI estimators

All threat classifications, projective measurement calculations, and composite risk scores are derived strictly from **deterministic linear algebra and classical statistical mechanics**.

---

## 14. Classical & Quantum Separation

Q-SHIELD maintains strict separation between layers:
- **Classical Layer**: Handles PDF structure parsing, X.509 digital certificates, PKI trust chains, and SHA-256 document hashing. Classical RSA/PyHanko operations remain standard and functional.
- **Quantum-Inspired Layer**: Receives external hash digests and evaluates them within Hilbert space state vectors for transmission integrity, teleportation simulation, and quantum-inspired threat modeling.

---

## 15. Limitations & Future Scope

- **Classical Simulation**: Executes on classical CPUs using NumPy; does not require or communicate with physical quantum QPUs.
- **Bell Pair Mode**: Currently models pairwise $|\Phi^+\rangle$ entanglement channels; expansion to multi-party GHZ/W entanglement networks represents future work.
- **In-Memory Registry**: Prototype key and signature registries reside in server process memory. Multi-server production deployments would leverage an encrypted Redis distributed cache.
- **Dual-Verifier Model**: Implements Bob & Charlie cross-verification; scaling to $N$-party verifier networks is supported by the mathematical architecture.

---

## 16. Test Verification Results

All 91 automated test cases pass with 100% precision:
- `test_quantum_core.py`: **10/10 Passed** (Hilbert space, Born rule, Bell states, Pauli algebra)
- `test_qds_protocol.py`: **18/18 Passed** (Multi-qubit QDS, teleportation, projective verification)
- `test_qds_statistical_analysis.py`: **18/18 Passed** (TVD, $\chi^2$, threat evidence, risk bounds)
- `test_qds_attack_pipeline.py`: **16/16 Passed** (Attack simulations, separability, benchmarks)
- `test_step5_quantum_threat_engine.py`: **100% Passed** (Composite risk scoring)
- `test_step8_qds.py`: **9/9 Passed** (Step 8 protocol verification & classical decoupling)
- `test_qds_api_integration.py`: **20/20 Passed** (Full REST API integration & RBAC checks)
- **Frontend TypeScript & Production Build**: `npx tsc --noEmit` (**0 errors**), `npm run build` (**clean build**).

---

## 17. Local Setup & Execution

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate   # On Windows
# source venv/bin/activate  # On Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Run FastAPI backend server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: `http://127.0.0.1:8000`
- Swagger Documentation: `http://127.0.0.1:8000/docs`

### 2. Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run Vite development server
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 18. Scientific Disclaimer

> **Notice:** This project is a classical software mathematical simulation of quantum-inspired concepts designed for cybersecurity research, education, and SIH prototype demonstration. It does not perform quantum hardware communication, does not deploy physical qubits, and does not claim unconditional or information-theoretic physical security.
