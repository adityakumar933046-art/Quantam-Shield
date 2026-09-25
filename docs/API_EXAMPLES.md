# Q-SHIELD — QDS REST API Reference & Payload Examples

This document provides concrete, production-validated request and response payloads for all Multi-Qubit QDS REST API endpoints. All payloads strictly adhere to Pydantic V2 schemas defined in `backend/app/schemas.py`.

---

## Authentication & Headers
- **Protected Endpoints** require a Bearer token in the `Authorization` header:
  ```http
  Authorization: Bearer <JWT_ACCESS_TOKEN>
  Content-Type: application/json
  ```
- **Public Endpoints**: `/api/qds/health`, `/api/qds/thresholds`.
- **Role Requirement**: Most operational endpoints accept `DIGITAL_SIGNATURE_USER`, `SECURITY_ANALYST`, and `SUPER_ADMIN`. Certain simulation operations require `SECURITY_ANALYST` or `SUPER_ADMIN`.

---

### 1. System Health Check

- **Method**: `GET`
- **Path**: `/api/qds/health`
- **Auth**: Public (No JWT required)

#### Example Request:
```http
GET /api/qds/health HTTP/1.1
Host: 127.0.0.1:8000
```

#### Example Response (`200 OK`):
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

---

### 2. Operational Thresholds Reference

- **Method**: `GET`
- **Path**: `/api/qds/thresholds`
- **Auth**: Public (No JWT required)

#### Example Request:
```http
GET /api/qds/thresholds HTTP/1.1
Host: 127.0.0.1:8000
```

#### Example Response (`200 OK`):
```json
{
  "verification_threshold": 0.10,
  "repudiation_threshold": 0.05,
  "channel_disturbance_threshold": 0.20,
  "minimum_acceptable_fidelity": 0.90,
  "distribution_distance_anomaly_threshold": 0.15,
  "chi_square_min_sample_size": 20,
  "chi_square_min_expected_count": 5.0
}
```

---

### 3. Multi-Qubit Key Generation

- **Method**: `POST`
- **Path**: `/api/qds/key-generation`
- **Auth**: Bearer JWT (`User` or `Analyst`)

#### Example Request:
```json
{
  "key_length": 8,
  "seed": 42
}
```

#### Example Response (`200 OK`):
```json
{
  "key_id": "qds-key-b9c1d84e-3f72-4a91-9872-e104f6479b12",
  "key_length": 8,
  "protocol_version": "1.0",
  "public_key": [
    [[1.0, 0.0], [0.0, 0.0]],
    [[0.70710678, 0.0], [0.70710678, 0.0]],
    [[0.0, 0.0], [1.0, 0.0]],
    [[0.70710678, 0.0], [-0.70710678, 0.0]],
    [[1.0, 0.0], [0.0, 0.0]],
    [[0.70710678, 0.0], [0.70710678, 0.0]],
    [[0.0, 0.0], [1.0, 0.0]],
    [[0.70710678, 0.0], [-0.70710678, 0.0]]
  ],
  "basis_information": ["Z", "X", "Z", "X", "Z", "X", "Z", "X"],
  "seed": 42
}
```
*(Note: Private state pairs $K_0, K_1$ are securely held server-side in the session registry and are never transmitted over the wire).*

---

### 4. Quantum Document Signing

- **Method**: `POST`
- **Path**: `/api/qds/sign`
- **Auth**: Bearer JWT (`User` or `Analyst`)

#### Example Request:
```json
{
  "key_id": "qds-key-b9c1d84e-3f72-4a91-9872-e104f6479b12",
  "message_hash": "a1",
  "seed": 42
}
```
*(Note: Hash `"a1"` contains 2 hex characters = 8 bits, exactly matching the 8-qubit key length).*

#### Example Response (`200 OK`):
```json
{
  "signature_id": "qds-sig-7e20b3f1-482a-4389-9a4f-56f89021e892",
  "message_hash": "a1",
  "qubit_count": 8,
  "protocol_version": "1.0"
}
```

---

### 5. Multi-Qubit Quantum Teleportation

- **Method**: `POST`
- **Path**: `/api/qds/teleport`
- **Auth**: Bearer JWT (`User` or `Analyst`)

#### Example Request:
```json
{
  "signature_id": "qds-sig-7e20b3f1-482a-4389-9a4f-56f89021e892",
  "seed": 42
}
```

#### Example Response (`200 OK`):
```json
{
  "signature_id": "qds-sig-7e20b3f1-482a-4389-9a4f-56f89021e892",
  "qubit_count": 8,
  "average_fidelity": 1.0,
  "fidelities": [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
  "measurement_bits": ["00", "10", "01", "11", "00", "01", "10", "00"],
  "pauli_corrections": ["I", "Z", "X", "-iY", "I", "X", "Z", "I"],
  "success": true
}
```

---

### 6. Projective Signature Verification

- **Method**: `POST`
- **Path**: `/api/qds/verify`
- **Auth**: Bearer JWT (`User` or `Analyst`)

#### Example Request:
```json
{
  "signature_id": "qds-sig-7e20b3f1-482a-4389-9a4f-56f89021e892",
  "threshold": 0.10
}
```

#### Example Response (`200 OK`):
```json
{
  "verification": {
    "accepted": true,
    "mismatch_rate": 0.0,
    "mismatch_count": 0,
    "total_qubits": 8,
    "threshold": 0.10,
    "decision": "VERIFIED_AUTHENTIC"
  },
  "statistics": {
    "total_variation_distance": 0.0,
    "chi_square_statistic": 0.0,
    "p_value": 1.0,
    "average_fidelity": 1.0,
    "state_disturbance": 0.0
  },
  "threat": {
    "detected": false,
    "type": "NONE",
    "severity": "LOW",
    "indicators": []
  },
  "risk": {
    "composite_risk_score": 0.0,
    "tier": "LOW",
    "explanation": "Valid signature: mismatch rate within tolerance."
  }
}
```

---

### 7. Attack Simulation & Threat Assessment

- **Method**: `POST`
- **Path**: `/api/qds/attack-simulation`
- **Auth**: Bearer JWT (`Analyst` or `Super Admin`)

#### Example Request (Bit-Flip Attack):
```json
{
  "message_hash": "a1",
  "attack_type": "bit_flip",
  "key_length": 8,
  "seed": 42
}
```

#### Example Response (`200 OK`):
```json
{
  "attack_type": "bit_flip",
  "key_length": 8,
  "message_hash": "a1",
  "verification": {
    "accepted": false,
    "mismatch_rate": 1.0,
    "mismatch_count": 8,
    "total_qubits": 8,
    "threshold": 0.10,
    "decision": "SIGNATURE_REJECTED"
  },
  "statistics": {
    "total_variation_distance": 0.50,
    "chi_square_statistic": 8.0,
    "p_value": 0.0046,
    "average_fidelity": 0.0,
    "state_disturbance": 1.0
  },
  "threat": {
    "detected": true,
    "type": "QUANTUM_CHANNEL_MANIPULATION",
    "severity": "CRITICAL",
    "indicators": [
      "Mismatch rate 1.000 exceeds threshold 0.100",
      "Total Variation Distance 0.500 exceeds anomaly bound 0.150",
      "Quantum state disturbance 1.000 exceeds bound 0.200"
    ]
  },
  "risk": {
    "composite_risk_score": 95.0,
    "tier": "CRITICAL",
    "explanation": "Severe channel perturbation: 100% mismatch rate detected."
  }
}
```

---

### 8. Comparative Attack Scenarios

- **Method**: `POST`
- **Path**: `/api/qds/attack-scenarios`
- **Auth**: Bearer JWT (`Analyst` or `Super Admin`)

#### Example Request:
```json
{
  "message_hash": "a1",
  "key_length": 8,
  "seed": 42
}
```

#### Example Response (`200 OK`):
```json
{
  "message_hash": "a1",
  "key_length": 8,
  "scenarios": [
    {
      "attack_type": "none",
      "accepted": true,
      "mismatch_rate": 0.0,
      "fidelity": 1.0,
      "threat_detected": false,
      "threat_type": "NONE",
      "risk_score": 0.0,
      "risk_tier": "LOW"
    },
    {
      "attack_type": "forgery",
      "accepted": false,
      "mismatch_rate": 0.50,
      "fidelity": 0.50,
      "threat_detected": true,
      "threat_type": "DIGITAL_SIGNATURE_FORGERY",
      "risk_score": 87.5,
      "risk_tier": "CRITICAL"
    },
    {
      "attack_type": "bit_flip",
      "accepted": false,
      "mismatch_rate": 1.0,
      "fidelity": 0.0,
      "threat_detected": true,
      "threat_type": "QUANTUM_CHANNEL_MANIPULATION",
      "risk_score": 95.0,
      "risk_tier": "CRITICAL"
    },
    {
      "attack_type": "phase_flip",
      "accepted": false,
      "mismatch_rate": 0.50,
      "fidelity": 0.50,
      "threat_detected": true,
      "threat_type": "QUANTUM_CHANNEL_MANIPULATION",
      "risk_score": 87.5,
      "risk_tier": "CRITICAL"
    },
    {
      "attack_type": "intercept_resend",
      "accepted": false,
      "mismatch_rate": 0.25,
      "fidelity": 0.75,
      "threat_detected": true,
      "threat_type": "QUANTUM_CHANNEL_MANIPULATION",
      "risk_score": 75.0,
      "risk_tier": "HIGH"
    }
  ]
}
```
