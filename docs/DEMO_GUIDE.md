# Q-SHIELD SIH Demonstration & Evaluation Guide

This guide walks through the 7 core demonstration scenarios designed for SIH jury and evaluators.

---

## Preparation: Pre-Seeded Demonstration Files

Pre-fabricated demo files are available in the `demo_data/` folder:
- `demo_data/DEMO_sample_contract.txt`: Valid text contract for signing.
- `demo_data/DEMO_tampered_contract.txt`: Modified contract simulating post-signing alteration.
- `demo_data/DEMO_sample_payload.json`: Clean structured data payload.
- `demo_data/DEMO_tampered_payload.json`: JSON payload with tampered transaction value.

---

## Scenario 1: Valid Document Lifecycle & Verification

1. **Sign In**: Login as Digital Signer (`user@qshield.com` / `UserPassword123!`).
2. **Upload & Sign**:
   - Go to **Digital Signature Dashboard**.
   - Upload `demo_data/DEMO_sample_contract.txt`.
   - Click **Generate Digital Signature**.
   - Note the generated Signature ID (e.g. `QSHIELD-SIGN-XXXXXXXX`) and SHA-256 digest.
   - Download the signed package file (`signed_DEMO_sample_contract.txt`).
3. **Analyst Inspection**:
   - Switch accounts: Login as Security Analyst (`analyst@qshield.com` / `AnalystPassword123!`).
   - Navigate to **Security Analyst Inspection**.
   - Upload the downloaded signed file.
   - Click **Inspect & Verify**.
4. **Expected Verdict**:
   - **Status**: `VALID`
   - **Integrity**: `INTACT`
   - **Quantum State Consistency**: $100\%$ ($D = 0.00$)
   - **Risk Score**: $\le 10.0$ (LOW RISK)
   - **Threats**: $0$ Threats Detected

---

## Scenario 2: Document Tampering Detection

1. **Simulate Adversary Alteration**:
   - Take the downloaded signed file and edit any text character inside the payload (or upload `demo_data/DEMO_tampered_contract.txt`).
2. **Submit for Inspection**:
   - In the Analyst portal, upload the tampered file.
   - Click **Inspect & Verify**.
3. **Expected Verdict**:
   - **Status**: `INTEGRITY_MISMATCH`
   - **Integrity**: `MODIFIED`
   - **Threat Incident**: `DOCUMENT_TAMPERING` (Severity: `CRITICAL`)
   - **Pauli Perturbation**: Massive $\sigma_X$ bit-flip anomaly detected ($D_X \approx 1.0$)
   - **Risk Score**: $\ge 88.0$ (CRITICAL)

---

## Scenario 3: Signature Forgery Detection

1. **Navigate to Attack Simulations**:
   - Go to **Controlled Attack Simulations** tab.
   - Select Attack Type: **Signature Forgery**.
   - Target Document: `DEMO_sample_contract.txt`.
   - Mode: `CORRUPT_BYTES`.
   - Click **Launch Controlled Simulation**.
2. **Expected Verdict**:
   - **Detection Status**: `DETECTED`
   - **Cryptographic Signature**: `INVALID`
   - **Estimated Forgery Probability**: $\ge 40.0\%$
   - **Final Composite Risk**: $\ge 70.0$ (HIGH / CRITICAL)

---

## Scenario 4: Replay Attack (Velocity Thresholding)

1. **Trigger Replay Attack**:
   - Submit the identical valid signed document 7 consecutive times within a 30-second interval.
2. **Expected Verdict on 7th Submission**:
   - **Status**: Flagged with `REPLAY_ATTACK`
   - **Velocity Trigger**: Frequency threshold exceeded ($\ge 6$ submissions/10 min)
   - **Risk Score**: Elevated by $+35.0$ risk penalty

---

## Scenario 5: Signer Impersonation Detection

1. **Launch Impersonation Simulation**:
   - In Attack Simulations, select **Impersonation**.
   - Claimed Signer: `Chief Executive Officer (Authorized)`.
   - Verified Signer: `Untrusted External Entity (Attacker)`.
   - Click **Run Simulation**.
2. **Expected Verdict**:
   - **Detection Status**: `DETECTED`
   - **PKI Signer Mismatch**: Claimed public key fingerprint does not match verified key.
   - **Pauli $\sigma_Z$ Phase Disturbance**: Detected.

---

## Scenario 6: Unauthorized Access Attempt (RBAC)

1. **Attempt Unauthorized Action**:
   - Login as regular user (`user@qshield.com`).
   - Attempt to access Super Admin Audit Logs (`/api/admin/audit-logs`).
2. **Expected Result**:
   - HTTP `403 Forbidden` response.
   - Security incident recorded in audit chain as `UNAUTHORIZED_ACCESS_ATTEMPT`.

---

## Scenario 7: Quantum-Inspired Channel Disturbance Simulation

1. **Run Quantum Simulation**:
   - In Attack Simulations, select **Quantum Channel Manipulation**.
   - Test `PAULI_X_DISTURBANCE`, `PAULI_Z_DISTURBANCE`, and `MEASUREMENT_DISTURBANCE`.
2. **Expected Result**:
   - Bell state transmission fidelity drops from $1.0$ to $0.0$ or $0.5$.
   - Born rule measurement probability flags disturbance state with $100\%$ mathematical certainty.
