# Q-SHIELD — SIH Defense & Technical Evaluation FAQ

This document prepares the team for rigorous technical interrogation by the Smart India Hackathon (SIH) jury, cybersecurity defense experts, and cryptographic evaluators. Every answer cites concrete code evidence from the Q-SHIELD repository.

---

### Q1: Are you running on physical cryogenic quantum hardware, or is this a simulation?
**Answer**:
Q-SHIELD is a **software-based mathematical simulation** running on classical hardware. We model quantum mechanical principles—complex state vectors in Hilbert space ($\mathcal{H}_2$), Bell-state entanglement, unitary Pauli operations, and Born-rule projective measurements—using NumPy numerical linear algebra.

**Code Evidence**:
- `backend/quantum_engine/states.py`: Complex state vectors with $\|\psi\|^2 = 1.0$.
- `backend/quantum_engine/bell_states.py`: Canonical 4-dimensional Bell basis.
- `backend/app/core/qds_engine.py`: Teleportation simulation using tensor products and projective measurements.
- We maintain full scientific transparency: neither QPU access nor cryogenic hardware is claimed.

---

### Q2: If classical RSA-2048 and SHA-256 already work, why do you need quantum-inspired metrics?
**Answer**:
Classical cryptographic verification is strictly **binary** (Pass or Fail). When a classical signature fails, it provides zero insight into:
1. *How* it failed (accidental channel noise vs malicious forgery).
2. *What axis* of perturbation occurred (bit alteration vs identity spoofing).
3. Continuous risk gradation prior to total cryptographic failure.

By mapping cryptographic parameters into complex Hilbert space:
- Document content alteration manifests as **Pauli $\sigma_X$ bit-flip disturbances**.
- Signer identity spoofing manifests as **Pauli $\sigma_Z$ phase-flip disturbances**.
- Eavesdropping manifests as **measurement state collapse** and Total Variation Distance ($\text{TVD}$) anomalies.
This yields continuous quantitative risk telemetry rather than a blind binary rejection.

---

### Q3: Why is there zero AI/ML in Q-SHIELD? Isn't AI preferred for cyber threat detection?
**Answer**:
In mission-critical defense, digital forensics, and courtrooms, **probabilistic AI/ML models are a liability**:
- Neural networks are "black boxes" prone to hallucinations, adversarial evasion, and non-deterministic outputs.
- In legal proceedings, an expert witness cannot explain *why* a neural network assigned a $0.87$ fraud probability.

Q-SHIELD is **100% deterministic**. Given identical cryptographic inputs, the exact same state vector, disturbance score, and risk rating are produced every single time. Every decision is grounded in verifiable linear algebra and statistical bounds ($\chi^2$, $\text{TVD}$, Born's rule).

---

### Q4: How does your quantum teleportation simulation work mathematically?
**Answer**:
For each signature qubit $|\psi\rangle = \alpha|0\rangle + \beta|1\rangle$:
1. Alice and Bob share an entangled Bell pair $|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$.
2. The 3-qubit joint state is $|\psi\rangle \otimes |\Phi^+\rangle$.
3. Alice performs a Bell-State Measurement (BSM) on her two qubits, yielding one of four classical bit pairs $(c_x, c_z) \in \{00, 01, 10, 11\}$.
4. Alice transmits $(c_x, c_z)$ to Bob over a classical channel.
5. Bob applies the Pauli unitary correction operator $\sigma_X^{c_x} \sigma_Z^{c_z}$ to his qubit, perfectly recovering $|\psi\rangle$.

**Code Evidence**:
- Defined in `backend/app/core/qds_engine.py` within `teleport_qubit()`.
- Validated with unit tests in `tests/test_qds_core.py` showing fidelity $F = 1.000000 \pm 10^{-6}$.

---

### Q5: What are your exact detection thresholds and where are they defined?
**Answer**:
All thresholds are centralized in a single source of truth in `backend/app/core/qds_engine.py` and exposed via the `GET /api/qds/thresholds` REST endpoint:
- **Verification Threshold ($S_a$)**: `0.10` (10% maximum acceptable mismatch rate).
- **Non-Repudiation Threshold ($S_v$)**: `0.05` (5% maximum cross-verifier discrepancy).
- **Disturbance Threshold ($D$)**: `0.20` (Disturbance $D \ge 0.20$ triggers channel manipulation alerts).
- **Minimum Acceptable Fidelity ($F$)**: `0.90` ($F < 0.90$ indicates degraded state fidelity).
- **TVD Anomaly Threshold**: `0.15` (Total Variation Distance $\ge 0.15$ indicates distribution skew).
- **Chi-Square Minimum Sample Size**: $N \ge 20$ shots with expected count $E_i \ge 5.0$.

---

### Q6: How do you detect a digital signature forgery attack?
**Answer**:
Due to the **Quantum No-Cloning Theorem** and the indistinguishability of non-orthogonal quantum states, an adversary who does not possess Alice's private keys cannot determine or clone her signature states. If an adversary attempts to forge a signature by transmitting randomly generated quantum states, Bob's projective Born-rule measurement will disagree with probability $P_{\text{error}} \approx 0.50$ (50%). Because $0.50 \gg S_a (0.10)$, the forgery is rejected with mathematical certainty and flagged as `ThreatType.FORGERY`.

**Code Evidence**:
- `simulate_forgery_attack()` in `backend/app/core/qds_engine.py`.
- Verified in `tests/test_qds_attacks.py::test_forgery_attack_detection`.

---

### Q7: How do you differentiate between a bit-flip attack and a phase-flip attack?
**Answer**:
- **Bit-Flip ($\sigma_X$)**: Inverts $|0\rangle \leftrightarrow |1\rangle$. In the computational basis $\{|0\rangle, |1\rangle\}$, this produces a direct measurement mismatch on affected qubits ($\epsilon \approx 1.0$).
- **Phase-Flip ($\sigma_Z$)**: Maps $|0\rangle \to |0\rangle$ and $|1\rangle \to -|1\rangle$. In the computational basis, $|0\rangle$ and $|1\rangle$ probabilities are invariant ($|\alpha|^2$ and $|-\beta|^2 = |\beta|^2$). However, when evaluated in the conjugate Hadamard basis $\{|+\rangle, |-\rangle\}$, the phase flip inverts $|+\rangle \leftrightarrow |-\rangle$.
- Q-SHIELD measures Pauli disturbance observables $\langle\sigma_X\rangle, \langle\sigma_Y\rangle, \langle\sigma_Z\rangle$ in `backend/quantum_engine/pauli_operations.py` to isolate the exact perturbation axis.

---

### Q8: How does the Intercept-Resend eavesdropping simulation work?
**Answer**:
When an eavesdropper (Eve) intercepts qubits in transit, she must measure them to extract information. By the **Heisenberg uncertainty principle** and projective measurement collapse:
1. If Eve measures in the computational basis, she collapses any superposition states.
2. If Alice prepared conjugate states, Eve's measurement induces a $25\%$ error rate when Bob subsequently verifies the states.
3. In Q-SHIELD, `simulate_intercept_resend_attack()` simulates Eve measuring each qubit with probability $p_{\text{intercept}}$ and resending the collapsed post-measurement state.
4. The resulting mismatch rate $\epsilon \ge 0.25$ exceeds $S_a = 0.10$, exposing Eve's presence.

---

### Q9: How do you prevent signer repudiation in a multi-party scheme?
**Answer**:
Signer repudiation occurs when a dishonest Alice signs a document, transmits valid signature keys to Bob, but transmits invalid or differing keys to Charlie, allowing her to later claim to Charlie that she never signed the document.
Q-SHIELD mitigates this via a two-verifier cross-validation protocol:
1. Alice signs document $M$ and sends signature state sets $S_{\text{Bob}}$ and $S_{\text{Charlie}}$.
2. Bob and Charlie independently verify their received states, obtaining mismatch rates $\epsilon_{\text{Bob}}$ and $\epsilon_{\text{Charlie}}$.
3. The inter-verifier discrepancy $|\epsilon_{\text{Bob}} - \epsilon_{\text{Charlie}}|$ is calculated.
4. If $|\epsilon_{\text{Bob}} - \epsilon_{\text{Charlie}}| > S_v (0.05)$, the platform flags `SIGNER_REPUDIATION_ATTEMPT`.

**Code Evidence**:
- `verify_non_repudiation()` in `backend/app/core/qds_engine.py`.
- Tested in `tests/test_qds_attacks.py::test_repudiation_detection`.

---

### Q10: How does your composite risk engine calculate risk scores?
**Answer**:
The risk engine uses a weighted sum of classical and quantum factors, plus an additive QDS penalty:

$$\text{Composite Risk} = \min\left(100.0, \; \sum_{i} \frac{w_i \cdot r_i}{\sum_k w_k} + c_{\text{QDS}}\right)$$

- **Weights**: Classical Sig ($0.25$), Digest Integrity ($0.25$), Public Key ($0.10$), Cert ($0.08$), Replay ($0.08$), Activity ($0.06$), Disturbance ($0.08$), Pauli ($0.05$), Forgery ($0.05$).
- **Additive QDS Penalty ($c_{\text{QDS}}$)**:
  - If mismatch rate $\epsilon > S_a (0.10)$, add $20.0 \times \frac{\epsilon - S_a}{1 - S_a}$. If $\epsilon \ge 0.40$, floor at $85.0$.
  - If disturbance $D \ge 0.20$, add $10.0 \times \min(1.0, \frac{D}{0.50})$. If $D \ge 0.50$, floor at $80.0$.
- **Severity Tiers**: `LOW` ($[0, 30)$), `MEDIUM` ($[30, 60)$), `HIGH` ($[60, 85)$), `CRITICAL` ($[85, 100]$).

---

### Q11: What happens if a third-party signature without a registered public key is verified?
**Answer**:
Many legacy scanners erroneously flag unknown signatures as malicious forgeries. Q-SHIELD handles this cleanly:
- It classifies missing public keys as `UNKNOWN_SIGNATURE` or `PUBLIC_KEY_NOT_FOUND`.
- It assigns a moderate base risk score of $30.0$ (`MEDIUM`), prompting the analyst to import the signer's public key or certificate.
- It never falsely accuses legitimate external signers of hostile forgery.

---

### Q12: How does the tamper-evident audit logging prevent database manipulation?
**Answer**:
Every security action is recorded in the `audit_logs` table using a cryptographic SHA-256 hash pointer chain:

$$\text{Hash}_n = \text{SHA256}(\text{id} \parallel \text{event\_id} \parallel \text{user\_email} \parallel \text{action} \parallel \text{result} \parallel \text{details} \parallel \text{previous\_hash} \parallel \text{timestamp})$$

- If an attacker gains direct SQL access and modifies or deletes a row, the `previous_hash` pointer of all subsequent rows becomes invalid.
- The `GET /api/v1/audit/verify-chain` endpoint traverses the chain from genesis to the latest record, instantly detecting any alteration and pinpointing the exact corrupted event ID.

---

### Q13: What is the computational performance and latency of QDS operations?
**Answer**:
- **Key Generation & Signing**: $< 15\text{ ms}$ for standard 8 to 16 qubit key lengths.
- **Bell Teleportation & Pauli Correction**: $< 20\text{ ms}$ for multi-qubit payloads.
- **Projective Verification & Statistics**: $< 10\text{ ms}$ for 1000 projective measurement shots.
- **End-to-End REST Roundtrip**: $< 60\text{ ms}$ on local localhost network.
- Memory consumption is minimal: state vectors reside in lightweight NumPy complex arrays without background leaks.

---

### Q14: How does Q-SHIELD inspect classical PDF documents?
**Answer**:
Q-SHIELD integrates the **PyHanko** cryptographic inspection engine:
- Verifies ISO 32000-1 / PKCS#7 CMS detached signatures embedded in PDF byte ranges.
- Computes bitwise SHA-256 hash digests across the signed byte range to detect incremental content tampering.
- Inspects X.509 certificate chains, validity dates, subject DNs, and key usage constraints.

---

### Q15: Can Q-SHIELD be integrated into existing enterprise or defense PKI workflows?
**Answer**:
Yes. Q-SHIELD is architected as an API-first microservice:
- Exposes standard OpenAPI (Swagger) compliant REST endpoints.
- Secures all communications via JWT bearer authentication and granular RBAC.
- Can be deployed as a Docker container behind an enterprise reverse proxy (Nginx/Traefik).
- Works as an inspection sidecar to existing document management and digital signing pipelines.
