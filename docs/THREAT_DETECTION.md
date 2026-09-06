# Q-SHIELD Threat Detection Engine

## 1. Multi-Layer Threat Detection Architecture

The Q-SHIELD Threat Detection Engine operates on an evidence-based, deterministic decision engine. It evaluates digital signatures and documents across 5 independent defensive layers to produce transparent, auditable security verdicts.

```
Evidence Acquisition (L1, L2, L3) ──► Quantum Disturbance Analysis (L4) ──► Temporal Velocity (L5) ──► Threat Synthesis
```

---

## 2. Threat Catalog & Detection Rules

### 2.1 `DOCUMENT_TAMPERING` (Severity: CRITICAL)
- **Description**: Document content modified after digital signature generation.
- **Detection Mechanism**:
  $$\text{Hash}_{\text{computed}} \neq \text{Hash}_{\text{expected}}$$
  The cryptographic digest computed over the current file does not match the digest recorded at signing time or stored within the signed envelope.
- **Pauli Perturbation**: Large $\sigma_X$ disturbance ($D_X \approx 1.0$).
- **Risk Impact**: Instant escalation to $\ge 88.0$ (CRITICAL).

### 2.2 `FORGERY` (Severity: CRITICAL)
- **Description**: Cryptographic digital signature value fails mathematical verification against the signer's public key.
- **Detection Mechanism**:
  $$\text{Verify}_{\text{RSA}}(\text{Public\_Key}, \text{Digest}, \text{Signature}) = \text{False}$$
- **Pauli Perturbation**: High combined disturbance ($D \ge 0.70$).
- **Risk Impact**: Escalate to $\ge 90.0$ (CRITICAL).

### 2.3 `UNKNOWN_SIGNATURE` (Severity: INFORMATIONAL / MEDIUM)
- **Important Specification Rule**: Untracked or unknown signatures from third-party keys are **NOT** falsely flagged as malicious forgery.
- **Verdict**: Labeled as `UNKNOWN_SIGNATURE` / `PUBLIC_KEY_NOT_FOUND` with a moderate baseline score ($30.0$, MEDIUM), prompting analyst manual key import.

### 2.4 `REPLAY_ATTACK` (Severity: HIGH)
- **Description**: Legitimate signature repeatedly submitted within an anomalous burst window.
- **Detection Mechanism**:
  $$\text{Count}(\text{Doc\_Hash}, \Delta t \le 10\text{ min}) \ge 6 \implies \text{REPLAY\_ATTACK}$$
- **Confidence**: Scales dynamically with velocity $V = \frac{N}{\Delta t}$.
- **Risk Impact**: Adds $+35.0$ risk penalty, escalating to HIGH/CRITICAL.

### 2.5 `IMPERSONATION` (Severity: HIGH / CRITICAL)
- **Description**: Claimed signer identity in document metadata does not match the certified owner of the signing key.
- **Detection Mechanism**:
  $$\text{Subject}(\text{Cert}) \neq \text{Claimed\_Signer} \quad \lor \quad \text{Fingerprint}(\text{Key}) \neq \text{Authorized\_Signer\_Key}$$
- **Pauli Perturbation**: Phase disturbance $\sigma_Z$ ($D_Z \ge 0.50$).

### 2.6 `CERTIFICATE_PROBLEM` (Severity: MEDIUM / HIGH)
- **Description**: Signing X.509 certificate expired, not yet valid, self-signed without trust root, or untrusted issuer.
- **Detection Mechanism**:
  $$t_{\text{current}} < t_{\text{not\_before}} \quad \lor \quad t_{\text{current}} > t_{\text{not\_after}}$$

---

## 3. Composite Risk Scoring Formula

The platform calculates a deterministic composite risk score $\mathcal{R} \in [0, 100]$:

$$\mathcal{R} = w_1 \cdot (1 - S_{\text{crypto}}) \cdot 40 + w_2 \cdot (1 - I_{\text{integrity}}) \cdot 35 + w_3 \cdot D_{\text{quantum}} \cdot 15 + w_4 \cdot R_{\text{replay}} \cdot 10$$

Where:
- $S_{\text{crypto}} \in \{0, 1\}$ (Cryptographic validity)
- $I_{\text{integrity}} \in \{0, 1\}$ (Digest match)
- $D_{\text{quantum}} \in [0, 1]$ (State disturbance)
- $R_{\text{replay}} \in [0, 1]$ (Replay frequency ratio)

### Risk Classification Thresholds

| Risk Score ($\mathcal{R}$) | Risk Level | Operational Action |
|:---|:---|:---|
| **$0.0 - 24.9$** | **LOW** | Verified authentic; approved for downstream processing |
| **$25.0 - 49.9$** | **MEDIUM** | Informational anomaly or unknown signer; review recommended |
| **$50.0 - 74.9$** | **HIGH** | Replay suspicion or certificate violation; quarantine document |
| **$75.0 - 100.0$** | **CRITICAL** | Tampering or forgery detected; reject and trigger security incident |
