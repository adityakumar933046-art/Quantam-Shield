# Q-SHIELD Quantum-Inspired Mathematical Model

## 1. Scientific Principles & Theoretical Framework

Q-SHIELD utilizes a **quantum-inspired analytical framework** rooted in linear algebra and Hilbert space state geometry.

> [!NOTE]
> **Scientific Disclosure**:
> Q-SHIELD's quantum-inspired engine is a pure software mathematical simulation executing deterministic operations in linear algebra. It does not require or claim the existence of physical quantum hardware or cryogenic QPUs. Classical documents and cryptographic signatures exist as classical data, but their security parameters are mathematically mapped into Hilbert space to exploit quantum analytical constructs (orthogonality, fidelity, projective disturbance).

---

## 2. Mathematical State Representation

### 2.1 Qubit State Space ($\mathbb{C}^2$)
A security state is represented as a normalized unit vector in a 2-dimensional complex Hilbert space $\mathcal{H}_2$:

$$|\psi\rangle = \alpha |0\rangle + \beta |1\rangle, \quad \alpha, \beta \in \mathbb{C}$$

subject to the normalization constraint:

$$\langle\psi|\psi\rangle = |\alpha|^2 + |\beta|^2 = 1$$

### 2.2 Computational Basis States
- **Secure / Valid Ground State**:
  $$|0\rangle = \begin{pmatrix} 1 \\ 0 \end{pmatrix}$$
- **Compromised / Threat State**:
  $$|1\rangle = \begin{pmatrix} 0 \\ 1 \end{pmatrix}$$

### 2.3 Superposition & Pauli Eigenstates
- **X-Basis (Diagonal)**:
  $$|+\rangle = \frac{1}{\sqrt{2}}(|0\rangle + |1\rangle) = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ 1 \end{pmatrix}$$
  $$|-\rangle = \frac{1}{\sqrt{2}}(|0\rangle - |1\rangle) = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ -1 \end{pmatrix}$$
- **Y-Basis (Circular)**:
  $$|+i\rangle = \frac{1}{\sqrt{2}}(|0\rangle + i|1\rangle) = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ i \end{pmatrix}$$
  $$|-i\rangle = \frac{1}{\sqrt{2}}(|0\rangle - i|1\rangle) = \frac{1}{\sqrt{2}}\begin{pmatrix} 1 \\ -i \end{pmatrix}$$

---

## 3. Pauli Disturbance Operations

Perturbations in security state vectors are modeled using Hermitian Pauli operators:

$$\sigma_I = \begin{pmatrix} 1 & 0 \\ 0 & 1 \end{pmatrix}, \quad \sigma_X = \begin{pmatrix} 0 & 1 \\ 1 & 0 \end{pmatrix}, \quad \sigma_Y = \begin{pmatrix} 0 & -i \\ i & 0 \end{pmatrix}, \quad \sigma_Z = \begin{pmatrix} 1 & 0 \\ 0 & -1 \end{pmatrix}$$

### Physical Interpretation in Security Analysis:
1. **$\sigma_X$ (Bit-Flip Disturbance)**: Models complete data alteration or hash discrepancy ($|0\rangle \leftrightarrow |1\rangle$).
2. **$\sigma_Z$ (Phase-Flip Disturbance)**: Models identity metadata or certificate signer mismatches without altering the raw digest ($|1\rangle \leftrightarrow -|1\rangle$).
3. **$\sigma_Y$ (Compound Bit-and-Phase Disturbance)**: Models coordinated attacks involving both content tampering and signer impersonation.

---

## 4. Quantum Metrics & Born's Rule

### 4.1 Quantum State Fidelity
The fidelity between expected state $|\psi\rangle$ and observed state $|\phi\rangle$ measures their mathematical closeness:

$$F(|\psi\rangle, |\phi\rangle) = |\langle\psi|\phi\rangle|^2$$

- When $|\psi\rangle = |\phi\rangle$, $F = 1.0$ (Zero disturbance, completely authentic).
- When $|\psi\rangle \perp |\phi\rangle$, $F = 0.0$ (Complete orthogonal divergence, severe breach).

### 4.2 State Disturbance Metric
The state disturbance score quantifies deviation from ideal cryptographic integrity:

$$D(|\psi\rangle, |\phi\rangle) = 1 - F(|\psi\rangle, |\phi\rangle) = 1 - |\langle\psi|\phi\rangle|^2, \quad D \in [0.0, 1.0]$$

### 4.3 Born's Rule Projective Measurements
Using projection operators onto the computational basis $\{P_0 = |0\rangle\langle 0|, P_1 = |1\rangle\langle 1|\}$:

$$P(\text{Secure}) = \text{Tr}(P_0 |\psi\rangle\langle\psi|) = |\langle 0|\psi\rangle|^2 = |\alpha|^2$$
$$P(\text{Threat}) = \text{Tr}(P_1 |\psi\rangle\langle\psi|) = |\langle 1|\psi\rangle|^2 = |\beta|^2$$

---

## 5. Parameter Mapping from Cryptographic Evidence

Security parameters extracted from classical inspection are deterministically mapped into state vector amplitudes:

| Classical Cryptographic Parameter | Metric Weight | Security Mapping |
|:---|:---|:---|
| Mathematical Signature Verification | $w_{\text{sig}} = 0.35$ | $1.0$ if RSA check valid, $0.0$ if invalid |
| Document Hash Integrity | $w_{\text{hash}} = 0.30$ | $1.0$ if current hash == stored hash, $0.0$ if mismatch |
| PKI Certificate Trust & Validity | $w_{\text{cert}} = 0.15$ | $1.0$ if trusted & unexpired, $0.0$ if untrusted/expired |
| Signer Identity Match | $w_{\text{id}} = 0.10$ | $1.0$ if public key matches owner, $0.0$ if mismatch |
| Historical Verification Velocity | $w_{\text{vel}} = 0.10$ | $1.0$ if normal frequency, decreases under replay burst |

$$\alpha = \sqrt{\sum_i w_i \cdot x_i}, \quad \beta = \sqrt{1 - \alpha^2}$$

$$|\psi_{\text{security}}\rangle = \alpha |0\rangle + \beta |1\rangle$$

---

## 6. Two-Qubit Entangled States (Bell States)

For decoupled channel transmission and Quantum Digital Signature (QDS) simulations:

$$|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle), \quad |\Phi^-\rangle = \frac{1}{\sqrt{2}}(|00\rangle - |11\rangle)$$
$$|\Psi^+\rangle = \frac{1}{\sqrt{2}}(|01\rangle + |10\rangle), \quad |\Psi^-\rangle = \frac{1}{\sqrt{2}}(|01\rangle - |10\rangle)$$

Eavesdropping on transmission collapses the entangled state onto a separable classical state ($F < 0.707$), which is caught by detection thresholds.
