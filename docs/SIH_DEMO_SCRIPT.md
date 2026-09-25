# Q-SHIELD — SIH Live Demonstration Script

## Demonstration Overview
- **Target Duration**: 5 to 7 minutes
- **Audience**: Smart India Hackathon (SIH) Evaluation Jury / Defense Cryptographic Reviewers
- **Demonstrator Persona**: Lead Security Analyst
- **Demo URL**: `http://localhost:5173`
- **Backend URL**: `http://127.0.0.1:8000`
- **Login Credentials**:
  - **Email**: `analyst@qshield.com`
  - **Password**: `AnalystPassword123!`

---

## Timed Walkthrough Schedule

```
┌──────────────┬────────────────────────────────────────────┬─────────────────────────────┐
│ Timestamp    │ Demonstration Phase                        │ Focus Area                  │
├──────────────┼────────────────────────────────────────────┼─────────────────────────────┤
│ 00:00 – 01:00│ Executive Introduction & Architecture      │ Problem context & 0% AI/ML  │
│ 01:00 – 02:30│ Multi-Qubit QDS Protocol Demonstration     │ KeyGen, Sign, Teleport, Ver │
│ 02:30 – 04:00│ Live Quantum Attack Simulation             │ Baseline vs Forgery/BitFlip │
│ 04:00 – 05:00│ Non-Repudiation Multi-Verifier Proof       │ Bob vs Charlie discrepancy  │
│ 05:00 – 06:00│ Cryptographic Chained Audit Ledger         │ SHA-256 tamper-evident log  │
│ 06:00 – 07:00│ Scientific Summary & Jury Q&A Defense      │ Determinism & Q&A readiness │
└──────────────┴────────────────────────────────────────────┴─────────────────────────────┘
```

---

### Phase 1: Executive Introduction & Login (00:00 – 01:00)

#### Actions:
1. Open browser to `http://localhost:5173`.
2. Enter email `analyst@qshield.com` and password `AnalystPassword123!`.
3. Click **Sign In**.
4. Land on the **Executive Dashboard**.

#### What to Say:
> *"Respected members of the jury, digital signatures are the cryptographic foundation of government orders, banking transactions, and defense communications. However, classical signature verification is strictly binary—it reports whether a signature passed or failed, but offers zero physical or mathematical insight into in-flight manipulation, state perturbation, or forgery.*
>
> *Q-SHIELD bridges this gap through a 5-layer cyber defense platform. We combine standard classical PKI (RSA-2048 and X.509) with a 100% deterministic, zero-AI/ML quantum-inspired analytical core operating in Hilbert space.*
>
> *We explicitly emphasize: Q-SHIELD does not claim to run on physical cryogenic quantum hardware, nor do we rely on unpredictable AI/ML neural networks. We model quantum mechanical principles—such as Bell-state entanglement, quantum teleportation, and Pauli disturbances—purely through linear algebra to achieve continuous, mathematically auditable threat detection."*

---

### Phase 2: Multi-Qubit QDS Protocol Workflow (01:00 – 02:30)

#### Actions:
1. In the left navigation sidebar, click on **QDS Protocol**.
2. **Step 1: Key Generation**:
   - Set Key Length to `8` qubits.
   - Click **Generate Quantum Keys**.
   - Point out the generated private key pairs $(K_0, K_1)$ and public state vectors on the screen.
3. **Step 2: Sign Document**:
   - Enter document text: `"URGENT: AUTHORIZE DEFENSE DISPATCH #9042"`.
   - Click **Sign Document with QDS**.
   - Point out the computed SHA-256 hash and the selected quantum signature states.
4. **Step 3: Quantum Teleportation**:
   - Click **Teleport Signature**.
   - Show the shared Bell-pair entanglement, the Bell-State Measurement (BSM) outcomes, and the classical Pauli correction bits $(c_x, c_z)$ transmitted over the channel.
5. **Step 4: Projective Verification**:
   - Click **Perform Projective Verification**.
   - Show the verification outcome:
     - Decision: `VERIFIED_AUTHENTIC`
     - Mismatch Rate: `0.00%` (well below threshold $S_a = 0.10$)
     - Fidelity: `1.0000` (exceeding minimum $0.90$)
     - Risk Score: `0.0 / 100` (`LOW`)

#### What to Say:
> *"Here on the QDS Protocol Dashboard, we simulate a complete multi-qubit teleportation-based signature workflow.*
>
> *In Step 1, Alice generates quantum private keys and prepares public state vectors in Hilbert space. In Step 2, she hashes the document with SHA-256 and maps the hash bits directly to signature states.*
>
> *In Step 3, instead of sending quantum states over an insecure classical wire, Alice entangles each signature qubit with a shared Bell pair $|\Phi^+\rangle$ and performs a Bell-state measurement. The signature is teleported, and 2 classical correction bits are transmitted.*
>
> *In Step 4, Bob applies Pauli corrections ($\sigma_X^{c_x} \sigma_Z^{c_z}$) and executes Born-rule projective measurements. Because no adversary interfered, the mismatch rate is exactly 0.00%, fidelity is 1.0000, and our composite risk engine scores this as 0.0 LOW risk."*

---

### Phase 3: Live Quantum Attack Simulation (02:30 – 04:00)

#### Actions:
1. In the sidebar, click on **Attack Simulation**.
2. **Run Baseline (Clean)**:
   - Select Attack Type: **None (Clean Baseline)**.
   - Click **Run Simulation**.
   - Point out the green card: Mismatch $0.00\%$, Fidelity $1.0000$, Threat: `None`, Risk Score $0.0$.
3. **Run Forgery Attack**:
   - Select Attack Type: **Signature Forgery**.
   - Click **Run Simulation**.
   - Point out the immediate red alert:
     - Mismatch Rate: $\approx 50.0\%$ (drastically exceeds $S_a = 0.10$)
     - State Disturbance: $\approx 0.50$
     - Threat Classification: `FORGERY`
     - Composite Risk Score: $\ge 85.0$ (`CRITICAL`)
4. **Run Bit-Flip Attack**:
   - Select Attack Type: **Bit-Flip ($\sigma_X$)**.
   - Click **Run Simulation**.
   - Point out the detection of Pauli $\sigma_X$ operator perturbation with $100\%$ mismatch on affected qubits and elevated risk.

#### What to Say:
> *"Now we transition from normal operations to our simulated cyber threat laboratory.*
>
> *First, we ran our clean baseline, confirming zero false positives.*
>
> *Next, we simulate an active digital signature forgery. An adversary attempts to forge Alice's signature without possessing her private quantum keys. Because quantum states cannot be cloned due to the No-Cloning Theorem, the adversary's state guesses collapse under Bob's projective measurements.*
>
> *Our statistical engine immediately detects a 50% mismatch rate and a TVD anomaly. Notice how our composite risk engine automatically adds the QDS penalty, driving the risk score to CRITICAL ($\ge 85$). This proves deterministic detection with zero AI/ML ambiguity."*

---

### Phase 4: Non-Repudiation Multi-Verifier Proof (04:00 – 05:00)

#### Actions:
1. Navigate back to **QDS Protocol** or the **Non-Repudiation** panel.
2. Click **Run Multi-Verifier Non-Repudiation Test**.
3. Inspect the comparison table showing:
   - Verifier 1 (Bob) mismatch rate: $\epsilon_{\text{Bob}}$
   - Verifier 2 (Charlie) mismatch rate: $\epsilon_{\text{Charlie}}$
   - Inter-verifier discrepancy: $|\epsilon_{\text{Bob}} - \epsilon_{\text{Charlie}}|$
   - Non-repudiation threshold: $S_v = 0.05$
   - Status: `REPUDIATION_PROTECTED`

#### What to Say:
> *"A fundamental requirement in SIH Problem Statement is non-repudiation in a multi-party scheme. What if a dishonest signer (Alice) signs a contract, sends one quantum key to Bob and a different key to Charlie, and later denies her signature to one of them?*
>
> *Q-SHIELD implements a multi-verifier cross-validation protocol. Bob and Charlie independently verify their teleported states and compare their respective mismatch rates. If the discrepancy exceeds our strict repudiation threshold of $S_v = 0.05$, Alice's repudiation attempt is immediately caught and mathematically flagged."*

---

### Phase 5: Cryptographic Chained Audit Ledger (05:00 – 06:00)

#### Actions:
1. In the sidebar, click on **Audit Logs**.
2. Scroll through the ledger displaying recent events (KeyGen, Verification, Attack Simulation).
3. Point out the `current_hash` and `previous_hash` columns.
4. Click the **Verify Hash Chain** button at the top right.
5. Point out the green badge: **"Cryptographic Audit Chain Intact (All Hashes Valid)"**.

#### What to Say:
> *"In digital forensics and national defense, the audit trail itself is a primary target for sophisticated adversaries who attempt to delete their tracks.*
>
> *Every event in Q-SHIELD is linked through a cryptographic SHA-256 hash pointer chain, identical in structure to a blockchain ledger. Each log's hash is computed over its event data concatenated with the hash of the preceding record.*
>
> *When we click 'Verify Hash Chain', the engine traverses the entire table from the genesis record to the latest event. Any unauthorized database modification, row insertion, or deletion immediately breaks the cryptographic chain."*

---

### Phase 6: Conclusion & Jury Defense (06:00 – 07:00)

#### What to Say:
> *"To conclude, Q-SHIELD delivers a complete, end-to-end cyber threat detection platform for digital signature security:*
> 1. *It satisfies every mathematical mandate of the SIH problem statement, including Bell-state entanglement, teleportation, Pauli corrections, and projective measurements.*
> 2. *It detects 5 distinct cyber threat vectors: forgery, signer impersonation, replay attacks, channel perturbations, and signer repudiation.*
> 3. *It operates with 100% mathematical determinism—zero hallucinations, zero probabilistic AI/ML black boxes.*
> 4. *All 91 unit and integration tests are passing, and both the FastAPI backend and React frontend are fully operational.*
>
> *Thank you. We are now ready for your questions."*
