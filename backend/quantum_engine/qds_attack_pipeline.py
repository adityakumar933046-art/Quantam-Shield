"""
Unified End-to-End Quantum Digital Signature (QDS) Attack Simulation Pipeline.

Module: quantum_engine.qds_attack_pipeline
Executes complete 10-step cryptographic simulation:
1. Generate QDS key pair
2. Create QDS quantum signature from message digest
3. Distribute Bell states and teleport signature qubits
4. Inject simulated adversary attack (None, Random Substitution, Bit Flip, Phase Flip, Intercept-Resend)
5. Receive and verify quantum signature with conjugate-basis projective measurement
6. Perform deterministic statistical measurement analysis (mismatch rate, TVD, Chi-square)
7. Construct structured QDS threat evidence object
8. Evaluate rule-based threat classification
9. Compute composite risk score and tier
10. Return structured security assessment for visualization and auditing

Scientific Note:
This is a software simulation of theoretical quantum communication and digital signatures.
Contains NO AI/ML models. No unverified claims of physical quantum hardware or information-
theoretic security beyond the mathematical bounds of the implemented protocol.
"""

from dataclasses import dataclass, asdict, field
import random
from typing import Dict, Any, List, Optional, Sequence, Union
import numpy as np

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    STATE_PLUS,
    STATE_MINUS,
    state_fidelity,
    normalize_state,
)
from quantum_engine.pauli_operations import (
    apply_x,
    apply_z,
)
from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    QDS_REPUDIATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD,
    get_qds_thresholds,
)
from quantum_engine.qds_protocol import (
    generate_qds_key_pair,
    sign_hash_qds,
    teleport_signature,
    verify_signature_qds,
    forge_qds_signature,
    hex_to_bit_sequence,
    generate_random_state_from_allowed_set,
    QDSKeyPair,
    QDSSignature,
    TeleportationResult,
    QDSVerificationResult,
)
from quantum_engine.measurement_analysis import (
    analyze_qds_measurements,
    calculate_total_variation_distance,
    calculate_chi_square,
)
from quantum_engine.threat_detector import (
    build_qds_threat_evidence,
    evaluate_qds_threats,
    evaluate_deterministic_threats,
    analyze_quantum_channel_attack,
)
from quantum_engine.forgery_probability import (
    calculate_qds_forgery_probability_estimate,
    calculate_forgery_probability_estimate,
)
from quantum_engine.risk_engine import (
    calculate_composite_risk_score,
)


SUPPORTED_QDS_ATTACKS = [
    "none",
    "random_state_substitution",
    "bit_flip",
    "phase_flip",
    "intercept_resend",
]


# ==============================================================================
# PIPELINE RESULT STRUCTURES
# ==============================================================================

@dataclass
class QDSAttackSimulationResult:
    """
    Standardized result structure for end-to-end QDS attack simulation.
    """
    protocol: str
    attack_type: str
    seed: Optional[int]
    signature: Dict[str, Any]
    teleportation: Dict[str, Any]
    verification: Dict[str, Any]
    statistics: Dict[str, Any]
    threat: Dict[str, Any]
    risk: Dict[str, Any]
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "seed": self.seed,
            "signature": self.signature,
            "teleportation": self.teleportation,
            "verification": self.verification,
            "statistics": self.statistics,
            "threat": self.threat,
            "risk": self.risk,
            "evidence": self.evidence,
        }


# ==============================================================================
# CORE END-TO-END SIMULATION PIPELINE
# ==============================================================================

def run_qds_attack_simulation(
    message_hash: str,
    attack_type: str = "none",
    key_length: int = 32,
    seed: Optional[int] = None,
    threshold: float = QDS_VERIFICATION_THRESHOLD
) -> Dict[str, Any]:
    """
    Executes a complete unified end-to-end QDS attack evaluation pipeline.

    Pipeline Steps:
        1. Generate QDS key pair
        2. Create QDS quantum signature from message digest
        3. Teleport signature qubits via Bell-state entanglement and Pauli correction
        4. Inject selected adversarial attack
        5. Verify received states with conjugate-basis projective measurements
        6. Compute empirical statistical metrics (mismatch rate, TVD, Chi-square)
        7. Assemble standardized QDS threat evidence
        8. Evaluate threat classification (Forgery, Channel Manipulation, or None)
        9. Calculate composite risk score and risk tier (LOW/MEDIUM/HIGH/CRITICAL)
        10. Return comprehensive security assessment dictionary

    Supported Attacks:
        - "none": Nominal honest quantum teleportation and signature verification.
        - "random_state_substitution": Replaces signature qubits with random valid states.
        - "bit_flip": Applies Pauli X to transmitted qubits.
        - "phase_flip": Applies Pauli Z to transmitted qubits (observable in X-basis).
        - "intercept_resend": Projective measurement collapse and retransmission by Eve.

    Args:
        message_hash: Hexadecimal message digest string (e.g. 'a1b2c3d4').
        attack_type: Adversary attack scenario to inject.
        key_length: Number of qubits in key pair (must be >= message hash bits).
        seed: Optional integer seed for 100% deterministic reproducibility.
        threshold: Permissible mismatch threshold (default 0.10).

    Returns:
        Dict adhering to QDS platform attack simulation specification.
    """
    clean_attack = str(attack_type).strip().lower()
    if clean_attack not in SUPPORTED_QDS_ATTACKS:
        raise ValueError(
            f"Unsupported attack type '{attack_type}'. "
            f"Must be one of {SUPPORTED_QDS_ATTACKS}."
        )

    # Validate inputs
    bit_sequence = hex_to_bit_sequence(message_hash)
    req_qubits = len(bit_sequence)

    if not isinstance(key_length, int) or key_length < 1:
        raise ValueError(f"Key length must be a positive integer >= 1, got {key_length}.")

    if key_length < req_qubits:
        raise ValueError(
            f"Key length ({key_length}) is insufficient for message hash "
            f"bit length ({req_qubits})."
        )

    # Deterministic sub-seed derivation if seed provided
    if seed is not None:
        rng = random.Random(seed)
        key_seed = rng.randint(0, 10_000_000)
        teleport_seed = rng.randint(0, 10_000_000)
        attack_seed = rng.randint(0, 10_000_000)
    else:
        key_seed = None
        teleport_seed = None
        attack_seed = None

    # -------------------------------------------------------------------------
    # STEP 1: Generate QDS Key Pair
    # -------------------------------------------------------------------------
    key_pair = generate_qds_key_pair(length=key_length, seed=key_seed)

    # -------------------------------------------------------------------------
    # STEP 2: Generate QDS Signature
    # -------------------------------------------------------------------------
    signature = sign_hash_qds(message_hash, key_pair)

    # -------------------------------------------------------------------------
    # STEP 3: Teleport Signature
    # -------------------------------------------------------------------------
    teleport_res = teleport_signature(signature.signature_states, seed=teleport_seed)
    transmitted_states = [np.copy(s) for s in teleport_res.received_states]

    # -------------------------------------------------------------------------
    # STEP 4: Inject Attack on Transmitted States
    # -------------------------------------------------------------------------
    intercept_resend_flag = False
    pauli_error_flag = False

    if clean_attack == "none":
        attacked_states = transmitted_states

    elif clean_attack == "random_state_substitution":
        attack_rng = random.Random(attack_seed)
        attacked_states = [
            generate_random_state_from_allowed_set(rng=attack_rng)[1]
            for _ in transmitted_states
        ]

    elif clean_attack == "bit_flip":
        # Pauli X applied to all transmitted qubits
        attacked_states = [apply_x(s) for s in transmitted_states]
        pauli_error_flag = True

    elif clean_attack == "phase_flip":
        # Pauli Z applied to all transmitted qubits
        # Note on Quantum Mechanics:
        # In the Z-basis, Z|0> = |0> and Z|1> = -|1> (global phase -1, fidelity = 1.0, mismatch = 0).
        # In the X-basis, Z|+> = |-> and Z|-> = |+> (orthogonal phase flip, fidelity = 0.0, mismatch = 1).
        # Therefore, phase errors are observable only when the verifier measures in conjugate X-basis.
        attacked_states = [apply_z(s) for s in transmitted_states]
        pauli_error_flag = True

    elif clean_attack == "intercept_resend":
        # Eve intercept-resend projective computational measurement
        attack_rng = random.Random(attack_seed)
        attacked_states = []
        for s in transmitted_states:
            p0 = abs(s[0]) ** 2
            collapsed = np.copy(STATE_0 if attack_rng.random() < p0 else STATE_1)
            attacked_states.append(collapsed)
        intercept_resend_flag = True

    # -------------------------------------------------------------------------
    # STEP 5: Projective Verification by Verifier (Bob)
    # -------------------------------------------------------------------------
    ver_res = verify_signature_qds(
        signature=signature,
        received_states=attacked_states,
        public_key=key_pair,
        threshold=threshold,
        seed=None  # Deterministic Born-rule verification
    )

    # -------------------------------------------------------------------------
    # STEP 6: Statistical Measurement Analysis
    # -------------------------------------------------------------------------
    stat_res = analyze_qds_measurements(
        observed_measurements=ver_res.measurements,
        expected_measurements=ver_res.expected_measurements,
        threshold=threshold
    )

    # Calculate post-attack state fidelities against Alice's pristine signature
    fidelities = [
        float(state_fidelity(signature.signature_states[i], attacked_states[i]))
        for i in range(len(attacked_states))
    ]
    attack_avg_fidelity = float(np.mean(fidelities))
    disturbance = max(0.0, min(1.0, 1.0 - attack_avg_fidelity))

    # -------------------------------------------------------------------------
    # STEP 7: Build Structured QDS Threat Evidence
    # -------------------------------------------------------------------------
    chi_sq_val = (
        stat_res["chi_square_analysis"]["chi_square"]
        if stat_res["chi_square_analysis"]["valid"]
        else None
    )

    evidence = build_qds_threat_evidence(
        teleportation_average_fidelity=attack_avg_fidelity,
        mismatch_rate=ver_res.mismatch_rate,
        measurement_accuracy=stat_res["accuracy"],
        distribution_distance=stat_res["distribution_distance"],
        chi_square_statistic=chi_sq_val,
        intercept_resend_indicator=intercept_resend_flag,
        pauli_error_indicator=pauli_error_flag,
        verification_threshold=threshold,
        channel_disturbance_threshold=QDS_CHANNEL_DISTURBANCE_THRESHOLD
    )

    # -------------------------------------------------------------------------
    # STEP 8: Evaluate Threat Classification
    # -------------------------------------------------------------------------
    threat_eval = evaluate_qds_threats(evidence)

    # -------------------------------------------------------------------------
    # STEP 9: Calculate Risk Score
    # -------------------------------------------------------------------------
    forgery_est = calculate_qds_forgery_probability_estimate(evidence)

    # Security parameters mapping
    sec_params = {
        "signature_validity": 1.0 if ver_res.accepted else 0.0,
        "hash_integrity": 1.0,
        "public_key_validity": 1.0,
        "certificate_validity": 1.0,
        "replay_safety": 1.0,
        "activity_safety": 1.0
    }

    risk_eval = calculate_composite_risk_score(
        security_parameters=sec_params,
        state_disturbance=disturbance,
        combined_pauli_disturbance=disturbance if pauli_error_flag else 0.0,
        forgery_risk_percentage=forgery_est["forgery_risk_percentage"],
        qds_evidence=evidence
    )

    # -------------------------------------------------------------------------
    # STEP 10: Assemble Complete Result
    # -------------------------------------------------------------------------
    result = QDSAttackSimulationResult(
        protocol="QDS",
        attack_type=clean_attack,
        seed=seed,
        signature={
            "qubit_count": req_qubits,
            "message_hash": message_hash.lower(),
            "protocol_version": signature.protocol_version,
            "bases_used": {
                "Z": signature.basis_metadata.count("Z"),
                "X": signature.basis_metadata.count("X"),
            }
        },
        teleportation={
            "initial_average_fidelity": round(teleport_res.average_fidelity, 6),
            "attacked_average_fidelity": round(attack_avg_fidelity, 6),
            "fidelities": [round(f, 6) for f in fidelities],
            "measurement_bits": teleport_res.measurement_bits,
            "pauli_corrections": teleport_res.pauli_corrections,
            "success": teleport_res.success
        },
        verification={
            "accepted": ver_res.accepted,
            "mismatch_rate": round(ver_res.mismatch_rate, 6),
            "threshold": threshold,
            "matches": stat_res["matches"],
            "mismatches": stat_res["mismatches"],
            "total_measurements": stat_res["total_measurements"]
        },
        statistics={
            "accuracy": round(stat_res["accuracy"], 6),
            "distribution_distance": round(stat_res["distribution_distance"], 6),
            "observed_distribution": stat_res["observed_distribution"],
            "expected_distribution": stat_res["expected_distribution"],
            "chi_square": stat_res["chi_square_analysis"]["chi_square"],
            "chi_square_status": stat_res["chi_square_analysis"]["status"],
            "chi_square_valid": stat_res["chi_square_analysis"]["valid"]
        },
        threat={
            "detected": threat_eval["threat_detected"],
            "type": threat_eval["threat_type"],
            "severity": threat_eval["severity"],
            "explanation": threat_eval["explanation"]
        },
        risk={
            "score": risk_eval["final_risk_score"],
            "tier": risk_eval["risk_level"],
            "contributing_factors": risk_eval["contributing_factors"]
        },
        evidence=evidence
    )

    return result.to_dict()


# ==============================================================================
# MULTI-ATTACK COMPARISON RUNNER
# ==============================================================================

def run_all_qds_attack_scenarios(
    message_hash: str = "a1b2c3d4",
    key_length: int = 32,
    seed: Optional[int] = None,
    threshold: float = QDS_VERIFICATION_THRESHOLD
) -> Dict[str, Any]:
    """
    Executes all 5 standard QDS attack scenarios and produces a comparative summary.

    Scenarios evaluated:
        1. none (Honest baseline)
        2. random_state_substitution (Signature forgery attempt)
        3. bit_flip (Pauli X channel error)
        4. phase_flip (Pauli Z channel error)
        5. intercept_resend (Eavesdropper projective measurement)

    Returns:
        Dict containing itemized scenario results, comparative metrics table,
        and summary diagnostics for frontend dashboards and performance metrics.
    """
    scenarios: List[Dict[str, Any]] = []

    for attack in SUPPORTED_QDS_ATTACKS:
        res = run_qds_attack_simulation(
            message_hash=message_hash,
            attack_type=attack,
            key_length=key_length,
            seed=seed,
            threshold=threshold
        )

        scenarios.append({
            "attack_type": attack,
            "fidelity": res["teleportation"]["attacked_average_fidelity"],
            "mismatch_rate": res["verification"]["mismatch_rate"],
            "distribution_distance": res["statistics"]["distribution_distance"],
            "accepted": res["verification"]["accepted"],
            "threat_detected": res["threat"]["detected"],
            "threat_type": res["threat"]["type"],
            "severity": res["threat"]["severity"],
            "risk_score": res["risk"]["score"],
            "risk_tier": res["risk"]["tier"],
        })

    # Summary diagnostics
    honest_res = next(s for s in scenarios if s["attack_type"] == "none")
    attacked_res = [s for s in scenarios if s["attack_type"] != "none"]

    detection_count = sum(1 for s in attacked_res if s["threat_detected"])
    detection_rate = round((detection_count / len(attacked_res)) * 100.0, 2)
    avg_attack_fidelity = round(float(np.mean([s["fidelity"] for s in attacked_res])), 4)

    return {
        "protocol": "QDS",
        "message_hash": message_hash.lower(),
        "key_length": key_length,
        "seed_used": seed,
        "scenarios": scenarios,
        "summary": {
            "total_scenarios": len(scenarios),
            "attacks_evaluated": len(attacked_res),
            "attacks_detected": detection_count,
            "detection_rate_percentage": detection_rate,
            "honest_baseline_fidelity": honest_res["fidelity"],
            "average_attacked_fidelity": avg_attack_fidelity,
            "thresholds": get_qds_thresholds(),
        }
    }
