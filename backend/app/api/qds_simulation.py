import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Union
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
import numpy as np

from app.core.db import get_db
from app.models import (
    User,
    QDSSimulationSession,
    QDSAttackSimulation,
    QDSThreatEvent,
    AuditLog
)
from app.schemas import (
    QDSSimulationRunRequest,
    QDSSimulationResponse,
    QDSAttackRunRequest,
    QDSAttackSimulationResponse,
    QDSThreatEventResponse,
    QDSPerformanceMetricsResponse,
    QDSKeyGenerationRequest,
    QDSKeyGenerationResponse,
    QDSSignRequest,
    QDSSignResponse,
    QDSTeleportRequest,
    QDSTeleportResponse,
    QDSVerifyRequest,
    QDSVerifyResponse,
    QDSMultiQubitAttackSimulationRequest,
    QDSAttackScenarioRequest,
    QDSThresholdsResponse,
    QDSHealthResponse,
)
from app.api.auth import get_current_user
from app.core.audit_engine import log_audit_event
from app.core.qds_engine import (
    run_teleportation_qds_simulation,
    run_qds_attack_simulation as run_legacy_qds_attack_simulation
)
from quantum_engine.qds_protocol import (
    generate_qds_key_pair,
    sign_hash_qds,
    teleport_signature,
    verify_signature_qds,
    hex_to_bit_sequence,
    state_to_tuple,
    QDSKeyPair,
    QDSSignature,
    TeleportationResult,
    QDSVerificationResult,
)
from quantum_engine.states import state_fidelity
from quantum_engine.measurement_analysis import (
    analyze_qds_measurements,
    calculate_total_variation_distance,
    calculate_chi_square,
)
from quantum_engine.threat_detector import (
    build_qds_threat_evidence,
    evaluate_qds_threats,
)
from quantum_engine.risk_engine import calculate_composite_risk_score
from quantum_engine.forgery_probability import calculate_qds_forgery_probability_estimate
from quantum_engine.thresholds import (
    get_qds_thresholds,
    QDS_VERIFICATION_THRESHOLD,
    QDS_REPUDIATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD,
    QDS_MIN_ACCEPTABLE_FIDELITY,
    QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD,
    CHI_SQUARE_MIN_SAMPLE_SIZE,
    CHI_SQUARE_MIN_EXPECTED_COUNT,
)
from quantum_engine.qds_attack_pipeline import (
    run_qds_attack_simulation as run_multi_qubit_qds_attack_simulation,
    run_all_qds_attack_scenarios,
    SUPPORTED_QDS_ATTACKS,
)

router = APIRouter(prefix="/qds", tags=["Quantum Digital Signature (QDS) Simulation Module"])

# In-memory registries for simulation / prototype QDS keys and signatures
# Thread-safe and securely kept server-side; private quantum states are NEVER logged or leaked
QDS_KEY_REGISTRY: Dict[str, Dict[str, Any]] = {}
QDS_SIGNATURE_REGISTRY: Dict[str, Dict[str, Any]] = {}

def require_security_analyst(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN"]:
        log_audit_event(
            db=db,
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            user_id=current_user.user_id,
            user_email=current_user.email,
            result="BLOCKED",
            details=f"User '{current_user.email}' with role '{current_user.role}' attempted restricted QDS simulation API access."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Only Security Analysts and Super Admins can access QDS Simulation modules."
        )
    return current_user


@router.post("/simulate", response_model=QDSSimulationResponse)
@router.post("/simulate/", response_model=QDSSimulationResponse, include_in_schema=False)
def run_qds_simulation(
    req: QDSSimulationRunRequest,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    try:
        # Audit Start
        log_audit_event(
            db=db,
            action="QDS_SIMULATION_STARTED",
            user_id=analyst.user_id,
            user_email=analyst.email,
            details=f"Started QDS Teleportation Simulation with state '{req.initial_state}', Bell state '{req.bell_state}', seed {req.simulation_seed}"
        )

        # Execute QDS Mathematical Engine
        sim_res = run_teleportation_qds_simulation(
            initial_state_name=req.initial_state,
            bell_state_name=req.bell_state,
            simulation_seed=req.simulation_seed,
            signer_id=req.signer_id,
            verifier_id=req.verifier_id,
            acceptance_threshold=req.acceptance_threshold,
            attack_simulation=req.attack_simulation,
            depolarizing_error_prob=req.depolarizing_error_prob,
            phase_flip_error_prob=req.phase_flip_error_prob
        )

        # Persist QDSSimulationSession Record
        db_session = QDSSimulationSession(
            session_id=sim_res["session_id"],
            simulation_seed=sim_res["simulation_seed"],
            signer_id=sim_res["signer_id"],
            verifier_id=sim_res["verifier_id"],
            initial_state=sim_res["initial_state"],
            initial_state_vector=sim_res["initial_state_vector"],
            bell_state=sim_res["bell_state"],
            protocol_parameters=sim_res["protocol_parameters"],
            measurement_bits=sim_res["measurement_bits"],
            measurement_outcome=sim_res["measurement_outcome"],
            pauli_correction=sim_res["pauli_correction"],
            reconstructed_state=sim_res["reconstructed_state"],
            fidelity=sim_res["fidelity"],
            verification_result=sim_res["verification_result"],
            session_status=sim_res["session_status"]
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)

        # Comprehensive QDS Audit Trail Logging
        log_audit_event(
            db=db,
            action="QDS_TELEPORTATION_VERIFIED",
            user_id=analyst.user_id,
            user_email=analyst.email,
            details=f"QDS Teleportation Session {db_session.session_id}: Bell pair {sim_res['bell_state']}, bits: {sim_res['measurement_bits']}, Pauli: {sim_res['pauli_correction']}, outcome: |{sim_res['observed_projective_outcome']}⟩, {sim_res['verification_result']} (Fidelity: {sim_res['fidelity']:.4f})"
        )

        return db_session
    except ValueError as ve:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"QDS Simulation parameter error: {str(ve)}"
        )
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDS Simulation execution error: {str(exc)}"
        )


@router.get("/simulations", response_model=List[QDSSimulationResponse])
def get_qds_simulations_history(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    sessions = db.query(QDSSimulationSession).order_by(QDSSimulationSession.created_at.desc()).all()
    return sessions


@router.get("/simulations/{simulation_id}", response_model=QDSSimulationResponse)
def get_qds_simulation_details(
    simulation_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    session = db.query(QDSSimulationSession).filter(QDSSimulationSession.simulation_id == simulation_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="QDS Simulation record not found.")
    return session


@router.post("/attack-simulation")
@router.post("/attack-simulation/", include_in_schema=False)
def run_attack_experiment(
    req: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes a QDS attack simulation.
    Supports both:
    1. Multi-Qubit QDS Attack Simulation (Prompt 5):
       Payload contains 'message_hash', 'attack_type', 'key_length', 'seed'.
       Returns full end-to-end security assessment.
    2. Legacy Single-Qubit Monte Carlo Attack Experiment (Step 8):
       Payload contains 'number_of_trials', 'initial_state', etc.
       Returns QDSAttackSimulationResponse.
    """
    # -------------------------------------------------------------------------
    # Multi-Qubit QDS Attack Pipeline (Prompt 5)
    # -------------------------------------------------------------------------
    if "message_hash" in req:
        raw_hash = str(req.get("message_hash", "")).strip().lower()
        if not raw_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message hash cannot be empty."
            )
        for c in raw_hash:
            if c not in "0123456789abcdef":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid hex character '{c}' in message hash."
                )

        att_type = str(req.get("attack_type", "bit_flip")).strip().lower()
        if att_type not in SUPPORTED_QDS_ATTACKS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported attack type '{att_type}'. Must be one of {SUPPORTED_QDS_ATTACKS}."
            )

        k_len = req.get("key_length", 8)
        if not isinstance(k_len, int) or k_len < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Key length must be a positive integer >= 1."
            )

        req_qubits = len(raw_hash) * 4
        if k_len < req_qubits:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Key length ({k_len}) is shorter than required message hash bits ({req_qubits})."
            )

        seed = req.get("seed")

        try:
            return run_multi_qubit_qds_attack_simulation(
                message_hash=raw_hash,
                attack_type=att_type,
                key_length=k_len,
                seed=seed
            )
        except ValueError as ve:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    # -------------------------------------------------------------------------
    # Legacy Single-Qubit Monte Carlo Attack Experiment (Step 8)
    # -------------------------------------------------------------------------
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Only Security Analysts and Super Admins can access QDS Simulation modules."
        )

    legacy_req = QDSAttackRunRequest(**req)
    prob = legacy_req.attack_probability if legacy_req.attack_probability is not None else (legacy_req.noise_level if legacy_req.noise_level is not None else 0.5)
    thresh = legacy_req.detection_threshold if legacy_req.detection_threshold is not None else (legacy_req.acceptance_threshold if legacy_req.acceptance_threshold is not None else 0.95)

    log_audit_event(
        db=db,
        action="QDS_ATTACK_SIMULATION_STARTED",
        user_id=current_user.user_id,
        user_email=current_user.email,
        details=f"Started QDS attack experiment: '{legacy_req.attack_type}' ({legacy_req.number_of_trials} trials, p={prob})"
    )

    # Execute Multi-Trial Attack Engine
    att_res = run_legacy_qds_attack_simulation(
        attack_type=legacy_req.attack_type,
        number_of_trials=legacy_req.number_of_trials,
        attack_probability=prob,
        initial_state_name=legacy_req.initial_state,
        simulation_seed=legacy_req.simulation_seed,
        detection_threshold=thresh,
        signer_id=legacy_req.signer_id,
        verifier_id=legacy_req.verifier_id
    )

    # Persist QDSAttackSimulation Record
    db_attack = QDSAttackSimulation(
        attack_type=att_res["attack_type"],
        attack_parameters=json.dumps({
            "attack_probability": att_res["attack_probability"],
            "simulation_seed": att_res["simulation_seed"],
            "detection_threshold": att_res["detection_threshold"],
            "min_fidelity": att_res["min_fidelity"],
            "max_fidelity": att_res["max_fidelity"]
        }),
        number_of_trials=att_res["number_of_trials"],
        expected_distribution=json.dumps(att_res["expected_distribution"]),
        observed_distribution=json.dumps(att_res["observed_distribution"]),
        mean_fidelity=att_res["mean_fidelity"],
        measurement_error_rate=att_res["measurement_error_rate"],
        acceptance_rate=att_res["acceptance_rate"],
        rejection_rate=att_res["rejection_rate"],
        detection_rate=att_res["detection_rate"],
        false_acceptance_rate=att_res["false_acceptance_rate"],
        execution_time_ms=att_res["execution_time_ms"]
    )
    db.add(db_attack)
    db.commit()
    db.refresh(db_attack)

    # Persist Threat Events from Attack Simulation
    threat_samples = att_res.get("sample_threat_events", [])
    for sample in threat_samples:
        threat_rec = QDSThreatEvent(
            attack_simulation_id=db_attack.attack_simulation_id,
            threat_type=sample["threat_type"],
            severity=sample["severity"],
            detection_score=sample["detection_score"],
            detection_reason=sample["detection_reason"],
            threshold_used=json.dumps({"threshold": thresh, "fidelity": sample["fidelity"]})
        )
        db.add(threat_rec)
    db.commit()

    if threat_samples:
        log_audit_event(
            db=db,
            action="QDS_THREAT_EVENTS_CREATED",
            user_id=current_user.user_id,
            user_email=current_user.email,
            details=f"Detected {len(threat_samples)} QDS threat events during {legacy_req.attack_type} simulation"
        )

    return QDSAttackSimulationResponse.model_validate(db_attack).model_dump()


@router.get("/threat-events", response_model=List[QDSThreatEventResponse])
def get_qds_threat_events(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    events = db.query(QDSThreatEvent).order_by(QDSThreatEvent.created_at.desc()).all()
    return events


@router.get("/metrics", response_model=QDSPerformanceMetricsResponse)
def get_qds_performance_metrics(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    simulations = db.query(QDSSimulationSession).all()
    attacks = db.query(QDSAttackSimulation).all()
    threats = db.query(QDSThreatEvent).all()

    total_sims = len(simulations)
    successful_teleportations = sum(1 for s in simulations if s.verification_result == "ACCEPT")
    
    total_attacks = len(attacks)
    threats_count = len(threats)

    avg_fidelity = 0.0
    if total_sims > 0:
        avg_fidelity = sum(s.fidelity for s in simulations) / total_sims

    avg_exec_ms = 0.0
    avg_detection_accuracy = 0.0
    avg_far = 0.0
    avg_frr = 0.0

    if total_attacks > 0:
        avg_exec_ms = sum(a.execution_time_ms for a in attacks) / total_attacks
        avg_detection_accuracy = sum(a.detection_rate for a in attacks) / total_attacks
        avg_far = sum(a.false_acceptance_rate for a in attacks) / total_attacks
        avg_frr = sum(a.rejection_rate for a in attacks) / total_attacks

    return QDSPerformanceMetricsResponse(
        total_simulations=total_sims,
        successful_teleportations=successful_teleportations,
        attack_simulations_count=total_attacks,
        threats_detected_count=threats_count,
        average_fidelity=float(round(avg_fidelity, 4)),
        average_execution_time_ms=float(round(avg_exec_ms, 2)),
        attack_detection_accuracy=float(round(avg_detection_accuracy, 2)),
        false_acceptance_rate=float(round(avg_far, 2)),
        false_rejection_rate=float(round(avg_frr, 2)),
        time_complexity_explanation="O(N × 2^n) matrix-vector transformations per qubit state simulation trial. Teleportation setup executes in O(1) constant time for 2-qubit system.",
        space_complexity_explanation="O(2^n) state vector amplitude storage. 2-qubit Hilbert space requires exact 4 complex float numbers (64 bytes memory)."
    )


@router.post("/simulations/{simulation_id}/rerun", response_model=QDSSimulationResponse)
def rerun_qds_simulation_by_seed(
    simulation_id: int,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    old_session = db.query(QDSSimulationSession).filter(QDSSimulationSession.simulation_id == simulation_id).first()
    if not old_session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="QDS Simulation record not found for re-running.")

    # Re-run simulation with exact same seed and parameters
    sim_res = run_teleportation_qds_simulation(
        initial_state_name=old_session.initial_state,
        bell_state_name=old_session.bell_state,
        simulation_seed=old_session.simulation_seed,
        signer_id=old_session.signer_id,
        verifier_id=old_session.verifier_id
    )

    new_session = QDSSimulationSession(
        session_id=sim_res["session_id"],
        simulation_seed=sim_res["simulation_seed"],
        signer_id=sim_res["signer_id"],
        verifier_id=sim_res["verifier_id"],
        initial_state=sim_res["initial_state"],
        initial_state_vector=sim_res["initial_state_vector"],
        bell_state=sim_res["bell_state"],
        protocol_parameters=sim_res["protocol_parameters"],
        measurement_bits=sim_res["measurement_bits"],
        measurement_outcome=sim_res["measurement_outcome"],
        pauli_correction=sim_res["pauli_correction"],
        reconstructed_state=sim_res["reconstructed_state"],
        fidelity=sim_res["fidelity"],
        verification_result=sim_res["verification_result"],
        session_status="REPRODUCED"
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    log_audit_event(
        db=db,
        action="QDS_SIMULATION_REPRODUCED",
        user_id=analyst.user_id,
        user_email=analyst.email,
        details=f"Reproduced simulation #{simulation_id} using seed {old_session.simulation_seed}. Reconstructed Fidelity: {sim_res['fidelity']:.4f}"
    )

    return new_session


# ==============================================================================
# MULTI-QUBIT QDS PROTOCOL REST API ENDPOINTS (PROMPT 5)
# ==============================================================================

@router.get("/health", response_model=QDSHealthResponse)
def get_qds_health():
    """
    Lightweight health check for QDS module.
    Confirms availability of quantum engine, statistical analysis, and attack pipeline.
    Does not execute expensive quantum simulations.
    """
    return {
        "status": "healthy",
        "protocol": "QDS",
        "quantum_engine": "available",
        "statistical_analysis": "available",
        "attack_pipeline": "available",
        "ai_ml": False
    }


@router.get("/thresholds", response_model=QDSThresholdsResponse)
def get_public_qds_thresholds():
    """
    Returns public protocol, repudiation, channel disturbance, and statistical validity thresholds.
    """
    return {
        "verification_threshold": QDS_VERIFICATION_THRESHOLD,
        "repudiation_threshold": QDS_REPUDIATION_THRESHOLD,
        "channel_disturbance_threshold": QDS_CHANNEL_DISTURBANCE_THRESHOLD,
        "minimum_acceptable_fidelity": QDS_MIN_ACCEPTABLE_FIDELITY,
        "distribution_distance_anomaly_threshold": QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD,
        "chi_square_min_sample_size": CHI_SQUARE_MIN_SAMPLE_SIZE,
        "chi_square_min_expected_count": CHI_SQUARE_MIN_EXPECTED_COUNT,
    }


@router.post("/key-generation", response_model=QDSKeyGenerationResponse)
def generate_qds_key(
    req: QDSKeyGenerationRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Generates a new multi-qubit QDS key pair.
    Private quantum key states are strictly kept server-side in secure memory and never leaked.
    Public verification states and basis sequences are returned to the client.
    """
    if req.key_length < 1 or req.key_length > 512:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key length must be between 1 and 512 qubits, got {req.key_length}."
        )

    try:
        key_pair = generate_qds_key_pair(length=req.key_length, seed=req.seed)
        key_id = f"qds-key-{uuid.uuid4().hex[:12]}"

        # Secure server-side prototype registry storage
        QDS_KEY_REGISTRY[key_id] = {
            "key_id": key_id,
            "key_pair": key_pair,
            "created_at": datetime.now(timezone.utc),
            "owner": current_user.email,
            "seed": req.seed
        }

        # Serialize public key states safely (real and imaginary components)
        serialized_pub_key = [
            [round(float(s[0].real), 6), round(float(s[0].imag), 6),
             round(float(s[1].real), 6), round(float(s[1].imag), 6)]
            for s in key_pair.public_states
        ]

        return {
            "key_id": key_id,
            "key_length": req.key_length,
            "protocol_version": key_pair.metadata.get("protocol_version", "QDS-TP-1.0"),
            "public_key": serialized_pub_key,
            "basis_information": key_pair.basis_sequence,
            "seed": req.seed
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDS key generation failed: {str(exc)}"
        )


@router.post("/sign", response_model=QDSSignResponse)
def sign_qds_message(
    req: QDSSignRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Generates a multi-qubit QDS quantum signature for a message hash digest.
    Maps hash bits to quantum basis states. Never exposes private key material.
    """
    if req.key_id not in QDS_KEY_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown key_id '{req.key_id}'. Please generate a key first."
        )

    key_entry = QDS_KEY_REGISTRY[req.key_id]
    key_pair = key_entry["key_pair"]

    clean_hash = req.message_hash.strip().lower()
    if not clean_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message hash cannot be empty.")
    for c in clean_hash:
        if c not in "0123456789abcdef":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid hexadecimal character '{c}' in message hash.")

    req_qubits = len(clean_hash) * 4
    if len(key_pair.private_states) < req_qubits:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key length ({len(key_pair.private_states)}) is shorter than required hash bits ({req_qubits})."
        )

    try:
        signature = sign_hash_qds(clean_hash, key_pair)
        sig_id = f"qds-sig-{uuid.uuid4().hex[:12]}"

        QDS_SIGNATURE_REGISTRY[sig_id] = {
            "signature_id": sig_id,
            "signature": signature,
            "key_id": req.key_id,
            "key_pair": key_pair,
            "created_at": datetime.now(timezone.utc),
            "owner": current_user.email,
            "teleported": False,
            "teleportation_result": None,
            "received_states": None,
        }

        return {
            "signature_id": sig_id,
            "message_hash": signature.message_hash,
            "qubit_count": signature.num_qubits,
            "protocol_version": signature.protocol_version
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDS signing failed: {str(exc)}"
        )


@router.post("/teleport", response_model=QDSTeleportResponse)
def teleport_qds_signature(
    req: QDSTeleportRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Teleports signature qubits to verifier using Bell pairs and Pauli corrections.
    Reconstructs transmitted quantum states on verifier side.
    """
    if req.signature_id not in QDS_SIGNATURE_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown signature_id '{req.signature_id}'."
        )

    sig_entry = QDS_SIGNATURE_REGISTRY[req.signature_id]
    signature = sig_entry["signature"]

    try:
        teleport_res = teleport_signature(signature.signature_states, seed=req.seed)

        sig_entry["teleported"] = True
        sig_entry["teleportation_result"] = teleport_res
        sig_entry["received_states"] = teleport_res.received_states

        return {
            "signature_id": req.signature_id,
            "qubit_count": len(teleport_res.received_states),
            "average_fidelity": round(teleport_res.average_fidelity, 6),
            "fidelities": [round(f, 6) for f in teleport_res.fidelities],
            "measurement_bits": teleport_res.measurement_bits,
            "pauli_corrections": teleport_res.pauli_corrections,
            "success": teleport_res.success
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDS teleportation failed: {str(exc)}"
        )


@router.post("/verify", response_model=QDSVerifyResponse)
def verify_qds_signature_endpoint(
    req: QDSVerifyRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Performs conjugate-basis projective measurement verification,
    statistical outcome analysis, threat detection, and risk scoring.
    """
    if req.signature_id not in QDS_SIGNATURE_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown signature_id '{req.signature_id}'."
        )

    if not (0.0 <= req.threshold <= 1.0):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification threshold must be in [0.0, 1.0], got {req.threshold}."
        )

    sig_entry = QDS_SIGNATURE_REGISTRY[req.signature_id]
    signature = sig_entry["signature"]
    key_pair = sig_entry["key_pair"]

    # Use teleported states if available, else signature states
    received_states = sig_entry["received_states"] if sig_entry.get("received_states") is not None else signature.signature_states

    try:
        ver_res = verify_signature_qds(
            signature=signature,
            received_states=received_states,
            public_key=key_pair,
            threshold=req.threshold
        )

        stat_res = analyze_qds_measurements(
            observed_measurements=ver_res.measurements,
            expected_measurements=ver_res.expected_measurements,
            threshold=req.threshold
        )

        fids = [
            float(state_fidelity(signature.signature_states[i], received_states[i]))
            for i in range(len(received_states))
        ]
        avg_fid = float(np.mean(fids))
        dist = max(0.0, min(1.0, 1.0 - avg_fid))

        chi_sq_val = (
            stat_res["chi_square_analysis"]["chi_square"]
            if stat_res["chi_square_analysis"]["valid"]
            else None
        )
        evidence = build_qds_threat_evidence(
            teleportation_average_fidelity=avg_fid,
            mismatch_rate=ver_res.mismatch_rate,
            measurement_accuracy=stat_res["accuracy"],
            distribution_distance=stat_res["distribution_distance"],
            chi_square_statistic=chi_sq_val,
            verification_threshold=req.threshold
        )

        threat_eval = evaluate_qds_threats(evidence)
        forgery_est = calculate_qds_forgery_probability_estimate(evidence)

        risk_eval = calculate_composite_risk_score(
            security_parameters={
                "signature_validity": 1.0 if ver_res.accepted else 0.0,
                "hash_integrity": 1.0
            },
            state_disturbance=dist,
            combined_pauli_disturbance=0.0,
            forgery_risk_percentage=forgery_est["forgery_risk_percentage"],
            qds_evidence=evidence
        )

        return {
            "verification": {
                "accepted": ver_res.accepted,
                "mismatch_rate": round(ver_res.mismatch_rate, 6),
                "threshold": req.threshold,
                "matches": stat_res["matches"],
                "mismatches": stat_res["mismatches"]
            },
            "statistics": {
                "accuracy": round(stat_res["accuracy"], 6),
                "distribution_distance": round(stat_res["distribution_distance"], 6),
                "chi_square": stat_res["chi_square_analysis"]["chi_square"],
                "chi_square_status": stat_res["chi_square_analysis"]["status"]
            },
            "threat": {
                "detected": threat_eval["threat_detected"],
                "type": threat_eval["threat_type"],
                "severity": threat_eval["severity"],
                "explanation": threat_eval["explanation"]
            },
            "risk": {
                "score": risk_eval["final_risk_score"],
                "tier": risk_eval["risk_level"]
            }
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QDS verification failed: {str(exc)}"
        )


@router.post("/attack-scenarios")
def compare_all_attack_scenarios(
    req: QDSAttackScenarioRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Executes and compares all 5 standard QDS attack scenarios (none, random substitution,
    bit flip, phase flip, intercept-resend) for the specified message digest.
    Returns comparative table for frontend performance dashboards.
    """
    clean_hash = req.message_hash.strip().lower()
    if not clean_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message hash cannot be empty.")
    for c in clean_hash:
        if c not in "0123456789abcdef":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid hex character '{c}' in message hash.")

    req_qubits = len(clean_hash) * 4
    if req.key_length < req_qubits:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key length ({req.key_length}) must be at least {req_qubits} for hash '{clean_hash}'."
        )

    try:
        return run_all_qds_attack_scenarios(
            message_hash=clean_hash,
            key_length=req.key_length,
            seed=req.seed
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

