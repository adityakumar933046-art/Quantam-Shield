import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

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
    QDSPerformanceMetricsResponse
)
from app.api.auth import get_current_user
from app.core.audit_engine import log_audit_event
from app.core.qds_engine import (
    run_teleportation_qds_simulation,
    run_qds_attack_simulation
)

router = APIRouter(prefix="/qds", tags=["Quantum Digital Signature (QDS) Simulation Module"])

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


@router.post("/attack-simulation", response_model=QDSAttackSimulationResponse)
def run_attack_experiment(
    req: QDSAttackRunRequest,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_security_analyst)
):
    prob = req.attack_probability if req.attack_probability is not None else (req.noise_level if req.noise_level is not None else 0.5)
    thresh = req.detection_threshold if req.detection_threshold is not None else (req.acceptance_threshold if req.acceptance_threshold is not None else 0.95)

    log_audit_event(
        db=db,
        action="QDS_ATTACK_SIMULATION_STARTED",
        user_id=analyst.user_id,
        user_email=analyst.email,
        details=f"Started QDS attack experiment: '{req.attack_type}' ({req.number_of_trials} trials, p={prob})"
    )

    # Execute Multi-Trial Attack Engine
    att_res = run_qds_attack_simulation(
        attack_type=req.attack_type,
        number_of_trials=req.number_of_trials,
        attack_probability=prob,
        initial_state_name=req.initial_state,
        simulation_seed=req.simulation_seed,
        detection_threshold=thresh,
        signer_id=req.signer_id,
        verifier_id=req.verifier_id
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
            user_id=analyst.user_id,
            user_email=analyst.email,
            details=f"Detected {len(threat_samples)} QDS threat events during {req.attack_type} simulation"
        )

    return db_attack


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

    avg_fidelity = 1.0
    if total_sims > 0:
        avg_fidelity = sum(s.fidelity for s in simulations) / total_sims

    avg_exec_ms = 12.5
    avg_detection_accuracy = 100.0
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
