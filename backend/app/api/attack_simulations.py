"""
Controlled Attack Simulation Endpoints.
Provides isolated, defensive testing of platform detection capabilities.
"""

import json
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.models import User, AttackSimulation, AttackSimulationResult, AuditLog
from app.api.auth import get_current_user
from app.schemas import (
    AttackSimulationCreateRequest,
    AttackSimulationResponse,
    SimulationResultResponse,
    SimulationMetricsSummaryResponse
)
from attack_simulation import (
    generate_simulation_id,
    DocumentTamperingSimulator,
    SignatureForgerySimulator,
    ReplayAttackSimulator,
    ImpersonationSimulator,
    UnauthorizedAttemptSimulator,
    SignatureManipulationSimulator,
    QuantumChannelSimulator,
    calculate_simulation_metrics
)

router = APIRouter(prefix="/simulations", tags=["Step 6 Attack Simulation Module"])


def require_analyst_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Security Analyst or Super Admin role required."
        )
    return current_user


def execute_simulator_for_type(
    attack_type: str,
    target_reference: Optional[str],
    parameters: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Executes the specialized simulator based on the attack type."""
    params = parameters or {}
    atype = attack_type.upper()

    if atype == "DOCUMENT_TAMPERING":
        simulator = DocumentTamperingSimulator(parameters=params)
        sample_text = params.get("content_text", "AGREEMENT: The undersigned agrees to terms outlined in Section 12. Validated by Q-SHIELD.")
        original_bytes = sample_text.encode("utf-8")
        import hashlib
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        return simulator.simulate(
            original_content=original_bytes,
            original_hash=original_hash,
            signature_present=params.get("signature_present", True),
            tamper_mode=params.get("tamper_mode", "CHAR_FLIP"),
            custom_payload=params.get("custom_payload")
        )

    elif atype == "SIGNATURE_FORGERY":
        simulator = SignatureForgerySimulator(parameters=params)
        return simulator.simulate(
            forgery_mode=params.get("forgery_mode", "CORRUPT_BYTES"),
            original_public_key_fingerprint=params.get("public_key_fingerprint", "VALID_KEY_FP_2048"),
            target_document_hash=params.get("document_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        )

    elif atype == "REPLAY_ATTACK":
        simulator = ReplayAttackSimulator(parameters=params)
        return simulator.simulate(
            number_of_attempts=int(params.get("number_of_attempts", 20)),
            time_window_seconds=int(params.get("time_window_seconds", 10)),
            same_user=bool(params.get("same_user", True)),
            same_source_identifier=bool(params.get("same_source_identifier", True)),
            document_hash=params.get("document_hash", "SYNTHETIC_REPLAY_HASH")
        )

    elif atype == "IMPERSONATION":
        simulator = ImpersonationSimulator(parameters=params)
        return simulator.simulate(
            claimed_signer_name=params.get("claimed_signer_name", "Chief Executive Officer (Authorized)"),
            verified_signer_name=params.get("verified_signer_name", "Untrusted External Entity (Attacker)"),
            claimed_fp=params.get("claimed_fp", "CLAIMED_PUBKEY_FP_8899"),
            actual_fp=params.get("actual_fp", "ACTUAL_PUBKEY_FP_1122")
        )

    elif atype == "UNAUTHORIZED_VERIFICATION":
        simulator = UnauthorizedAttemptSimulator(parameters=params)
        return simulator.simulate(
            attempting_role=params.get("attempting_role", "DIGITAL_SIGNATURE_USER"),
            required_role=params.get("required_role", "SECURITY_ANALYST"),
            target_endpoint=params.get("target_endpoint", "/api/security/analysis/verify")
        )

    elif atype == "SIGNATURE_MANIPULATION":
        simulator = SignatureManipulationSimulator(parameters=params)
        return simulator.simulate(
            manipulation_type=params.get("manipulation_type", "TRUNCATED_SIGNATURE"),
            original_signature_algorithm=params.get("original_signature_algorithm", "RSA-SHA256")
        )

    elif atype in ["QUANTUM_CHANNEL_MANIPULATION", "QUANTUM_CHANNEL_SIMULATION"]:
        simulator = QuantumChannelSimulator(parameters=params)
        return simulator.simulate(
            scenario=params.get("scenario", "PAULI_X_DISTURBANCE"),
            bell_state_name=params.get("bell_state_name", "PHI_PLUS")
        )

    else:
        raise ValueError(f"Unsupported attack simulation type: '{attack_type}'.")


@router.get("/", response_model=List[AttackSimulationResponse])
def list_simulations(
    limit: int = Query(50, ge=1, le=200),
    attack_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Lists attack simulation records."""
    query = db.query(AttackSimulation).order_by(AttackSimulation.id.desc())
    if attack_type:
        query = query.filter(AttackSimulation.attack_type == attack_type.upper())
    if status_filter:
        query = query.filter(AttackSimulation.status == status_filter.upper())
    return query.limit(limit).all()


@router.post("/create/", response_model=AttackSimulationResponse)
def create_simulation(
    req: AttackSimulationCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Registers a new controlled attack simulation."""
    sim_id = generate_simulation_id()
    sim = AttackSimulation(
        simulation_id=sim_id,
        initiated_by=user.email,
        attack_type=req.attack_type.upper(),
        target_document_reference=req.target_document_reference,
        target_analysis_id=req.target_analysis_id,
        parameters=json.dumps(req.parameters or {}),
        status="PENDING",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.add(sim)
    db.commit()
    db.refresh(sim)
    return sim


@router.post("/{sim_ref}/run/", response_model=AttackSimulationResponse)
def run_simulation(
    sim_ref: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Executes a registered simulation and saves the detection results."""
    if sim_ref.isdigit():
        sim = db.query(AttackSimulation).filter(AttackSimulation.id == int(sim_ref)).first()
    else:
        sim = db.query(AttackSimulation).filter(AttackSimulation.simulation_id == sim_ref).first()

    if not sim:
        raise HTTPException(status_code=404, detail="Attack simulation record not found.")

    params = json.loads(sim.parameters) if sim.parameters else {}
    sim_res = execute_simulator_for_type(sim.attack_type, sim.target_document_reference, params)

    # Delete previous result if rerun
    db.query(AttackSimulationResult).filter(AttackSimulationResult.simulation_id == sim.id).delete()

    db_res = AttackSimulationResult(
        simulation_id=sim.id,
        attack_type=sim.attack_type,
        detection_success=sim_res["detection_success"],
        detection_status=sim_res["detection_status"],
        signature_valid=sim_res["signature_valid"],
        integrity_valid=sim_res["integrity_valid"],
        threats_detected=json.dumps(sim_res["threats_detected"]),
        state_consistency=sim_res["state_consistency"],
        state_disturbance=sim_res["state_disturbance"],
        pauli_disturbance=sim_res["pauli_disturbance"],
        measurement_secure_probability=sim_res["measurement_secure_probability"],
        measurement_threat_probability=sim_res["measurement_threat_probability"],
        forgery_risk_estimate=sim_res["forgery_risk_estimate"],
        final_risk_score=sim_res["final_risk_score"],
        final_risk_level=sim_res["final_risk_level"],
        baseline_comparison=json.dumps(sim_res["baseline_comparison"]),
        explanation=json.dumps(sim_res["explanation"]),
        execution_time_ms=sim_res["execution_time_ms"]
    )
    db.add(db_res)

    sim.status = "COMPLETED"
    sim.completed_at = datetime.now(timezone.utc)

    db.add(AuditLog(
        user_id=user.user_id,
        user_email=user.email,
        action="ATTACK_SIMULATION_EXECUTED",
        details=f"Executed simulation {sim.simulation_id} (Type: {sim.attack_type}, Result: {sim_res['detection_status']})"
    ))
    db.commit()
    db.refresh(sim)
    return sim


@router.post("/execute/", response_model=AttackSimulationResponse)
def create_and_run_simulation(
    req: AttackSimulationCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Convenience endpoint to create and immediately execute an attack simulation."""
    sim_id = generate_simulation_id()
    sim_res = execute_simulator_for_type(req.attack_type, req.target_document_reference, req.parameters)

    sim = AttackSimulation(
        simulation_id=sim_id,
        initiated_by=user.email,
        attack_type=req.attack_type.upper(),
        target_document_reference=req.target_document_reference,
        target_analysis_id=req.target_analysis_id,
        parameters=json.dumps(req.parameters or {}),
        status="COMPLETED",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.add(sim)
    db.flush()

    db_res = AttackSimulationResult(
        simulation_id=sim.id,
        attack_type=sim.attack_type,
        detection_success=sim_res["detection_success"],
        detection_status=sim_res["detection_status"],
        signature_valid=sim_res["signature_valid"],
        integrity_valid=sim_res["integrity_valid"],
        threats_detected=json.dumps(sim_res["threats_detected"]),
        state_consistency=sim_res["state_consistency"],
        state_disturbance=sim_res["state_disturbance"],
        pauli_disturbance=sim_res["pauli_disturbance"],
        measurement_secure_probability=sim_res["measurement_secure_probability"],
        measurement_threat_probability=sim_res["measurement_threat_probability"],
        forgery_risk_estimate=sim_res["forgery_risk_estimate"],
        final_risk_score=sim_res["final_risk_score"],
        final_risk_level=sim_res["final_risk_level"],
        baseline_comparison=json.dumps(sim_res["baseline_comparison"]),
        explanation=json.dumps(sim_res["explanation"]),
        execution_time_ms=sim_res["execution_time_ms"]
    )
    db.add(db_res)

    db.add(AuditLog(
        user_id=user.user_id,
        user_email=user.email,
        action="ATTACK_SIMULATION_EXECUTED",
        details=f"Executed simulation {sim.simulation_id} (Type: {sim.attack_type}, Result: {sim_res['detection_status']})"
    ))
    db.commit()
    db.refresh(sim)
    return sim


@router.get("/history/", response_model=List[AttackSimulationResponse])
def get_simulation_history(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Retrieves completed simulations with detection results."""
    return db.query(AttackSimulation).filter(AttackSimulation.status == "COMPLETED").order_by(AttackSimulation.id.desc()).limit(limit).all()


@router.get("/metrics/summary", response_model=SimulationMetricsSummaryResponse)
def get_simulation_metrics_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Calculates defensive performance metrics from simulation history."""
    sims = db.query(AttackSimulation).filter(AttackSimulation.status == "COMPLETED").all()
    results_list = []
    for s in sims:
        if s.result:
            results_list.append({
                "attack_type": s.attack_type,
                "detection_success": s.result.detection_success,
                "execution_time_ms": s.result.execution_time_ms,
                "final_risk_score": s.result.final_risk_score
            })
    return calculate_simulation_metrics(results_list)


@router.get("/{sim_ref}/", response_model=AttackSimulationResponse)
def get_simulation_details(
    sim_ref: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Retrieves an individual simulation record by numeric ID or human-readable simulation ID."""
    if sim_ref.isdigit():
        sim = db.query(AttackSimulation).filter(AttackSimulation.id == int(sim_ref)).first()
    else:
        sim = db.query(AttackSimulation).filter(AttackSimulation.simulation_id == sim_ref).first()

    if not sim:
        raise HTTPException(status_code=404, detail="Attack simulation record not found.")
    return sim


@router.delete("/{sim_ref}/")
@router.post("/{sim_ref}/delete/")
def delete_simulation(
    sim_ref: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst_or_admin)
):
    """Deletes an isolated simulation record and its result."""
    if sim_ref.isdigit():
        sim = db.query(AttackSimulation).filter(AttackSimulation.id == int(sim_ref)).first()
    else:
        sim = db.query(AttackSimulation).filter(AttackSimulation.simulation_id == sim_ref).first()

    if not sim:
        raise HTTPException(status_code=404, detail="Attack simulation record not found.")

    sim_id_str = sim.simulation_id
    db.delete(sim)
    db.add(AuditLog(
        user_id=user.user_id,
        user_email=user.email,
        action="ATTACK_SIMULATION_DELETED",
        details=f"Deleted simulation {sim_id_str}"
    ))
    db.commit()
    return {"status": "success", "message": f"Simulation {sim_id_str} deleted successfully."}
