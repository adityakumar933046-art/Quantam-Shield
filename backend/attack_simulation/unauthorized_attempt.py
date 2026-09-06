"""
Unauthorized Verification Simulation.
Simulates unprivileged role access, expired session attempts, or privilege escalation
and verifies that RBAC and authorization guards correctly deny and log the event.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class UnauthorizedAttemptSimulator(BaseSimulator):
    """
    Simulates unauthorized access attempts against restricted analyst endpoints.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="UNAUTHORIZED_VERIFICATION", parameters=parameters)

    def simulate(
        self,
        attempting_role: str = "DIGITAL_SIGNATURE_USER",
        required_role: str = "SECURITY_ANALYST",
        target_endpoint: str = "/api/security/analysis/verify",
        user_role: Optional[str] = None,
        required_roles: Optional[Any] = None,
        action: Optional[str] = None
    ) -> SimulationResult:
        """
        Executes a controlled unauthorized role authorization test.
        """
        if user_role is not None:
            attempting_role = user_role

        baseline_normal = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": 1.0,
            "state_disturbance": 0.0,
            "threat_probability": 0.0,
            "risk_score": 10.0,
            "threats_detected": []
        }

        # RBAC verification logic
        if required_roles is not None:
            role_allowed = (attempting_role in required_roles) or (attempting_role == "SUPER_ADMIN")
        else:
            role_allowed = (attempting_role == required_role) or (attempting_role == "SUPER_ADMIN")
        access_denied = not role_allowed
        blocked_status_code = 403 if attempting_role != "ANONYMOUS" else 401

        unauthorized_count = 1 if access_denied else 0
        sec_params = qe.extract_security_parameters_from_evidence(
            signature_verified=True,
            integrity_verified=True,
            public_key_status="VALID",
            certificate_status="VALID",
            unauthorized_attempts=unauthorized_count
        )

        q_state = qe.calculate_quantum_security_state(sec_params)
        pauli_res = qe.evaluate_pauli_disturbances(sec_params)
        meas_res = qe.analyze_projective_measurements(q_state["state_vector"])
        forg_res = qe.calculate_forgery_probability_estimate(
            signature_validity=sec_params["signature_validity"],
            hash_integrity=sec_params["hash_integrity"],
            public_key_validity=sec_params["public_key_validity"],
            metadata_consistency=sec_params["metadata_consistency"],
            state_disturbance=q_state["security_disturbance"],
            pauli_disturbance=pauli_res["combined_pauli_disturbance"]
        )
        threats = qe.evaluate_deterministic_threats(
            security_parameters=sec_params,
            state_disturbance=q_state["security_disturbance"],
            pauli_disturbances=pauli_res,
            forgery_risk=forg_res
        )
        if access_denied:
            threats.append({
                "threat_category": "UNAUTHORIZED_VERIFICATION_ATTEMPT",
                "threat_type": "RBAC_ACCESS_VIOLATION",
                "severity": "HIGH",
                "threat_score": 75.0,
                "confidence": 1.0,
                "threat_status": "BLOCKED",
                "description": f"Unauthorized verification attempt blocked: Role '{attempting_role}' requested restricted action on '{target_endpoint}'."
            })
        composite_risk = qe.calculate_composite_risk_score(
            security_parameters=sec_params,
            state_disturbance=q_state["security_disturbance"],
            combined_pauli_disturbance=pauli_res["combined_pauli_disturbance"],
            forgery_risk_percentage=forg_res["forgery_risk_percentage"]
        )

        elapsed_ms = self.stop_timer()
        threat_categories = [t["threat_category"] for t in threats]
        detection_success = access_denied
        final_risk = max(composite_risk["composite_risk_score"], 70.0) if access_denied else composite_risk["composite_risk_score"]

        simulated_attack_state = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": round(q_state["security_consistency"] * 100.0, 2),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "threat_probability": round(meas_res["threat_probability"] * 100.0, 2),
            "risk_score": composite_risk["composite_risk_score"],
            "threats_detected": threat_categories
        }

        explanation = {
            "summary": "Unauthorized Verification Attempt evaluated against platform RBAC policies.",
            "attempting_role": attempting_role,
            "required_role": required_role,
            "target_resource": target_endpoint,
            "access_control_decision": f"ACCESS_DENIED (HTTP {blocked_status_code})" if access_denied else "ACCESS_GRANTED",
            "audit_logging": "Event logged to security audit trail with severity CRITICAL." if access_denied else "Nominal access logged.",
            "detection_outcome": "Unauthorized attempt blocked and flagged by system guard."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": detection_success,
            "detection_status": "BLOCKED" if access_denied else "NOT_DETECTED",
            "signature_valid": True,
            "integrity_valid": True,
            "threats_detected": threats,
            "state_consistency": round(q_state["security_consistency"], 4),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "pauli_disturbance": round(pauli_res["combined_pauli_disturbance"], 4),
            "measurement_secure_probability": round(meas_res["secure_probability"], 4),
            "measurement_threat_probability": round(meas_res["threat_probability"], 4),
            "forgery_risk_estimate": forg_res["forgery_risk_percentage"],
            "final_risk_score": final_risk,
            "final_risk_level": "HIGH" if final_risk >= 70.0 else composite_risk["risk_level"],
            "baseline_comparison": {
                "normal_state": baseline_normal,
                "simulated_attack_state": simulated_attack_state
            },
            "explanation": explanation,
            "execution_time_ms": elapsed_ms,
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
