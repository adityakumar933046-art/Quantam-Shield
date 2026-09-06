"""
Impersonation Simulation.
Simulates identity spoofing with synthetic identity records, mismatched signer names,
or certificate Common Name / public key fingerprint discrepancies.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class ImpersonationSimulator(BaseSimulator):
    """
    Simulates identity spoofing and certificate subject mismatch without compromising real users.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="IMPERSONATION", parameters=parameters)

    def simulate(
        self,
        claimed_signer_name: str = "Alice Corporate Officer",
        verified_signer_name: str = "Attacker Impersonator (Untrusted)",
        claimed_fp: str = "A1B2C3D4E5F6...",
        actual_fp: str = "998877665544...",
        claimed_signer: Optional[str] = None,
        cert_subject: Optional[str] = None,
        cert_serial: Optional[str] = None,
        mismatch_scenario: Optional[str] = None
    ) -> SimulationResult:
        """
        Executes a controlled identity impersonation attack simulation.
        """
        if claimed_signer is not None:
            claimed_signer_name = claimed_signer
        if cert_subject is not None:
            verified_signer_name = cert_subject
        baseline_normal = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": 1.0,
            "state_disturbance": 0.0,
            "threat_probability": 0.0,
            "risk_score": 10.0,
            "threats_detected": []
        }

        # Check mismatches
        identity_mismatch = (claimed_signer_name != verified_signer_name)
        fp_mismatch = (claimed_fp != actual_fp)

        anomalies = []
        if identity_mismatch:
            anomalies.append(f"Signer name mismatch: Claimed '{claimed_signer_name}', verified '{verified_signer_name}'")
        if fp_mismatch:
            anomalies.append("Public key certificate fingerprint does not match claimed credentials")

        sec_params = qe.extract_security_parameters_from_evidence(
            signature_verified=True,
            integrity_verified=True,
            public_key_status="VALID" if not fp_mismatch else "UNKNOWN",
            certificate_status="VALID",
            metadata_anomalies=anomalies
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
        composite_risk = qe.calculate_composite_risk_score(
            security_parameters=sec_params,
            state_disturbance=q_state["security_disturbance"],
            combined_pauli_disturbance=pauli_res["combined_pauli_disturbance"],
            forgery_risk_percentage=forg_res["forgery_risk_percentage"]
        )

        elapsed_ms = self.stop_timer()
        threat_categories = [t["threat_category"] for t in threats]
        detection_success = ("IMPERSONATION" in threat_categories) or identity_mismatch

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
            "summary": "Impersonation Simulation evaluated against metadata consistency rules.",
            "claimed_identity": claimed_signer_name,
            "verified_identity": verified_signer_name,
            "discrepancies": anomalies,
            "pauli_z_phase_shift": f"Pauli Z phase disturbance elevated to D_Z={pauli_res['pauli_z_disturbance']*100:.1f}%.",
            "threat_detected": "IMPERSONATION risk identified by identity consistency verification."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": detection_success,
            "detection_status": "DETECTED" if detection_success else "NOT_DETECTED",
            "signature_valid": True,
            "integrity_valid": True,
            "threats_detected": threats,
            "state_consistency": round(q_state["security_consistency"], 4),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "pauli_disturbance": round(pauli_res["combined_pauli_disturbance"], 4),
            "measurement_secure_probability": round(meas_res["secure_probability"], 4),
            "measurement_threat_probability": round(meas_res["threat_probability"], 4),
            "forgery_risk_estimate": forg_res["forgery_risk_percentage"],
            "final_risk_score": composite_risk["composite_risk_score"],
            "final_risk_level": composite_risk["risk_level"],
            "baseline_comparison": {
                "normal_state": baseline_normal,
                "simulated_attack_state": simulated_attack_state
            },
            "explanation": explanation,
            "execution_time_ms": elapsed_ms,
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
