"""
Signature Manipulation Simulation.
Simulates structural signature tampering, truncated encoding, corrupted ASN.1 structures,
algorithm downgrade, or conflicting signature reuse.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class SignatureManipulationSimulator(BaseSimulator):
    """
    Simulates signature block tampering and structural anomalies on temporary objects.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="SIGNATURE_MANIPULATION", parameters=parameters)

    def simulate(
        self,
        signature_bytes: Optional[bytes] = None,
        manipulation_type: str = "TRUNCATED_SIGNATURE",
        original_signature_algorithm: str = "RSA-SHA256",
        truncate_bytes: Optional[int] = None
    ) -> SimulationResult:
        """
        Executes a controlled signature structure manipulation simulation.
        """
        baseline_normal = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": 1.0,
            "state_disturbance": 0.0,
            "threat_probability": 0.0,
            "risk_score": 10.0,
            "threats_detected": []
        }

        desc = ""
        sig_conflict = False
        meta_anomalies = []

        if manipulation_type in ["TRUNCATED_SIGNATURE", "TRUNCATE_ASN1"]:
            desc = f"Truncated signature block by {truncate_bytes or 50} bytes causing ASN.1 parsing failure."
            meta_anomalies.append("Truncated signature block: Unexpected EOF in ASN.1 structure")
        elif manipulation_type == "CORRUPT_ENCODING":
            desc = "Injected non-hex/corrupted DER bytes into signature payload."
            meta_anomalies.append("Corrupted DER encoding in signature container")
        elif manipulation_type == "REUSE_CONFLICT":
            desc = "Reused existing cryptographic signature on different document context."
            sig_conflict = True
        elif manipulation_type == "WEAK_ALGORITHM_DOWNGRADE":
            desc = "Downgraded signature algorithm parameter to MD5-RSA (Weak cryptographic primitive)."
            meta_anomalies.append("Cryptographic downgrade: Insecure digest algorithm MD5 detected")
        else:
            desc = "Altered signature metadata headers."
            meta_anomalies.append("Header structure mismatch in signature container")

        sec_params = qe.extract_security_parameters_from_evidence(
            signature_verified=False,
            integrity_verified=True,
            public_key_status="VALID",
            certificate_status="VALID",
            metadata_anomalies=meta_anomalies,
            signature_reuse_conflict=sig_conflict
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
        if meta_anomalies or sig_conflict or manipulation_type in ["TRUNCATED_SIGNATURE", "TRUNCATE_ASN1", "CORRUPT_ENCODING", "WEAK_ALGORITHM_DOWNGRADE"]:
            threats.append({
                "threat_category": "SIGNATURE_MANIPULATION",
                "threat_type": manipulation_type,
                "severity": "CRITICAL",
                "threat_score": 85.0,
                "confidence": 0.95,
                "threat_status": "FLAGGED",
                "description": f"Structural signature anomaly detected: {desc}"
            })
        composite_risk = qe.calculate_composite_risk_score(
            security_parameters=sec_params,
            state_disturbance=q_state["security_disturbance"],
            combined_pauli_disturbance=pauli_res["combined_pauli_disturbance"],
            forgery_risk_percentage=forg_res["forgery_risk_percentage"]
        )

        elapsed_ms = self.stop_timer()
        threat_categories = [t["threat_category"] for t in threats]
        detection_success = ("SIGNATURE_MANIPULATION" in threat_categories) or ("DIGITAL_SIGNATURE_FORGERY" in threat_categories) or len(threats) > 0

        simulated_attack_state = {
            "signature_status": "STRUCTURE_INVALID",
            "integrity_status": "INTACT",
            "state_consistency": round(q_state["security_consistency"] * 100.0, 2),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "threat_probability": round(meas_res["threat_probability"] * 100.0, 2),
            "risk_score": composite_risk["composite_risk_score"],
            "threats_detected": threat_categories
        }

        explanation = {
            "summary": "Signature Manipulation Simulation evaluated against parser and format validation rules.",
            "manipulation_type": manipulation_type,
            "details": desc,
            "anomalies_flagged": meta_anomalies,
            "pauli_disturbance": f"Combined Pauli disturbance elevated to {pauli_res['combined_percentage']}%.",
            "threat_detected": "SIGNATURE_MANIPULATION detected by structural analysis."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": detection_success,
            "detection_status": "DETECTED" if detection_success else "NOT_DETECTED",
            "signature_valid": False,
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
