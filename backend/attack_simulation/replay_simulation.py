"""
Replay Attack Simulation.
Generates controlled synthetic verification events to test time-window threshold detection
and replay attack prevention mechanisms.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class ReplayAttackSimulator(BaseSimulator):
    """
    Simulates repeated, rapid document verification traffic without modifying database originals.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="REPLAY_ATTACK", parameters=parameters)

    def simulate(
        self,
        document_hash: str = "SYNTHETIC_REPLAY_HASH",
        number_of_attempts: int = 20,
        time_window_seconds: int = 10,
        same_user: bool = True,
        same_source_identifier: bool = True,
        attempt_count: Optional[int] = None,
        interval_seconds: Optional[float] = None,
        threshold: int = 5
    ) -> SimulationResult:
        """
        Executes a controlled replay attack pattern simulation.
        """
        if attempt_count is not None:
            number_of_attempts = attempt_count
        if interval_seconds is not None:
            time_window_seconds = max(1, int(number_of_attempts * interval_seconds))

        baseline_normal = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": 1.0,
            "state_disturbance": 0.0,
            "threat_probability": 0.0,
            "risk_score": 10.0,
            "threats_detected": []
        }

        # Deterministic history-based replay evaluation
        rate_per_sec = number_of_attempts / max(1.0, float(time_window_seconds))
        is_replay = (number_of_attempts >= threshold) or (number_of_attempts >= 5 and time_window_seconds <= 300) or (number_of_attempts >= 10)

        if number_of_attempts <= 1:
            traffic_classification = "NORMAL"
            replay_safety = 1.0
        elif number_of_attempts <= 3 and time_window_seconds >= 60:
            traffic_classification = "NORMAL_REPEAT"
            replay_safety = 0.85
        elif is_replay:
            traffic_classification = "REPLAY_SUSPECT"
            replay_safety = max(0.0, 1.0 - (number_of_attempts * 0.05))
        else:
            traffic_classification = "ELEVATED_ACTIVITY"
            replay_safety = 0.60

        replay_detected = is_replay

        sec_params = qe.extract_security_parameters_from_evidence(
            signature_verified=True,
            integrity_verified=True,
            public_key_status="VALID",
            certificate_status="VALID",
            replay_detected=replay_detected
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
        final_risk_score = composite_risk["composite_risk_score"]
        final_risk_level = composite_risk["risk_level"]
        if replay_detected:
            final_risk_score = max(final_risk_score, 75.0)
            final_risk_level = "HIGH" if final_risk_score < 85.0 else "CRITICAL"

        simulated_attack_state = {
            "signature_status": "VALID",
            "integrity_status": "INTACT",
            "state_consistency": round(q_state["security_consistency"] * 100.0, 2),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "threat_probability": round(meas_res["threat_probability"] * 100.0, 2),
            "risk_score": final_risk_score,
            "threats_detected": threat_categories
        }

        explanation = {
            "summary": "Replay Attack Pattern Simulation evaluated across time window history.",
            "total_attempts": number_of_attempts,
            "time_window": f"{time_window_seconds}s",
            "rate_per_second": rate_per_sec,
            "traffic_classification": traffic_classification,
            "replay_decision": "REPLAY_ATTACK detected by frequency monitor" if replay_detected else "Normal verification frequency",
            "risk_score_penalty": f"Risk score increased to {final_risk_score:.1f} due to replay behavior."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": ("REPLAY_ATTACK" in threat_categories) or replay_detected,
            "detection_status": "DETECTED" if (("REPLAY_ATTACK" in threat_categories) or replay_detected) else "NOT_DETECTED",
            "signature_valid": True,
            "integrity_valid": True,
            "threats_detected": threats,
            "state_consistency": round(q_state["security_consistency"], 4),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "pauli_disturbance": round(pauli_res["combined_pauli_disturbance"], 4),
            "measurement_secure_probability": round(meas_res["secure_probability"], 4),
            "measurement_threat_probability": round(meas_res["threat_probability"], 4),
            "forgery_risk_estimate": forg_res["forgery_risk_percentage"],
            "final_risk_score": final_risk_score,
            "final_risk_level": final_risk_level,
            "baseline_comparison": {
                "normal_state": baseline_normal,
                "simulated_attack_state": simulated_attack_state
            },
            "explanation": explanation,
            "execution_time_ms": elapsed_ms,
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
