"""
Quantum Channel Simulation.
Simulates decoupled theoretical quantum communication channel disturbances (Bell-state transmission,
Pauli bit/phase flips, eavesdropper interception, and projective Born-rule measurement decoherence).
Clearly separated from classical file verification.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class QuantumChannelSimulator(BaseSimulator):
    """
    Simulates theoretical quantum channel disturbances without affecting classical documents.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="QUANTUM_CHANNEL_MANIPULATION", parameters=parameters)

    def simulate(
        self,
        scenario: str = "PAULI_X_DISTURBANCE",
        bell_state_name: str = "PHI_PLUS"
    ) -> SimulationResult:
        """
        Executes a decoupled Bell-state quantum channel transmission disturbance simulation.
        """
        baseline_normal = {
            "channel_status": "INTACT",
            "bell_state": bell_state_name,
            "fidelity": 1.0,
            "disturbance": 0.0,
            "threat_detected": False,
            "decision": "ACCEPT"
        }

        # Execute pure mathematical simulation from quantum_engine
        channel_result = qe.simulate_quantum_channel(
            scenario=scenario,
            bell_state_name=bell_state_name
        )

        fidelity = channel_result["fidelity"]
        disturbance = channel_result["disturbance_score"]
        threat_detected = channel_result["threat_detected"]

        # Born-rule projective probability of detecting threat state
        threat_prob = round(disturbance * 100.0, 2)
        secure_prob = round((1.0 - disturbance) * 100.0, 2)

        # Map to composite risk for consistent platform reporting
        risk_score = round(disturbance * 100.0, 2)
        if risk_score >= 70.0:
            risk_level = "CRITICAL"
        elif risk_score >= 45.0:
            risk_level = "HIGH"
        elif risk_score >= 20.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        elapsed_ms = self.stop_timer()

        threats = []
        if threat_detected:
            threat_cat = "QUANTUM_CHANNEL_DISTURBANCE"
            if scenario == "MEASUREMENT_DISTURBANCE":
                threat_cat = "MEASUREMENT_COLLAPSE"
            threats.append({
                "threat_category": threat_cat,
                "threat_type": channel_result.get("attack_type", "CHANNEL_DISTURBANCE"),
                "severity": "HIGH" if risk_score < 75.0 else "CRITICAL",
                "threat_score": risk_score,
                "threat_status": "FLAGGED",
                "description": channel_result.get("explanation", "Quantum channel disturbance detected.")
            })
            if threat_cat != "QUANTUM_CHANNEL_SIMULATION":
                threats.append({
                    "threat_category": "QUANTUM_CHANNEL_SIMULATION",
                    "threat_type": channel_result.get("attack_type", "CHANNEL_DISTURBANCE"),
                    "severity": "HIGH" if risk_score < 75.0 else "CRITICAL",
                    "threat_score": risk_score,
                    "threat_status": "FLAGGED",
                    "description": channel_result.get("explanation", "Quantum channel disturbance detected.")
                })

        simulated_attack_state = {
            "channel_status": "DISTURBED" if threat_detected else "INTACT",
            "scenario": scenario,
            "fidelity": fidelity,
            "disturbance": disturbance,
            "threat_detected": threat_detected,
            "decision": "REJECT" if threat_detected else "ACCEPT"
        }

        explanation = {
            "summary": "Quantum Channel Simulation executed in isolated mathematical space.",
            "scenario": scenario,
            "bell_state": bell_state_name,
            "attack_type": channel_result.get("attack_type"),
            "channel_fidelity": f"F={fidelity:.4f}",
            "channel_disturbance": f"D={disturbance:.4f}",
            "born_rule_probabilities": f"P(Secure)={secure_prob}%, P(Disturbed)={threat_prob}%",
            "decision": "REJECT - Eavesdropping/Noise Detected" if threat_detected else "ACCEPT - Ideal Transmission",
            "scientific_disclaimer": "Purely theoretical mathematical simulation of quantum states in Hilbert space; classical documents do not exist as physical quantum states."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": threat_detected if scenario != "NO_ATTACK" else True,
            "detection_status": "DETECTED" if threat_detected else ("SECURE" if scenario == "NO_ATTACK" else "NOT_DETECTED"),
            "signature_valid": not threat_detected,
            "integrity_valid": not threat_detected,
            "threats_detected": threats,
            "state_consistency": round(1.0 - disturbance, 4),
            "state_disturbance": round(disturbance, 4),
            "pauli_disturbance": round(disturbance, 4),
            "measurement_secure_probability": round(secure_prob / 100.0, 4),
            "measurement_threat_probability": round(threat_prob / 100.0, 4),
            "forgery_risk_estimate": round(threat_prob, 2),
            "final_risk_score": risk_score,
            "final_risk_level": risk_level,
            "channel_details": channel_result,
            "baseline_comparison": {
                "normal_state": baseline_normal,
                "simulated_attack_state": simulated_attack_state
            },
            "explanation": explanation,
            "execution_time_ms": elapsed_ms,
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
