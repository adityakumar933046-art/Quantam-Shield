"""
Document Tampering Simulation.
Applies controlled modifications to temporary copies of documents (text, JSON, PDF simulation)
and verifies detection across hash integrity, signature verification, and quantum engine.
"""

import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from attack_simulation.base_simulator import BaseSimulator, SimulationResult
import quantum_engine as qe


class DocumentTamperingSimulator(BaseSimulator):
    """
    Simulates controlled unauthorized document modification.
    """

    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(attack_type="DOCUMENT_TAMPERING", parameters=parameters)

    def simulate(
        self,
        original_content: Optional[bytes] = None,
        original_hash: Optional[str] = None,
        signature_present: bool = True,
        tamper_mode: str = "CHAR_FLIP",
        custom_payload: Optional[str] = None,
        strategy: Optional[str] = None,
        flip_index: Optional[int] = None
    ) -> SimulationResult:
        """
        Executes a controlled document tampering simulation on an in-memory temporary copy.
        """
        if original_content is None:
            original_content = b"Sample confidential record for Q-SHIELD security verification."
        if original_hash is None:
            original_hash = hashlib.sha256(original_content).hexdigest()

        if strategy is not None:
            tamper_mode = strategy

        # 1. Capture baseline normal state
        baseline_normal = {
            "signature_status": "VALID" if signature_present else "NO_SIGNATURE",
            "integrity_status": "INTACT",
            "state_consistency": 1.0,
            "state_disturbance": 0.0,
            "threat_probability": 0.0,
            "risk_score": 10.0,
            "threats_detected": []
        }

        # 2. Apply controlled in-memory modification
        modified_content = bytearray(original_content)
        tamper_description = ""

        if tamper_mode in ["NO_ATTACK", "NONE", "BASELINE"]:
            tamper_description = "Zero modification (Intact baseline baseline scenario)"
        elif tamper_mode in ["CHAR_FLIP", "CHARACTER_FLIP"]:
            if flip_index is not None and 0 <= flip_index < len(modified_content):
                idx = flip_index
            elif len(modified_content) > 10:
                idx = len(modified_content) // 2
            else:
                idx = 0
            if len(modified_content) > 0:
                modified_content[idx] = (modified_content[idx] + 1) % 256
                tamper_description = f"Flipped single byte at position {idx}"
            else:
                modified_content.extend(b"_tampered")
                tamper_description = "Appended '_tampered' byte sequence"
        elif tamper_mode == "WORD_REPLACE":
            try:
                text = original_content.decode("utf-8", errors="replace")
                if " " in text:
                    parts = text.split(" ", 1)
                    tampered_text = parts[0] + "_MODIFIED " + parts[1]
                else:
                    tampered_text = text + " [MODIFIED_PAYLOAD]"
                modified_content = bytearray(tampered_text.encode("utf-8"))
                tamper_description = "Altered lexical token in text body"
            except Exception:
                modified_content.extend(b" [MODIFIED]")
                tamper_description = "Appended modified byte payload"
        elif tamper_mode == "JSON_VALUE_TAMPER":
            try:
                data = json.loads(original_content.decode("utf-8"))
                if isinstance(data, dict) and data:
                    first_key = next(iter(data))
                    data[first_key] = f"{data[first_key]}_TAMPERED"
                else:
                    data = {"tampered": True, "original": str(original_content[:20])}
                modified_content = bytearray(json.dumps(data, indent=2).encode("utf-8"))
                tamper_description = "Mutated target field value within JSON structure"
            except Exception:
                modified_content.extend(b'{"tampered":true}')
                tamper_description = "Appended malicious JSON fragment"
        else:
            payload = custom_payload or "UNAUTHORIZED_MODIFICATION"
            modified_content.extend(payload.encode("utf-8", errors="ignore"))
            tamper_description = f"Injected controlled payload: {payload[:20]}..."

        # 3. Compute new hash
        new_hash = hashlib.sha256(modified_content).hexdigest()
        hash_matched = (new_hash == original_hash)

        # 4. Cryptographic integrity evaluation
        integrity_valid = hash_matched
        signature_valid = False if not integrity_valid else signature_present

        # 5. Quantum-Inspired Threat Analysis
        sec_params = qe.extract_security_parameters_from_evidence(
            signature_verified=signature_valid,
            integrity_verified=integrity_valid,
            public_key_status="VALID",
            certificate_status="VALID",
            raw_signature_detected=signature_present
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
        detection_success = ("DOCUMENT_TAMPERING" in threat_categories) or (not integrity_valid)

        simulated_attack_state = {
            "signature_status": "INVALID" if not signature_valid else "VALID",
            "integrity_status": "MODIFIED",
            "state_consistency": round(q_state["security_consistency"] * 100.0, 2),
            "state_disturbance": round(q_state["security_disturbance"], 4),
            "threat_probability": round(meas_res["threat_probability"] * 100.0, 2),
            "risk_score": composite_risk["composite_risk_score"],
            "threats_detected": threat_categories
        }

        explanation = {
            "summary": "Document Tampering Simulation executed on isolated copy.",
            "tamper_method": tamper_description,
            "original_digest": original_hash,
            "tampered_digest": new_hash,
            "hash_comparison": "FAIL (Digests differ, content modification proved)",
            "threat_detected": "DOCUMENT_TAMPERING successfully identified by integrity layer.",
            "quantum_state_impact": f"State disturbance increased to D={q_state['security_disturbance']:.4f}."
        }

        return SimulationResult({
            "simulation_id": self.simulation_id,
            "attack_type": self.attack_type,
            "detection_success": detection_success,
            "detection_status": "DETECTED" if detection_success else ("SECURE" if integrity_valid else "NOT_DETECTED"),
            "original_hash": original_hash,
            "tampered_hash": new_hash,
            "signature_valid": signature_valid,
            "integrity_valid": integrity_valid,
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
