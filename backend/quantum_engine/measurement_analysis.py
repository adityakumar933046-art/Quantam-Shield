"""
Deterministic Projective Measurement and Probability Distribution Analysis.

Module: quantum_engine.measurement_analysis
Applies the Born rule of quantum measurement to the two-state security representation.
Calculates deterministic probabilities, expected vs observed distributions, and statistical deviations.

Scientific Note:
Production security decisions use 100% deterministic Born-rule projective probabilities:
P(secure) = |<0|psi>|^2, P(threat) = |<1|psi>|^2.
Random sampling is strictly isolated in simulation functions.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np

from quantum_engine.states import STATE_0, STATE_1, normalize_state
from quantum_engine.metrics import (
    calculate_measurement_probability,
    calculate_deviation
)


def analyze_projective_measurements(
    state_vector: Any,
    expected_distribution: Optional[List[float]] = None
) -> Dict[str, Any]:
    """
    Performs deterministic projective measurement analysis onto standard basis:
        |0> = Secure
        |1> = Threat

    Mathematical formulas:
        P(secure) = |<0|psi>|^2
        P(threat) = |<1|psi>|^2
        P(secure) + P(threat) = 1.0
    """
    norm_psi = normalize_state(state_vector)

    p_secure = calculate_measurement_probability(norm_psi, STATE_0)
    p_threat = calculate_measurement_probability(norm_psi, STATE_1)

    # Enforce exact normalization
    total_p = p_secure + p_threat
    if total_p > 0:
        p_secure = p_secure / total_p
        p_threat = p_threat / total_p
    else:
        p_secure = 0.5
        p_threat = 0.5

    # Target baseline: perfect secure condition has P(0)=1.0, P(1)=0.0
    exp_dist = expected_distribution if expected_distribution else [1.0, 0.0]
    obs_dist = [float(p_secure), float(p_threat)]

    # Statistical deviation from ideal secure condition
    deviation = calculate_deviation(exp_dist, obs_dist)

    return {
        "secure_probability": round(p_secure, 6),
        "threat_probability": round(p_threat, 6),
        "secure_percentage": round(p_secure * 100.0, 2),
        "threat_percentage": round(p_threat * 100.0, 2),
        "expected_distribution": exp_dist,
        "observed_distribution": [round(x, 6) for x in obs_dist],
        "distribution_deviation": round(float(deviation), 6),
        "sum_of_probabilities": round(p_secure + p_threat, 6),
        "explanation": (
            f"Born-rule measurement yields P(Secure)={p_secure*100:.2f}%, P(Threat)={p_threat*100:.2f}%. "
            f"Statistical deviation from expected ideal secure baseline is Delta={deviation:.4f}."
        )
    }


def simulate_stochastic_measurements(
    state_vector: Any,
    number_of_shots: int = 100,
    seed: Optional[int] = None
) -> Dict[str, Any]:
    """
    SIMULATION-ONLY FEATURE:
    Simulates stochastic measurement sampling over N independent shots for demonstration.
    Separated from production deterministic security decisions.
    """
    norm_psi = normalize_state(state_vector)
    p_secure = calculate_measurement_probability(norm_psi, STATE_0)
    p_threat = 1.0 - p_secure

    rng = np.random.default_rng(seed)
    # 0 = secure, 1 = threat
    samples = rng.choice([0, 1], size=number_of_shots, p=[p_secure, p_threat])

    count_0 = int(np.sum(samples == 0))
    count_1 = int(np.sum(samples == 1))

    sim_p_secure = count_0 / number_of_shots
    sim_p_threat = count_1 / number_of_shots

    return {
        "simulation_mode": True,
        "number_of_shots": number_of_shots,
        "seed_used": seed,
        "secure_counts": count_0,
        "threat_counts": count_1,
        "simulated_secure_rate": round(sim_p_secure, 4),
        "simulated_threat_rate": round(sim_p_threat, 4),
        "analytical_secure_probability": round(p_secure, 4),
        "sampling_error": round(abs(sim_p_secure - p_secure), 4)
    }
