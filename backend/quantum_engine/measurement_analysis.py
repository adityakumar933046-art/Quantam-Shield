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

from typing import Dict, Any, List, Optional, Tuple, Sequence, Union
import numpy as np

from quantum_engine.states import STATE_0, STATE_1, normalize_state
from quantum_engine.metrics import (
    calculate_measurement_probability,
    calculate_deviation
)
from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    CHI_SQUARE_MIN_SAMPLE_SIZE,
    CHI_SQUARE_MIN_EXPECTED_COUNT
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


# ==============================================================================
# QDS STATISTICAL MEASUREMENT ANALYSIS & CHI-SQUARE
# ==============================================================================

def calculate_chi_square(
    observed: Sequence[Union[int, float]],
    expected: Sequence[Union[int, float]],
    min_expected_count: float = CHI_SQUARE_MIN_EXPECTED_COUNT,
    min_sample_size: int = CHI_SQUARE_MIN_SAMPLE_SIZE
) -> Dict[str, Any]:
    """
    Performs deterministic Chi-Square goodness-of-fit calculation.

    Formula:
        Chi^2 = Sum_i [ (O_i - E_i)^2 / E_i ]

    Handles sample size constraints safely:
    - If total observations < min_sample_size or any E_i < min_expected_count,
      returns status='insufficient_sample_size', valid=False to prevent misleading conclusions.
    - If E_i == 0 and O_i > 0, returns status='invalid_zero_expected', valid=False.

    Args:
        observed: Sequence of observed frequency counts.
        expected: Sequence of expected frequency counts.
        min_expected_count: Minimum expected count per category (Cochran criterion, default 5.0).
        min_sample_size: Minimum total observations (default 20).

    Returns:
        Dict with chi_square, degrees_of_freedom, valid, and status.
    """
    obs_arr = np.asarray(observed, dtype=np.float64)
    exp_arr = np.asarray(expected, dtype=np.float64)

    if obs_arr.size == 0 or exp_arr.size == 0:
        raise ValueError("Observed and expected sequences cannot be empty.")
    if obs_arr.shape != exp_arr.shape:
        raise ValueError(f"Shape mismatch: observed {obs_arr.shape} vs expected {exp_arr.shape}.")
    if np.any(obs_arr < 0) or np.any(exp_arr < 0):
        raise ValueError("Counts cannot be negative.")

    k = obs_arr.size
    dof = max(1, k - 1)
    total_obs = float(np.sum(obs_arr))
    total_exp = float(np.sum(exp_arr))

    # Check sample size constraint
    if total_obs < min_sample_size or np.any(exp_arr < min_expected_count):
        chi_val = 0.0
        can_compute = True
        for o, e in zip(obs_arr, exp_arr):
            if e > 0:
                chi_val += ((o - e) ** 2) / e
            elif o > 0:
                can_compute = False
        return {
            "chi_square": round(float(chi_val), 6) if can_compute else 0.0,
            "degrees_of_freedom": dof,
            "valid": False,
            "status": "insufficient_sample_size"
        }

    # Check for zero expected counts
    chi_sq = 0.0
    for o, e in zip(obs_arr, exp_arr):
        if e <= 0.0:
            if o > 0.0:
                return {
                    "chi_square": 0.0,
                    "degrees_of_freedom": dof,
                    "valid": False,
                    "status": "invalid_zero_expected"
                }
        else:
            chi_sq += ((o - e) ** 2) / e

    return {
        "chi_square": round(float(chi_sq), 6),
        "degrees_of_freedom": dof,
        "valid": True,
        "status": "valid"
    }


def calculate_total_variation_distance(
    p: Sequence[float],
    q: Sequence[float]
) -> float:
    """
    Calculates Total Variation Distance (TVD) between two probability distributions:
        TV(P, Q) = 1/2 * Sum_i |P(i) - Q(i)|

    Returns:
        float: TVD metric in [0.0, 1.0].
    """
    return calculate_deviation(p, q)


def analyze_qds_measurements(
    observed_measurements: Sequence[Any],
    expected_measurements: Sequence[Any],
    threshold: float = QDS_VERIFICATION_THRESHOLD
) -> Dict[str, Any]:
    """
    Performs deterministic statistical analysis of QDS measurement outcomes.

    Calculates:
        N = total measurements
        M = number of mismatches
        epsilon = M / N (mismatch rate)
        accuracy = 1 - epsilon
        accepted = (epsilon <= threshold)
        distribution_distance = TV(observed_distribution, expected_distribution)
        chi_square_analysis = Chi-square test on outcome frequencies

    Args:
        observed_measurements: Sequence of observed binary or categorical outcomes.
        expected_measurements: Sequence of expected binary or categorical outcomes.
        threshold: Permissible mismatch threshold (default 0.10).

    Returns:
        Dict with total_measurements, matches, mismatches, mismatch_rate, accuracy,
        threshold, accepted, observed_distribution, expected_distribution,
        distribution_distance, chi_square_analysis, and explanation.
    """
    if observed_measurements is None or expected_measurements is None:
        raise ValueError("Measurement sequences cannot be None.")

    n_obs = len(observed_measurements)
    n_exp = len(expected_measurements)

    if n_obs == 0 or n_exp == 0:
        raise ValueError("Measurement sequences cannot be empty.")
    if n_obs != n_exp:
        raise ValueError(f"Measurement count mismatch: observed has {n_obs}, expected has {n_exp}.")
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"Threshold must be in [0.0, 1.0], got {threshold}.")

    # Count mismatches
    mismatches = sum(1 for obs, exp in zip(observed_measurements, expected_measurements) if obs != exp)
    matches = n_obs - mismatches
    epsilon = mismatches / n_obs
    accuracy = 1.0 - epsilon
    accepted = bool(epsilon <= threshold)

    # Empirical outcome distributions over canonical binary outcomes {0, 1}
    all_outcomes = sorted(list(set(list(observed_measurements) + list(expected_measurements))))
    if not all_outcomes:
        all_outcomes = [0, 1]
    elif len(all_outcomes) == 1:
        all_outcomes = [0, 1] if all_outcomes[0] in (0, 1) else [all_outcomes[0], f"not_{all_outcomes[0]}"]

    obs_counts = [sum(1 for x in observed_measurements if x == val) for val in all_outcomes]
    exp_counts = [sum(1 for x in expected_measurements if x == val) for val in all_outcomes]

    obs_dist = [c / n_obs for c in obs_counts]
    exp_dist = [c / n_exp for c in exp_counts]

    dist_distance = calculate_deviation(exp_dist, obs_dist)
    chi_analysis = calculate_chi_square(obs_counts, exp_counts)

    explanation = (
        f"QDS Measurement Analysis: {matches}/{n_obs} matches ({accuracy*100:.2f}% accuracy). "
        f"Mismatch rate epsilon={epsilon:.4f} ({'<=' if accepted else '>'} threshold {threshold:.2f}). "
        f"TVD distribution distance={dist_distance:.4f}."
    )

    return {
        "total_measurements": n_obs,
        "matches": matches,
        "mismatches": mismatches,
        "mismatch_rate": round(float(epsilon), 6),
        "accuracy": round(float(accuracy), 6),
        "threshold": float(threshold),
        "accepted": accepted,
        "observed_distribution": [round(float(p), 6) for p in obs_dist],
        "expected_distribution": [round(float(p), 6) for p in exp_dist],
        "distribution_distance": round(float(dist_distance), 6),
        "chi_square_analysis": chi_analysis,
        "explanation": explanation
    }

