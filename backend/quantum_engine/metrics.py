"""
Deterministic Mathematical Security Metrics.

Quantum-Inspired Cyber Threat Detection Simulation Core.
This module provides closed-form, deterministic quantum-inspired metrics:
Born-rule projective measurement probabilities, state disturbance,
consistency scores, measurement distributions, and statistical deviation.

No random behaviour, heuristics, or AI/ML models are used.
"""

from typing import Any, Sequence, Union
import numpy as np

from quantum_engine.states import (
    normalize_state,
    state_fidelity,
    state_inner_product,
    _to_vector
)


# ==============================================================================
# 1. MEASUREMENT PROBABILITY (BORN RULE)
# ==============================================================================

def calculate_measurement_probability(state: Any, basis_state: Any) -> float:
    """
    Computes the Born-rule projective measurement probability of observing a target basis state.

    Mathematical formula:
        P(basis) = |⟨basis|state⟩|^2 = |Σ (basis_k)* · state_k|^2

    Postulates of Quantum Mechanics:
        Given normalized state |ψ⟩ and orthonormal projector Π_i = |i⟩⟨i|,
        the probability of outcome i is Tr(Π_i |ψ⟩⟨ψ|) = |⟨i|ψ⟩|^2.

    Args:
        state: The prepared quantum state vector.
        basis_state: The measurement basis eigenstate.

    Returns:
        float: Deterministic probability in [0.0, 1.0].
    """
    norm_state = normalize_state(state)
    norm_basis = normalize_state(basis_state)

    if norm_state.shape != norm_basis.shape:
        raise ValueError(
            f"Dimension mismatch between state {norm_state.shape} and basis {norm_basis.shape}."
        )

    overlap = state_inner_product(norm_basis, norm_state)
    prob = float(abs(overlap) ** 2)
    return max(0.0, min(1.0, prob))


# ==============================================================================
# 2. STATE DISTURBANCE AND CONSISTENCY
# ==============================================================================

def calculate_state_disturbance(expected_state: Any, observed_state: Any) -> float:
    """
    Calculates the quantum state disturbance (tampering/eavesdropping indicator).

    Mathematical formula:
        D(|ψ_exp⟩, |ψ_obs⟩) = 1.0 - F(|ψ_exp⟩, |ψ_obs⟩) = 1.0 - |⟨ψ_exp|ψ_obs⟩|^2

    Properties:
        - D = 0.0 when observed_state matches expected_state exactly (No disturbance).
        - D = 1.0 when observed_state is completely orthogonal (Maximum disturbance).
        - Normalized in [0.0, 1.0].

    Args:
        expected_state: Expected reference quantum state vector.
        observed_state: Observed/received quantum state vector.

    Returns:
        float: Deterministic disturbance metric in [0.0, 1.0].
    """
    fid = state_fidelity(expected_state, observed_state)
    return max(0.0, min(1.0, 1.0 - fid))


def calculate_consistency_score(expected_state: Any, observed_state: Any) -> float:
    """
    Calculates the quantum state consistency score (integrity verification metric).

    Mathematical formula:
        C(|ψ_exp⟩, |ψ_obs⟩) = F(|ψ_exp⟩, |ψ_obs⟩) = |⟨ψ_exp|ψ_obs⟩|^2

    Properties:
        - C = 1.0 when the observed state is perfectly intact.
        - C = 0.0 when the observed state has suffered complete bit/phase inversion.
        - Normalized in [0.0, 1.0].

    Args:
        expected_state: Expected reference quantum state vector.
        observed_state: Observed/received quantum state vector.

    Returns:
        float: Deterministic consistency score in [0.0, 1.0].
    """
    return state_fidelity(expected_state, observed_state)


# ==============================================================================
# 3. MEASUREMENT DISTRIBUTIONS AND DEVIATION
# ==============================================================================

def calculate_measurement_distribution(
    states: Sequence[Any],
    basis_states: Sequence[Any]
) -> np.ndarray:
    """
    Calculates the ensemble measurement probability distribution over a set of basis states.

    Mathematical formula:
        For basis state |b_i⟩ over an ensemble of N states {|ψ_1⟩, ..., |ψ_N⟩}:
            P_i = (1 / N) * Σ_{j=1}^N |⟨b_i|ψ_j⟩|^2

        Normalized such that Σ_i P_i = 1.0 (for complete orthonormal basis).

    Args:
        states: Sequence of quantum state vectors.
        basis_states: Sequence of orthonormal measurement basis state vectors.

    Returns:
        np.ndarray: 1D array of probabilities summing to 1.0.

    Raises:
        ValueError: If states or basis_states is empty.
    """
    if len(states) == 0:
        raise ValueError("Cannot calculate distribution for an empty states ensemble.")
    if len(basis_states) == 0:
        raise ValueError("Cannot calculate distribution with empty basis states.")

    norm_states = [normalize_state(s) for s in states]
    norm_basis = [normalize_state(b) for b in basis_states]

    num_basis = len(norm_basis)
    probs = np.zeros(num_basis, dtype=np.float64)

    for i, basis_vec in enumerate(norm_basis):
        basis_probs = [
            calculate_measurement_probability(state_vec, basis_vec)
            for state_vec in norm_states
        ]
        probs[i] = float(np.mean(basis_probs))

    # Normalize to ensure sum = 1.0
    total = np.sum(probs)
    if total > 1e-12:
        probs = probs / total

    return probs


def calculate_deviation(
    expected_distribution: Any,
    observed_distribution: Any
) -> float:
    """
    Calculates the statistical deviation between expected and observed distributions
    using the Total Variation Distance (TVD).

    Mathematical formula:
        D_TV(P, Q) = (1 / 2) * Σ_k |P_k - Q_k|

    Properties:
        - 0.0 <= D_TV <= 1.0 for valid probability distributions.
        - D_TV = 0.0 when distributions are identical.
        - D_TV = 1.0 when distributions have completely disjoint supports.

    Args:
        expected_distribution: 1D array or sequence of expected probabilities.
        observed_distribution: 1D array or sequence of observed probabilities.

    Returns:
        float: Normalized deviation score between 0.0 and 1.0.

    Raises:
        ValueError: If array dimensions mismatch, are empty, or contain negative values.
    """
    p = np.asarray(expected_distribution, dtype=np.float64).flatten()
    q = np.asarray(observed_distribution, dtype=np.float64).flatten()

    if p.size == 0 or q.size == 0:
        raise ValueError("Distributions cannot be empty.")

    if p.shape != q.shape:
        raise ValueError(f"Distribution length mismatch: {p.shape} vs {q.shape}.")

    if np.any(p < 0.0) or np.any(q < 0.0):
        raise ValueError("Probabilities cannot be negative.")

    # Normalize if not normalized
    sum_p = np.sum(p)
    sum_q = np.sum(q)

    if sum_p <= 1e-12 or sum_q <= 1e-12:
        raise ValueError("Distribution sums must be strictly positive.")

    p_norm = p / sum_p
    q_norm = q / sum_q

    # Total Variation Distance
    tvd = 0.5 * np.sum(np.abs(p_norm - q_norm))
    return max(0.0, min(1.0, float(tvd)))
