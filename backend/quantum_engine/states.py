"""
Quantum Basis States and State Vector Utilities.

Quantum-Inspired Cyber Threat Detection Simulation Core.
This module provides pure mathematical representations of quantum state vectors
using complex NumPy arrays. No physical quantum hardware or AI/ML is used.
"""

from typing import Any, Union
import numpy as np


# ==============================================================================
# 1. CANONICAL BASIS STATES
# ==============================================================================

# Computational / Z-basis eigenstates:
# |0> represents the ground state [1, 0]^T
# |1> represents the excited state [0, 1]^T
STATE_0: np.ndarray = np.array([1.0, 0.0], dtype=np.complex128)
STATE_1: np.ndarray = np.array([0.0, 1.0], dtype=np.complex128)

# Diagonal / X-basis eigenstates:
# |+> = (|0> + |1>) / sqrt(2)
# |-> = (|0> - |1>) / sqrt(2)
STATE_PLUS: np.ndarray = np.array([1.0, 1.0], dtype=np.complex128) / np.sqrt(2.0)
STATE_MINUS: np.ndarray = np.array([1.0, -1.0], dtype=np.complex128) / np.sqrt(2.0)

# Circular / Y-basis eigenstates:
# |i+> = (|0> + i|1>) / sqrt(2)
# |i-> = (|0> - i|1>) / sqrt(2)
STATE_I_PLUS: np.ndarray = np.array([1.0, 1.0j], dtype=np.complex128) / np.sqrt(2.0)
STATE_I_MINUS: np.ndarray = np.array([1.0, -1.0j], dtype=np.complex128) / np.sqrt(2.0)


# ==============================================================================
# 2. VALIDATION AND NORMALIZATION UTILITIES
# ==============================================================================

def _to_vector(state: Any) -> np.ndarray:
    """
    Validates and converts input into a 1D NumPy complex128 array.
    Raises ValueError or TypeError if input is invalid.
    """
    if state is None:
        raise ValueError("State vector cannot be None.")

    try:
        arr = np.asarray(state, dtype=np.complex128)
    except (TypeError, ValueError) as err:
        raise TypeError(f"State vector cannot be converted to complex array: {err}") from err

    if arr.size == 0:
        raise ValueError("State vector cannot be empty.")

    if not np.all(np.isfinite(arr)):
        raise ValueError("State vector contains NaN or infinite values.")

    # Flatten column vectors (e.g. shape (N, 1)) to 1D shape (N,)
    if arr.ndim > 2 or (arr.ndim == 2 and arr.shape[1] != 1 and arr.shape[0] != 1):
        raise ValueError(f"State vector must be 1D or column vector, got shape {arr.shape}.")

    return arr.flatten()


def is_valid_state(state: Any, tol: float = 1e-6) -> bool:
    """
    Checks whether the input represents a mathematically valid quantum state vector.
    A valid state must be a non-empty numeric vector with Euclidean norm ||state|| = 1.

    Mathematical definition:
        || |ψ⟩ ||^2 = Σ |ψ_i|^2 = 1 ± tol

    Args:
        state: Candidate state vector (list, tuple, or np.ndarray).
        tol: Tolerance for the norm check (default 1e-6).

    Returns:
        bool: True if valid and normalized, False otherwise.
    """
    try:
        vec = _to_vector(state)
        norm = np.linalg.norm(vec)
        return bool(abs(norm - 1.0) <= tol)
    except (ValueError, TypeError):
        return False


def normalize_state(state: Any) -> np.ndarray:
    """
    Normalizes a quantum state vector to unit Euclidean norm.

    Mathematical formula:
        |ψ_norm⟩ = |ψ⟩ / || |ψ⟩ ||
        where || |ψ⟩ || = sqrt(⟨ψ|ψ⟩) = sqrt(Σ |ψ_i|^2)

    Args:
        state: Unnormalized state vector (1D array or list).

    Returns:
        np.ndarray: Normalized 1D complex128 state vector.

    Raises:
        ValueError: If the vector norm is zero or non-finite.
    """
    vec = _to_vector(state)
    norm = np.linalg.norm(vec)
    if norm < 1e-12:
        raise ValueError("Cannot normalize a state vector with zero norm.")

    normalized = vec / norm
    return normalized


# ==============================================================================
# 3. INNER PRODUCT AND FIDELITY
# ==============================================================================

def state_inner_product(state_a: Any, state_b: Any) -> complex:
    """
    Computes the quantum inner product (braket) between state_a and state_b.

    Mathematical formula:
        ⟨a|b⟩ = Σ_k (a_k)* · b_k = a^† · b

    Args:
        state_a: Bra vector ⟨a| (1D complex array).
        state_b: Ket vector |b⟩ (1D complex array).

    Returns:
        complex: Complex inner product scalar.

    Raises:
        ValueError: If vector dimensions mismatch.
    """
    vec_a = _to_vector(state_a)
    vec_b = _to_vector(state_b)

    if vec_a.shape != vec_b.shape:
        raise ValueError(
            f"State dimension mismatch for inner product: {vec_a.shape} vs {vec_b.shape}."
        )

    # np.vdot conjugates the first argument: sum(conj(vec_a[i]) * vec_b[i])
    return complex(np.vdot(vec_a, vec_b))


def state_fidelity(state_a: Any, state_b: Any) -> float:
    """
    Calculates the quantum state fidelity between two pure states.

    Mathematical formula:
        F(|ψ⟩, |φ⟩) = |⟨ψ|φ⟩|^2 = |Σ (ψ_k)* · φ_k|^2

    Properties:
        - 0.0 <= F <= 1.0
        - F = 1.0 if and only if |ψ⟩ and |φ⟩ are identical up to global phase.
        - F = 0.0 if and only if |ψ⟩ and |φ⟩ are completely orthogonal.

    Args:
        state_a: First quantum state vector.
        state_b: Second quantum state vector.

    Returns:
        float: Deterministic fidelity value in [0.0, 1.0].
    """
    norm_a = normalize_state(state_a)
    norm_b = normalize_state(state_b)

    overlap = state_inner_product(norm_a, norm_b)
    fidelity = float(abs(overlap) ** 2)

    # Clamp to [0.0, 1.0] to account for any floating-point imprecision
    return max(0.0, min(1.0, fidelity))
