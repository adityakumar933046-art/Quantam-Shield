"""
Maximally Entangled Two-Qubit Bell States.

Quantum-Inspired Cyber Threat Detection Simulation Core.
This module constructs the four canonical maximally entangled bipartite states
(Bell states / EPR pairs) using Kronecker products and provides verification utilities.
"""

from typing import Dict, Any
import numpy as np

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    normalize_state,
    state_fidelity,
    _to_vector
)


# ==============================================================================
# 1. TENSOR / KRONECKER PRODUCT BASIS (2-QUBIT COMPUTATIONAL BASIS)
# ==============================================================================

# |00> = |0> ⊗ |0> = [1, 0, 0, 0]^T
STATE_00: np.ndarray = np.kron(STATE_0, STATE_0)

# |01> = |0> ⊗ |1> = [0, 1, 0, 0]^T
STATE_01: np.ndarray = np.kron(STATE_0, STATE_1)

# |10> = |1> ⊗ |0> = [0, 0, 1, 0]^T
STATE_10: np.ndarray = np.kron(STATE_1, STATE_0)

# |11> = |1> ⊗ |1> = [0, 0, 0, 1]^T
STATE_11: np.ndarray = np.kron(STATE_1, STATE_1)


# ==============================================================================
# 2. CANONICAL BELL STATES
# ==============================================================================

# |Φ+⟩ = (|00⟩ + |11⟩) / sqrt(2) = [1/sqrt(2), 0, 0, 1/sqrt(2)]^T
BELL_PHI_PLUS: np.ndarray = (STATE_00 + STATE_11) / np.sqrt(2.0)

# |Φ-⟩ = (|00⟩ - |11⟩) / sqrt(2) = [1/sqrt(2), 0, 0, -1/sqrt(2)]^T
BELL_PHI_MINUS: np.ndarray = (STATE_00 - STATE_11) / np.sqrt(2.0)

# |Ψ+⟩ = (|01⟩ + |10⟩) / sqrt(2) = [0, 1/sqrt(2), 1/sqrt(2), 0]^T
BELL_PSI_PLUS: np.ndarray = (STATE_01 + STATE_10) / np.sqrt(2.0)

# |Ψ-⟩ = (|01⟩ - |10⟩) / sqrt(2) = [0, 1/sqrt(2), -1/sqrt(2), 0]^T
BELL_PSI_MINUS: np.ndarray = (STATE_01 - STATE_10) / np.sqrt(2.0)


_BELL_MAP: Dict[str, np.ndarray] = {
    "phi_plus": BELL_PHI_PLUS,
    "phi+": BELL_PHI_PLUS,
    "phi_minus": BELL_PHI_MINUS,
    "phi-": BELL_PHI_MINUS,
    "psi_plus": BELL_PSI_PLUS,
    "psi+": BELL_PSI_PLUS,
    "psi_minus": BELL_PSI_MINUS,
    "psi-": BELL_PSI_MINUS,
}


# ==============================================================================
# 3. BELL STATE RETRIEVAL AND FIDELITY FUNCTIONS
# ==============================================================================

def get_bell_state(name: str) -> np.ndarray:
    """
    Retrieves the normalized 4-dimensional state vector for a specified Bell state.

    Supported names (case-insensitive):
        - 'phi_plus' or 'phi+'  -> |Φ+⟩ = (|00⟩ + |11⟩) / sqrt(2)
        - 'phi_minus' or 'phi-' -> |Φ-⟩ = (|00⟩ - |11⟩) / sqrt(2)
        - 'psi_plus' or 'psi+'  -> |Ψ+⟩ = (|01⟩ + |10⟩) / sqrt(2)
        - 'psi_minus' or 'psi-' -> |Ψ-⟩ = (|01⟩ - |10⟩) / sqrt(2)

    Args:
        name: Name or symbol of the Bell state.

    Returns:
        np.ndarray: 4-element complex128 array representing the state vector.

    Raises:
        ValueError: If the Bell state name is unrecognized.
    """
    if not isinstance(name, str):
        raise TypeError(f"Bell state name must be a string, got {type(name).__name__}.")

    clean_name = name.strip().lower().replace(" ", "_")
    if clean_name not in _BELL_MAP:
        valid_keys = ["phi_plus", "phi_minus", "psi_plus", "psi_minus"]
        raise ValueError(
            f"Unknown Bell state '{name}'. Valid options: {valid_keys}"
        )

    # Return a copy to prevent in-place mutation
    return np.copy(_BELL_MAP[clean_name])


def get_all_bell_states() -> Dict[str, np.ndarray]:
    """
    Returns a dictionary of all four canonical Bell states.

    Returns:
        Dict[str, np.ndarray]: Mapping with canonical keys:
            'phi_plus', 'phi_minus', 'psi_plus', 'psi_minus'.
    """
    return {
        "phi_plus": np.copy(BELL_PHI_PLUS),
        "phi_minus": np.copy(BELL_PHI_MINUS),
        "psi_plus": np.copy(BELL_PSI_PLUS),
        "psi_minus": np.copy(BELL_PSI_MINUS),
    }


def bell_state_fidelity(state_a: Any, state_b: Any) -> float:
    """
    Calculates the quantum state fidelity between two 2-qubit states (dim = 4).

    Mathematical formula:
        F(|Ψ_a⟩, |Ψ_b⟩) = |⟨Ψ_a|Ψ_b⟩|^2

    Args:
        state_a: First 2-qubit state vector.
        state_b: Second 2-qubit state vector.

    Returns:
        float: Deterministic fidelity value between 0.0 and 1.0.

    Raises:
        ValueError: If state vectors are not 4-dimensional.
    """
    vec_a = _to_vector(state_a)
    vec_b = _to_vector(state_b)

    if vec_a.shape != (4,) or vec_b.shape != (4,):
        raise ValueError(
            f"Bell state vectors must be 4-dimensional, got {vec_a.shape} and {vec_b.shape}."
        )

    return state_fidelity(vec_a, vec_b)
