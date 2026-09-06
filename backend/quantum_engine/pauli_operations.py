"""
Pauli Matrix Operations and Quantum Transformations.

Quantum-Inspired Cyber Threat Detection Simulation Core.
This module defines the standard single-qubit Pauli operators (I, X, Y, Z),
transformation functions, and state disturbance metrics.
"""

import math
from typing import Any, Union
import numpy as np

from quantum_engine.states import (
    normalize_state,
    state_fidelity,
    _to_vector
)


# ==============================================================================
# 1. PAULI MATRICES (SU(2) GENERATORS)
# ==============================================================================

# Identity Operator (No operation):
# I = [[1, 0], [0, 1]]
PAULI_I: np.ndarray = np.array([
    [1.0 + 0.0j, 0.0 + 0.0j],
    [0.0 + 0.0j, 1.0 + 0.0j]
], dtype=np.complex128)

# Pauli X (Bit-flip operator, quantum NOT):
# X = [[0, 1], [1, 0]]
# Transforms: X|0> = |1>, X|1> = |0>
PAULI_X: np.ndarray = np.array([
    [0.0 + 0.0j, 1.0 + 0.0j],
    [1.0 + 0.0j, 0.0 + 0.0j]
], dtype=np.complex128)

# Pauli Y (Bit and phase-flip operator):
# Y = [[0, -i], [i, 0]]
# Transforms: Y|0> = i|1>, Y|1> = -i|0>
PAULI_Y: np.ndarray = np.array([
    [0.0 + 0.0j, -1.0j],
    [1.0j, 0.0 + 0.0j]
], dtype=np.complex128)

# Pauli Z (Phase-flip operator):
# Z = [[1, 0], [0, -1]]
# Transforms: Z|0> = |0>, Z|1> = -|1>
PAULI_Z: np.ndarray = np.array([
    [1.0 + 0.0j, 0.0 + 0.0j],
    [0.0 + 0.0j, -1.0 + 0.0j]
], dtype=np.complex128)


_PAULI_MAP = {
    "i": PAULI_I,
    "identity": PAULI_I,
    "x": PAULI_X,
    "not": PAULI_X,
    "y": PAULI_Y,
    "z": PAULI_Z,
    "phase": PAULI_Z,
}


# ==============================================================================
# 2. PAULI APPLICATION FUNCTIONS
# ==============================================================================

def apply_pauli(state: Any, operation: Union[str, np.ndarray]) -> np.ndarray:
    """
    Applies a specified Pauli matrix operation to a 1-qubit state vector.

    Mathematical formula:
        |ψ'⟩ = U · |ψ⟩
        where U ∈ {I, X, Y, Z}

    Args:
        state: Input single-qubit state vector (dimension 2).
        operation: Operation name ('I', 'X', 'Y', 'Z') or a 2x2 unitary matrix.

    Returns:
        np.ndarray: Resulting normalized 1-qubit state vector.

    Raises:
        ValueError: If state is not 2D or operator is invalid.
    """
    vec = normalize_state(state)
    if vec.shape != (2,):
        raise ValueError(f"Single-qubit Pauli operation requires 2D state, got shape {vec.shape}.")

    if isinstance(operation, str):
        op_key = operation.strip().lower()
        if op_key not in _PAULI_MAP:
            raise ValueError(f"Unknown Pauli operation '{operation}'. Options: ['I', 'X', 'Y', 'Z']")
        matrix = _PAULI_MAP[op_key]
    else:
        matrix = np.asarray(operation, dtype=np.complex128)
        if matrix.shape != (2, 2):
            raise ValueError(f"Pauli operation matrix must be shape (2, 2), got {matrix.shape}.")

    # Matrix-vector multiplication U |ψ⟩
    transformed = np.dot(matrix, vec)
    return normalize_state(transformed)


def apply_x(state: Any) -> np.ndarray:
    """
    Applies the Pauli X (Bit-flip) operator to the state vector.
    Mathematical effect: X|0⟩ = |1⟩, X|1⟩ = |0⟩.
    """
    return apply_pauli(state, PAULI_X)


def apply_y(state: Any) -> np.ndarray:
    """
    Applies the Pauli Y (Bit-and-phase flip) operator to the state vector.
    Mathematical effect: Y|0⟩ = i|1⟩, Y|1⟩ = -i|0⟩.
    """
    return apply_pauli(state, PAULI_Y)


def apply_z(state: Any) -> np.ndarray:
    """
    Applies the Pauli Z (Phase-flip) operator to the state vector.
    Mathematical effect: Z|0⟩ = |0⟩, Z|1⟩ = -|1⟩, Z|+⟩ = |-⟩.
    """
    return apply_pauli(state, PAULI_Z)


def apply_identity(state: Any) -> np.ndarray:
    """
    Applies the Identity operator (no transformation) to the state vector.
    Mathematical effect: I|ψ⟩ = |ψ⟩.
    """
    return apply_pauli(state, PAULI_I)


# ==============================================================================
# 3. STATE DISTURBANCE METRIC
# ==============================================================================

def calculate_state_change(original_state: Any, transformed_state: Any) -> float:
    """
    Calculates the normalized quantum disturbance / state change induced by a transformation.

    Mathematical formula:
        D(|ψ⟩, |φ⟩) = 1.0 - F(|ψ⟩, |φ⟩) = 1.0 - |⟨ψ|φ⟩|^2

    Properties:
        - D = 0.0 when transformed_state is identical to original_state.
        - D = 1.0 when transformed_state is completely orthogonal to original_state.
        - Strictly bounded in [0.0, 1.0].

    Args:
        original_state: Quantum state before transformation.
        transformed_state: Quantum state after transformation.

    Returns:
        float: Normalized disturbance score in [0.0, 1.0].
    """
    fid = state_fidelity(original_state, transformed_state)
    disturbance = 1.0 - fid
    return max(0.0, min(1.0, float(disturbance)))


# ==============================================================================
# 4. DETERMINISTIC SECURITY ANOMALY OPERATOR EVALUATION
# ==============================================================================

def evaluate_pauli_disturbances(
    security_parameters: dict,
    weights: dict = None
) -> dict:
    """
    Evaluates deterministic Pauli disturbance scores from real security parameters.

    Pauli X: Evaluates binary state inversion (e.g. signature verification failure).
    Pauli Z: Evaluates phase/structural disturbance (e.g. metadata/cert anomalies).
    Pauli Y: Evaluates compound multi-indicator failures.
    Combined: Weighted composite Pauli disturbance metric in [0.0, 1.0].
    """
    sig_val = float(security_parameters.get("signature_validity", 1.0))
    hash_integ = float(security_parameters.get("hash_integrity", 1.0))
    pk_val = float(security_parameters.get("public_key_validity", 1.0))
    cert_val = float(security_parameters.get("certificate_validity", 1.0))
    meta_val = float(security_parameters.get("metadata_consistency", 1.0))
    sig_cons = float(security_parameters.get("signature_consistency", 1.0))

    # 1. Pauli X Disturbance (Bit-flip / Inversion)
    # Triggered by signature verification failure and/or hash integrity mismatch
    dist_x = max(0.0, min(1.0, (1.0 - sig_val) * 0.70 + (1.0 - hash_integ) * 0.30))

    # 2. Pauli Z Disturbance (Phase / Structure Anomaly)
    # Triggered by metadata mismatches, cert expiration/untrusted, and signature reuse
    structural_indicators = [meta_val, cert_val, sig_cons, pk_val]
    worst_structural = min(structural_indicators)
    dist_z = max(0.0, min(1.0, 1.0 - worst_structural))

    # 3. Pauli Y Disturbance (Combined Bit & Phase Failure)
    # Models complex compound failure when both verification and metadata fail
    dist_y = max(0.0, min(1.0, math.sqrt(dist_x * dist_z) if (dist_x > 0 and dist_z > 0) else (dist_x * 0.5 + dist_z * 0.5 if (dist_x > 0.5 and dist_z > 0.5) else 0.0)))

    # Weights for combined Pauli disturbance
    w = weights or {"w_x": 0.45, "w_y": 0.35, "w_z": 0.20}
    combined = (w.get("w_x", 0.45) * dist_x +
                w.get("w_y", 0.35) * dist_y +
                w.get("w_z", 0.20) * dist_z)
    combined = max(0.0, min(1.0, combined))

    return {
        "pauli_x_disturbance": round(dist_x, 6),
        "pauli_y_disturbance": round(dist_y, 6),
        "pauli_z_disturbance": round(dist_z, 6),
        "combined_pauli_disturbance": round(combined, 6),
        "pauli_x_percentage": round(dist_x * 100.0, 2),
        "pauli_y_percentage": round(dist_y * 100.0, 2),
        "pauli_z_percentage": round(dist_z * 100.0, 2),
        "combined_percentage": round(combined * 100.0, 2),
        "explanation": (
            f"Pauli X (Bit-flip) disturbance: {dist_x*100:.1f}%, "
            f"Pauli Z (Phase) disturbance: {dist_z*100:.1f}%, "
            f"Pauli Y (Compound) disturbance: {dist_y*100:.1f}%. "
            f"Combined Pauli disturbance: {combined*100:.1f}%."
        )
    }

