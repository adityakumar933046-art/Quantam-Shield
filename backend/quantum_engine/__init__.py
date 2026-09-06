"""
Quantum-Inspired Cyber Threat Detection Simulation Core.

Package: quantum_engine
Clean, modular, deterministic mathematical simulation layer.
Contains NO AI or Machine Learning.
"""

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    STATE_PLUS,
    STATE_MINUS,
    STATE_I_PLUS,
    STATE_I_MINUS,
    normalize_state,
    state_inner_product,
    state_fidelity,
    is_valid_state,
)

from quantum_engine.bell_states import (
    STATE_00,
    STATE_01,
    STATE_10,
    STATE_11,
    BELL_PHI_PLUS,
    BELL_PHI_MINUS,
    BELL_PSI_PLUS,
    BELL_PSI_MINUS,
    get_bell_state,
    get_all_bell_states,
    bell_state_fidelity,
)

from quantum_engine.pauli_operations import (
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    apply_pauli,
    apply_x,
    apply_y,
    apply_z,
    apply_identity,
    calculate_state_change,
    evaluate_pauli_disturbances,
)

from quantum_engine.metrics import (
    calculate_measurement_probability,
    calculate_state_disturbance,
    calculate_consistency_score,
    calculate_measurement_distribution,
    calculate_deviation,
)

from quantum_engine.security_state import (
    build_security_parameter_vector,
    extract_security_parameters_from_evidence,
    calculate_quantum_security_state,
    DEFAULT_SECURITY_WEIGHTS,
)

from quantum_engine.measurement_analysis import (
    analyze_projective_measurements,
    simulate_stochastic_measurements,
)

from quantum_engine.forgery_probability import (
    calculate_forgery_probability_estimate,
    DEFAULT_FORGERY_WEIGHTS,
)

from quantum_engine.threat_detector import (
    evaluate_deterministic_threats,
    simulate_quantum_channel,
)

from quantum_engine.risk_engine import (
    calculate_composite_risk_score,
    DEFAULT_RISK_WEIGHTS,
)

__all__ = [
    # States
    "STATE_0",
    "STATE_1",
    "STATE_PLUS",
    "STATE_MINUS",
    "STATE_I_PLUS",
    "STATE_I_MINUS",
    "normalize_state",
    "state_inner_product",
    "state_fidelity",
    "is_valid_state",
    # Bell States
    "STATE_00",
    "STATE_01",
    "STATE_10",
    "STATE_11",
    "BELL_PHI_PLUS",
    "BELL_PHI_MINUS",
    "BELL_PSI_PLUS",
    "BELL_PSI_MINUS",
    "get_bell_state",
    "get_all_bell_states",
    "bell_state_fidelity",
    # Pauli Operations
    "PAULI_I",
    "PAULI_X",
    "PAULI_Y",
    "PAULI_Z",
    "apply_pauli",
    "apply_x",
    "apply_y",
    "apply_z",
    "apply_identity",
    "calculate_state_change",
    "evaluate_pauli_disturbances",
    # Metrics
    "calculate_measurement_probability",
    "calculate_state_disturbance",
    "calculate_consistency_score",
    "calculate_measurement_distribution",
    "calculate_deviation",
    # Security State
    "build_security_parameter_vector",
    "extract_security_parameters_from_evidence",
    "calculate_quantum_security_state",
    "DEFAULT_SECURITY_WEIGHTS",
    # Measurement Analysis
    "analyze_projective_measurements",
    "simulate_stochastic_measurements",
    # Forgery Probability
    "calculate_forgery_probability_estimate",
    "DEFAULT_FORGERY_WEIGHTS",
    # Threat Detector
    "evaluate_deterministic_threats",
    "simulate_quantum_channel",
    # Risk Engine
    "calculate_composite_risk_score",
    "DEFAULT_RISK_WEIGHTS",
]

