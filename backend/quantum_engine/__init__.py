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

from quantum_engine.thresholds import (
    QDS_VERIFICATION_THRESHOLD,
    QDS_REPUDIATION_THRESHOLD,
    QDS_CHANNEL_DISTURBANCE_THRESHOLD,
    QDS_MIN_ACCEPTABLE_FIDELITY,
    CHI_SQUARE_MIN_SAMPLE_SIZE,
    CHI_SQUARE_MIN_EXPECTED_COUNT,
    QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD,
    get_qds_thresholds,
)

from quantum_engine.measurement_analysis import (
    analyze_projective_measurements,
    simulate_stochastic_measurements,
    calculate_chi_square,
    calculate_total_variation_distance,
    analyze_qds_measurements,
)

from quantum_engine.forgery_probability import (
    calculate_forgery_probability_estimate,
    calculate_qds_forgery_probability_estimate,
    DEFAULT_FORGERY_WEIGHTS,
)

from quantum_engine.threat_detector import (
    evaluate_deterministic_threats,
    simulate_quantum_channel,
    build_qds_threat_evidence,
    evaluate_qds_threats,
    analyze_quantum_channel_attack,
)

from quantum_engine.risk_engine import (
    calculate_composite_risk_score,
    DEFAULT_RISK_WEIGHTS,
)

from quantum_engine.qds_protocol import (
    QDSKeyPair,
    QDSSignature,
    TeleportationResult,
    QDSVerificationResult,
    validate_qubit_state,
    state_to_tuple,
    generate_random_state_from_allowed_set,
    generate_qds_key_pair,
    hex_to_bit_sequence,
    sign_hash_qds,
    create_bell_pairs,
    teleport_qubit,
    teleport_signature,
    verify_signature_qds,
    forge_qds_signature,
    verify_non_repudiation_qds,
    ALLOWED_QDS_STATES,
    PROTOCOL_VERSION,
    DEFAULT_T_VER,
)

from quantum_engine.qds_attack_pipeline import (
    run_qds_attack_simulation,
    run_all_qds_attack_scenarios,
    QDSAttackSimulationResult,
    SUPPORTED_QDS_ATTACKS,
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
    "calculate_chi_square",
    "calculate_total_variation_distance",
    "analyze_qds_measurements",
    # Forgery Probability
    "calculate_forgery_probability_estimate",
    "calculate_qds_forgery_probability_estimate",
    "DEFAULT_FORGERY_WEIGHTS",
    # Threat Detector
    "evaluate_deterministic_threats",
    "simulate_quantum_channel",
    "build_qds_threat_evidence",
    "evaluate_qds_threats",
    "analyze_quantum_channel_attack",
    # Risk Engine
    "calculate_composite_risk_score",
    "DEFAULT_RISK_WEIGHTS",
    # Thresholds
    "QDS_VERIFICATION_THRESHOLD",
    "QDS_REPUDIATION_THRESHOLD",
    "QDS_CHANNEL_DISTURBANCE_THRESHOLD",
    "QDS_MIN_ACCEPTABLE_FIDELITY",
    "CHI_SQUARE_MIN_SAMPLE_SIZE",
    "CHI_SQUARE_MIN_EXPECTED_COUNT",
    "QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD",
    "get_qds_thresholds",
    # QDS Protocol Core
    "QDSKeyPair",
    "QDSSignature",
    "TeleportationResult",
    "QDSVerificationResult",
    "validate_qubit_state",
    "state_to_tuple",
    "generate_random_state_from_allowed_set",
    "generate_qds_key_pair",
    "hex_to_bit_sequence",
    "sign_hash_qds",
    "create_bell_pairs",
    "teleport_qubit",
    "teleport_signature",
    "verify_signature_qds",
    "forge_qds_signature",
    "verify_non_repudiation_qds",
    "ALLOWED_QDS_STATES",
    "PROTOCOL_VERSION",
    "DEFAULT_T_VER",
    # QDS Attack Pipeline
    "run_qds_attack_simulation",
    "run_all_qds_attack_scenarios",
    "QDSAttackSimulationResult",
    "SUPPORTED_QDS_ATTACKS",
]

