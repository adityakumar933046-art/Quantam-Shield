"""
Centralized Configuration and Thresholds for Quantum Digital Signatures (QDS).

Module: quantum_engine.thresholds
Provides standard mathematical and operational thresholds for:
1. QDS projective measurement verification
2. Non-repudiation cross-verifier agreement
3. Quantum channel disturbance and eavesdropping detection
4. Chi-square statistical goodness-of-fit testing

Scientific Basis:
In quantum digital signature protocols, noise and finite sampling induce small statistical
deviations. Configurable thresholds distinguish expected channel fluctuations from active
adversarial attacks (forgery, impersonation, intercept-resend, Pauli manipulation).
"""

from typing import Dict, Any


# ==============================================================================
# 1. CORE QDS PROTOCOL THRESHOLDS
# ==============================================================================

# Maximum acceptable mismatch rate (epsilon = mismatches / total_measurements)
# in projective measurement verification. Signatures with epsilon <= 0.10 (10%)
# are accepted as authentic; epsilon > 0.10 are rejected as tampered or forged.
QDS_VERIFICATION_THRESHOLD: float = 0.10

# Maximum allowable discrepancy rate between independent verifiers (e.g., Bob vs Charlie).
# If the cross-receiver mismatch rate exceeds 0.05 (5%), repudiation or asymmetric tampering
# is flagged.
QDS_REPUDIATION_THRESHOLD: float = 0.05

# Maximum allowable quantum state disturbance (D = 1.0 - Fidelity) on transmission channels.
# Channel disturbance D >= 0.20 (20%) indicates significant eavesdropping or channel degradation,
# triggering QUANTUM_CHANNEL_MANIPULATION alerts.
QDS_CHANNEL_DISTURBANCE_THRESHOLD: float = 0.20

# Minimum average state fidelity for nominal quantum teleportation acceptance.
# Derived directly as (1.0 - QDS_VERIFICATION_THRESHOLD) = 0.90.
QDS_MIN_ACCEPTABLE_FIDELITY: float = 0.90


# ==============================================================================
# 2. STATISTICAL VALIDITY THRESHOLDS
# ==============================================================================

# Minimum total observation count required for asymptotic validity of the Chi-Square test.
# Samples below this threshold are marked "insufficient_sample_size" to prevent misleading conclusions.
CHI_SQUARE_MIN_SAMPLE_SIZE: int = 20

# Cochran criterion: minimum expected frequency per bin for valid asymptotic Chi-Square testing.
CHI_SQUARE_MIN_EXPECTED_COUNT: float = 5.0

# Total Variation Distance (TVD) anomaly threshold.
# Empirical distributions diverging by TVD >= 0.15 from theoretical expectations indicate channel bias.
QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD: float = 0.15


# ==============================================================================
# 3. HELPER FUNCTIONS
# ==============================================================================

def get_qds_thresholds() -> Dict[str, float]:
    """
    Returns a dictionary of all active QDS security and statistical thresholds.
    """
    return {
        "verification_threshold": QDS_VERIFICATION_THRESHOLD,
        "repudiation_threshold": QDS_REPUDIATION_THRESHOLD,
        "channel_disturbance_threshold": QDS_CHANNEL_DISTURBANCE_THRESHOLD,
        "min_acceptable_fidelity": QDS_MIN_ACCEPTABLE_FIDELITY,
        "chi_square_min_sample_size": float(CHI_SQUARE_MIN_SAMPLE_SIZE),
        "chi_square_min_expected_count": CHI_SQUARE_MIN_EXPECTED_COUNT,
        "distribution_distance_anomaly_threshold": QDS_DISTRIBUTION_DISTANCE_ANOMALY_THRESHOLD,
    }
