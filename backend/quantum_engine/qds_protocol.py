"""
Quantum Digital Signature (QDS) Teleportation-Based Protocol Core.

Package: quantum_engine.qds_protocol
Deterministic mathematical model of multi-qubit teleportation-based QDS:
1. Normalized single-qubit states and conjugate-basis verification.
2. QDS key generation (private states, public verification states, basis sequences).
3. Hash / message bit-string mapping to quantum state sequences.
4. Bell pair generation using existing bell_states.py.
5. Single-qubit teleportation with exact Pauli correction rules (00->I, 01->X, 10->Z, 11->XZ).
6. Multi-qubit teleportation pipeline with fidelity tracking.
7. Projective measurement verification and mismatch thresholding.
8. Forgery simulation (random substitution, bit-flip, phase-flip, intercept-resend).
9. Non-repudiation verification between multiple recipients.

Contains NO AI/ML models. 100% deterministic, reproducible, and verifiable.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import random
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np

from quantum_engine.states import (
    STATE_0,
    STATE_1,
    STATE_PLUS,
    STATE_MINUS,
    STATE_I_PLUS,
    STATE_I_MINUS,
    normalize_state,
    state_fidelity,
    state_inner_product,
    is_valid_state,
    _to_vector
)
from quantum_engine.bell_states import (
    BELL_PHI_PLUS,
    get_bell_state,
    bell_state_fidelity
)
from quantum_engine.pauli_operations import (
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    apply_x,
    apply_y,
    apply_z,
    apply_identity,
    apply_pauli
)


# ==============================================================================
# PROTOCOL CONSTANTS AND ALLOWED STATE SETS
# ==============================================================================

PROTOCOL_VERSION = "QDS-TP-1.0"
DEFAULT_T_VER = 0.10

# Canonical 4 non-orthogonal states spanning conjugate bases Z and X
ALLOWED_QDS_STATES: Dict[str, np.ndarray] = {
    "|0>": STATE_0,
    "|1>": STATE_1,
    "|+>": STATE_PLUS,
    "|->": STATE_MINUS,
}

ALLOWED_STATE_NAMES = list(ALLOWED_QDS_STATES.keys())


# ==============================================================================
# PART 11 — DATACLASSES FOR TYPE SAFETY
# ==============================================================================

@dataclass
class QDSKeyPair:
    """
    Cryptographic Key Pair for Quantum Digital Signatures.
    
    Attributes:
        private_states: Sequence of private quantum states held by the signer.
        basis_sequence: Sequence of bases ('Z' or 'X') corresponding to each state.
        public_states: Sequence of public verification states shared with verifiers.
        metadata: Protocol parameters, key length, seed, and version info.
    """
    private_states: List[np.ndarray]
    basis_sequence: List[str]
    public_states: List[np.ndarray]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_length": len(self.private_states),
            "basis_sequence": self.basis_sequence,
            "metadata": self.metadata,
            "protocol_version": self.metadata.get("protocol_version", PROTOCOL_VERSION),
        }


@dataclass
class QDSSignature:
    """
    Quantum Digital Signature Package for a specific message hash.
    
    Attributes:
        message_hash: Hexadecimal digest of the signed payload.
        signature_states: Sequence of quantum state vectors representing the signature.
        basis_metadata: Basis tags ('Z' or 'X') for each signature qubit.
        protocol_version: Version identifier string.
        num_qubits: Total number of signature qubits.
    """
    message_hash: str
    signature_states: List[np.ndarray]
    basis_metadata: List[str]
    protocol_version: str = PROTOCOL_VERSION
    num_qubits: int = 0

    def __post_init__(self):
        if self.num_qubits == 0:
            self.num_qubits = len(self.signature_states)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_hash": self.message_hash,
            "num_qubits": self.num_qubits,
            "basis_metadata": self.basis_metadata,
            "protocol_version": self.protocol_version,
        }


@dataclass
class TeleportationResult:
    """
    Outcome of multi-qubit quantum teleportation of a QDS signature.
    """
    received_states: List[np.ndarray]
    measurement_bits: List[str]
    pauli_corrections: List[str]
    fidelities: List[float]
    average_fidelity: float
    success: bool

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "num_qubits": len(self.received_states),
            "measurement_bits": self.measurement_bits,
            "pauli_corrections": self.pauli_corrections,
            "fidelities": [round(f, 6) for f in self.fidelities],
            "average_fidelity": round(self.average_fidelity, 6),
            "success": self.success,
        }


@dataclass
class QDSVerificationResult:
    """
    Outcome of projective quantum verification of received QDS signature qubits.
    """
    accepted: bool
    mismatch_rate: float
    threshold: float
    measurements: List[int]
    expected_measurements: List[int]
    total_measurements: int
    mismatches: int
    explanation: str

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "mismatch_rate": round(self.mismatch_rate, 6),
            "threshold": self.threshold,
            "measurements": self.measurements,
            "expected_measurements": self.expected_measurements,
            "total_measurements": self.total_measurements,
            "mismatches": self.mismatches,
            "explanation": self.explanation,
        }


# ==============================================================================
# PART 1 — QUANTUM STATE REPRESENTATION & VALIDATION
# ==============================================================================

def validate_qubit_state(state: Any, tol: float = 1e-6) -> np.ndarray:
    """
    Validates that the input represents a mathematically sound, 2-dimensional
    pure quantum state vector with unit Euclidean norm.
    
    Raises:
        ValueError: If state is None, has invalid shape, zero norm, or non-finite values.
    """
    if state is None:
        raise ValueError("Quantum state vector cannot be None.")

    try:
        vec = np.asarray(state, dtype=np.complex128)
    except (TypeError, ValueError) as err:
        raise ValueError(f"State cannot be converted to complex array: {err}") from err

    if vec.size != 2:
        raise ValueError(f"Qubit state must have exactly 2 dimensions, got shape {vec.shape}.")

    vec = vec.flatten()

    if not np.all(np.isfinite(vec)):
        raise ValueError("Qubit state contains NaN or infinite values.")

    norm = np.linalg.norm(vec)
    if norm < 1e-12:
        raise ValueError("Cannot validate state with zero norm.")

    if abs(norm - 1.0) > tol:
        raise ValueError(f"Quantum state vector is not normalized (norm = {norm:.6f}).")

    return vec


def state_to_tuple(state: Any) -> Tuple[complex, complex]:
    """
    Converts a 2D quantum state vector into an immutable tuple of complex amplitudes.
    """
    vec = validate_qubit_state(state)
    return (complex(vec[0]), complex(vec[1]))


def generate_random_state_from_allowed_set(
    rng: Optional[random.Random] = None,
    allowed_states: Optional[Sequence[str]] = None
) -> Tuple[str, np.ndarray]:
    """
    Selects a deterministic/pseudo-random quantum state from the canonical non-orthogonal set:
    {|0>, |1>, |+>, |->}.
    
    Returns:
        Tuple of (state_name, normalized_numpy_array)
    """
    r = rng if rng is not None else random.Random()
    pool = list(allowed_states) if allowed_states else ALLOWED_STATE_NAMES
    chosen_name = r.choice(pool)
    return chosen_name, np.copy(ALLOWED_QDS_STATES[chosen_name])


# ==============================================================================
# PART 2 — QDS KEY GENERATION
# ==============================================================================

def generate_qds_key_pair(length: int, seed: Optional[int] = None) -> QDSKeyPair:
    """
    Generates a Quantum Digital Signature Key Pair of specified qubit length.
    
    For each position i in 0..length-1:
        1. Selects basis B_i in {'Z', 'X'}.
        2. Selects secret reference bit k_i in {0, 1}.
        3. Prepares private state |psi_i> corresponding to (B_i, k_i):
           - ('Z', 0) -> |0>
           - ('Z', 1) -> |1>
           - ('X', 0) -> |+>
           - ('X', 1) -> |->
        4. Prepares public verification state identical to |psi_i>.
        
    Args:
        length: Number of qubits in the key (must be >= 1).
        seed: Optional integer seed for reproducible deterministic generation.
        
    Returns:
        QDSKeyPair containing private_states, basis_sequence, public_states, and metadata.
    """
    if not isinstance(length, int) or length < 1:
        raise ValueError(f"Key length must be a positive integer >= 1, got {length}.")

    rng = random.Random(seed)

    private_states: List[np.ndarray] = []
    basis_sequence: List[str] = []
    public_states: List[np.ndarray] = []

    for _ in range(length):
        basis = rng.choice(["Z", "X"])
        bit_val = rng.choice([0, 1])

        if basis == "Z":
            state = STATE_0 if bit_val == 0 else STATE_1
        else: # basis == "X"
            state = STATE_PLUS if bit_val == 0 else STATE_MINUS

        state_copy = np.copy(state)
        private_states.append(state_copy)
        basis_sequence.append(basis)
        public_states.append(np.copy(state_copy))

    metadata = {
        "key_length": length,
        "seed": seed,
        "protocol_version": PROTOCOL_VERSION,
        "bases_distribution": {
            "Z": basis_sequence.count("Z"),
            "X": basis_sequence.count("X")
        },
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    return QDSKeyPair(
        private_states=private_states,
        basis_sequence=basis_sequence,
        public_states=public_states,
        metadata=metadata
    )


# ==============================================================================
# PART 3 — HASH / MESSAGE TO QDS SIGNATURE
# ==============================================================================

def hex_to_bit_sequence(message_hash: str) -> str:
    """
    Converts a hexadecimal string into an exact deterministic bit sequence.
    Each hex digit is converted to 4 binary bits (e.g. 'a' -> '1010').
    
    Raises:
        ValueError: If message_hash is empty or contains non-hex characters.
    """
    if not isinstance(message_hash, str) or len(message_hash.strip()) == 0:
        raise ValueError("Message hash must be a non-empty string.")

    clean_hex = message_hash.strip().lower()

    # Validate hex format
    for char in clean_hex:
        if char not in "0123456789abcdef":
            raise ValueError(f"Invalid hexadecimal character '{char}' in message hash.")

    return "".join(f"{int(c, 16):04b}" for c in clean_hex)


def sign_hash_qds(message_hash: str, private_key: QDSKeyPair) -> QDSSignature:
    """
    Signs a message hash using a QDS private key.
    
    Converts the message hash to a binary bit sequence M = (m_0, m_1, ...).
    For each bit m_i:
        - If m_i == 0: signature qubit is the private reference state |psi_i>.
        - If m_i == 1: signature qubit is flipped in its conjugate basis:
            - If basis is 'Z': apply Pauli X (|0> <-> |1>)
            - If basis is 'X': apply Pauli Z (|+> <-> |->)
            
    Does NOT use RSA or SHA. Treats the supplied hash as an external payload.
    
    Args:
        message_hash: Hexadecimal digest string.
        private_key: Signer's QDSKeyPair.
        
    Returns:
        QDSSignature object containing the quantum state sequence.
    """
    bit_sequence = hex_to_bit_sequence(message_hash)
    req_qubits = len(bit_sequence)

    if req_qubits > len(private_key.private_states):
        raise ValueError(
            f"Private key length ({len(private_key.private_states)}) is shorter "
            f"than required message hash bits ({req_qubits})."
        )

    signature_states: List[np.ndarray] = []
    basis_metadata: List[str] = []

    for i, bit_char in enumerate(bit_sequence):
        m_i = int(bit_char)
        basis = private_key.basis_sequence[i]
        base_state = private_key.private_states[i]

        if m_i == 0:
            sig_state = np.copy(base_state)
        else:
            # Flip according to the basis
            if basis == "Z":
                sig_state = apply_x(base_state)
            else: # basis == "X"
                sig_state = apply_z(base_state)

        signature_states.append(sig_state)
        basis_metadata.append(basis)

    return QDSSignature(
        message_hash=message_hash.strip().lower(),
        signature_states=signature_states,
        basis_metadata=basis_metadata,
        protocol_version=PROTOCOL_VERSION,
        num_qubits=req_qubits
    )


# ==============================================================================
# PART 4 — BELL PAIR DISTRIBUTION
# ==============================================================================

def create_bell_pairs(count: int, bell_state_name: str = "phi_plus") -> List[np.ndarray]:
    """
    Constructs a sequence of normalized two-qubit maximally entangled Bell states
    by reusing the canonical definitions from quantum_engine.bell_states.
    
    Default Bell State: |Phi+> = (|00> + |11>) / sqrt(2)
    
    Args:
        count: Number of Bell pairs to generate (>= 1).
        bell_state_name: Name of Bell state ('phi_plus', 'phi_minus', etc.)
        
    Returns:
        List of count 4D complex128 Bell state vectors.
    """
    if not isinstance(count, int) or count < 1:
        raise ValueError(f"Bell pair count must be an integer >= 1, got {count}.")

    base_bell = get_bell_state(bell_state_name)
    return [np.copy(base_bell) for _ in range(count)]


# ==============================================================================
# PART 5 — SINGLE-QUBIT TELEPORTATION
# ==============================================================================

def teleport_qubit(
    input_state: Any,
    bell_pair: Optional[Any] = None,
    measurement_bits: Optional[str] = None,
    seed: Optional[int] = None
) -> Tuple[np.ndarray, str, str]:
    """
    Executes a mathematically sound quantum teleportation protocol primitive.
    
    Protocol Flow:
    1. Alice holds input qubit |psi> = a|0> + b|1>.
    2. Alice and Bob share an entangled Bell pair |Phi+>_23 = (|00> + |11>)/sqrt(2).
    3. Alice performs joint Bell-basis measurement on qubits (1, 2).
       Outcomes occur with equal probability (1/4):
           - '00' (|Phi+> measurement outcome)
           - '01' (|Psi+> measurement outcome)
           - '10' (|Phi-> measurement outcome)
           - '11' (|Psi-> measurement outcome)
    4. Alice transmits classical measurement bits (m1, m2) to Bob.
    5. Bob applies corresponding Pauli correction operator:
           - 00 -> Identity (I)
           - 01 -> Pauli X  (Bit-flip)
           - 10 -> Pauli Z  (Phase-flip)
           - 11 -> Pauli XZ (Compound Bit-and-Phase flip)
    6. Bob reconstructs exact normalized replica of |psi>.
    
    Args:
        input_state: Alice's 2D input state vector.
        bell_pair: Optional shared 4D Bell state (defaults to |Phi+>).
        measurement_bits: Optional preset measurement outcome ('00', '01', '10', '11').
        seed: Optional seed for stochastic measurement outcome selection.
        
    Returns:
        Tuple of (reconstructed_state, measurement_bits, pauli_correction_name).
    """
    psi = validate_qubit_state(input_state)

    if bell_pair is not None:
        bell_vec = _to_vector(bell_pair)
        if bell_vec.shape != (4,):
            raise ValueError(f"Bell pair must have 4 dimensions, got shape {bell_vec.shape}.")
        if abs(np.linalg.norm(bell_vec) - 1.0) > 1e-5:
            raise ValueError("Bell pair state is not normalized.")

    # Select or validate measurement bits
    valid_outcomes = ["00", "01", "10", "11"]
    if measurement_bits is not None:
        clean_bits = str(measurement_bits).strip()
        if clean_bits not in valid_outcomes:
            raise ValueError(f"Invalid measurement bits '{measurement_bits}'. Must be one of {valid_outcomes}.")
        bits = clean_bits
    else:
        rng = random.Random(seed)
        bits = rng.choice(valid_outcomes)

    # Bob's qubit state after Alice's measurement collapses the entangled pair:
    # 00: Bob receives |psi>
    # 01: Bob receives X |psi>
    # 10: Bob receives Z |psi>
    # 11: Bob receives XZ |psi>
    if bits == "00":
        pauli_op = "I"
        # Bob applies I: I |psi> = |psi>
        reconstructed = apply_identity(psi)
    elif bits == "01":
        pauli_op = "X"
        # Bob applies X: X (X|psi>) = |psi>
        collapsed = apply_x(psi)
        reconstructed = apply_x(collapsed)
    elif bits == "10":
        pauli_op = "Z"
        # Bob applies Z: Z (Z|psi>) = |psi>
        collapsed = apply_z(psi)
        reconstructed = apply_z(collapsed)
    else: # bits == "11"
        pauli_op = "XZ"
        # Bob applies X then Z: Z X (X Z |psi>) = Z (X^2) Z |psi> = Z^2 |psi> = |psi>
        collapsed = apply_z(apply_x(psi))
        reconstructed = apply_x(apply_z(collapsed))

    # Guarantee unit normalization
    reconstructed = normalize_state(reconstructed)

    return reconstructed, bits, pauli_op


# ==============================================================================
# PART 6 — MULTI-QUBIT TELEPORTATION
# ==============================================================================

def teleport_signature(
    signature_states: Sequence[Any],
    seed: Optional[int] = None
) -> TeleportationResult:
    """
    Teleports an entire sequence of QDS signature qubits from Alice to Bob.
    
    For every qubit:
        1. Distributes a shared |Phi+> Bell pair.
        2. Teleports using simulated Bell-basis measurement.
        3. Applies Bob's Pauli correction.
        4. Calculates individual fidelity between original and reconstructed state.
        
    Args:
        signature_states: Sequence of 2D normalized qubit state vectors.
        seed: Optional seed for deterministic multi-qubit simulation.
        
    Returns:
        TeleportationResult containing received states, measurement bits,
        corrections, individual fidelities, and overall average fidelity.
    """
    if not signature_states or len(signature_states) == 0:
        raise ValueError("Cannot teleport empty signature state sequence.")

    rng = random.Random(seed)

    received_states: List[np.ndarray] = []
    measurement_bits: List[str] = []
    pauli_corrections: List[str] = []
    fidelities: List[float] = []

    for state in signature_states:
        sub_seed = rng.randint(0, 10_000_000) if seed is not None else None
        rec_state, bits, pauli_op = teleport_qubit(state, seed=sub_seed)

        fid = state_fidelity(state, rec_state)

        received_states.append(rec_state)
        measurement_bits.append(bits)
        pauli_corrections.append(pauli_op)
        fidelities.append(fid)

    avg_fidelity = sum(fidelities) / len(fidelities)
    success = bool(avg_fidelity >= 0.999)

    return TeleportationResult(
        received_states=received_states,
        measurement_bits=measurement_bits,
        pauli_corrections=pauli_corrections,
        fidelities=fidelities,
        average_fidelity=avg_fidelity,
        success=success
    )


# ==============================================================================
# PART 7 — PROJECTIVE VERIFICATION
# ==============================================================================

def verify_signature_qds(
    signature: QDSSignature,
    received_states: Sequence[Any],
    public_key: QDSKeyPair,
    threshold: float = DEFAULT_T_VER,
    seed: Optional[int] = None
) -> QDSVerificationResult:
    """
    Performs projective quantum verification on received signature qubits.
    
    Verification Flow:
    1. Converts message hash into bit sequence M = (m_0, m_1, ...).
    2. For each qubit i:
       - Retrieves verification basis B_i in {'Z', 'X'}.
       - Computes expected public state:
           - If m_i == 0: base public state public_states[i]
           - If m_i == 1: flipped public state in basis B_i (X for Z, Z for X)
       - Evaluates projective measurement fidelity F_i = |<psi_exp|phi_rec>|^2.
       - Identifies matches/mismatches based on projective projection.
    3. Computes mismatch rate epsilon = mismatches / total_measurements.
    4. Verdict Decision:
           epsilon <= threshold -> ACCEPT (Authentic signature)
           epsilon > threshold  -> REJECT (Tampered or Forged signature)
           
    Args:
        signature: Signed QDSSignature package.
        received_states: Sequence of qubits received by the verifier.
        public_key: Signer's QDSKeyPair.
        threshold: Verification threshold T_VER (default 0.10).
        seed: Optional seed for stochastic measurement projection.
        
    Returns:
        QDSVerificationResult with verdict, mismatch rate, and itemized metrics.
    """
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"Verification threshold must be in [0.0, 1.0], got {threshold}.")

    if len(signature.signature_states) != len(received_states):
        raise ValueError(
            f"Length mismatch: signature has {len(signature.signature_states)} qubits, "
            f"but received {len(received_states)} states."
        )

    if len(received_states) > len(public_key.public_states):
        raise ValueError(
            f"Public key length ({len(public_key.public_states)}) is insufficient "
            f"for received states ({len(received_states)})."
        )

    bit_sequence = hex_to_bit_sequence(signature.message_hash)
    total_qubits = len(received_states)

    measurements: List[int] = []
    expected_measurements: List[int] = []
    mismatches = 0

    rng = random.Random(seed) if seed is not None else None

    for i in range(total_qubits):
        m_i = int(bit_sequence[i])
        basis = public_key.basis_sequence[i]
        rec_state = validate_qubit_state(received_states[i])

        # Compute expected quantum state for bit m_i
        base_pub_state = public_key.public_states[i]
        if m_i == 0:
            expected_state = base_pub_state
        else:
            expected_state = apply_x(base_pub_state) if basis == "Z" else apply_z(base_pub_state)

        # Expected measurement outcome (0 if base state, 1 if flipped state)
        exp_outcome = m_i
        expected_measurements.append(exp_outcome)

        # Projective measurement probability onto expected state
        prob_match = state_fidelity(expected_state, rec_state)

        # In stochastic mode (seed supplied): sample outcome according to Born rule
        # In deterministic mode (seed=None): strict threshold check on fidelity
        if rng is not None:
            is_match = (rng.random() < prob_match)
            obs_outcome = exp_outcome if is_match else (1 - exp_outcome)
        else:
            # Deterministic fidelity threshold: orthogonal states (F < 0.5) trigger mismatch
            is_match = (prob_match >= 0.85)
            obs_outcome = exp_outcome if is_match else (1 - exp_outcome)

        measurements.append(obs_outcome)

        if not is_match:
            mismatches += 1

    mismatch_rate = mismatches / total_qubits if total_qubits > 0 else 0.0
    accepted = bool(mismatch_rate <= threshold)

    explanation = (
        f"QDS Verification {'ACCEPTED' if accepted else 'REJECTED'}: "
        f"mismatch rate epsilon={mismatch_rate:.4f} "
        f"({'<=' if accepted else '>'} threshold T_VER={threshold:.2f}). "
        f"Total qubits: {total_qubits}, Mismatches: {mismatches}."
    )

    return QDSVerificationResult(
        accepted=accepted,
        mismatch_rate=mismatch_rate,
        threshold=threshold,
        measurements=measurements,
        expected_measurements=expected_measurements,
        total_measurements=total_qubits,
        mismatches=mismatches,
        explanation=explanation
    )


# ==============================================================================
# PART 8 — FORGERY SIMULATION
# ==============================================================================

def forge_qds_signature(
    signature: QDSSignature,
    attack_type: str = "random_state_substitution",
    seed: Optional[int] = None
) -> QDSSignature:
    """
    Simulates attacks on a QDS signature package.
    
    Supported Attack Types:
        - 'random_state_substitution': Replaces each signature state with a random state.
        - 'bit_flip': Applies Pauli X to all signature qubits.
        - 'phase_flip': Applies Pauli Z to all signature qubits.
        - 'intercept_resend': Projective computational basis collapse.
        
    IMPORTANT:
        Does NOT modify the original signature object in-place.
        Returns a newly created forged QDSSignature.
        
    Raises:
        ValueError: If attack_type is unsupported.
    """
    clean_attack = attack_type.strip().lower()
    supported = ["random_state_substitution", "bit_flip", "phase_flip", "intercept_resend"]
    if clean_attack not in supported:
        raise ValueError(f"Unsupported attack type '{attack_type}'. Must be one of {supported}.")

    rng = random.Random(seed)
    forged_states: List[np.ndarray] = []

    for state in signature.signature_states:
        if clean_attack == "random_state_substitution":
            _, r_state = generate_random_state_from_allowed_set(rng=rng)
            forged_states.append(r_state)
        elif clean_attack == "bit_flip":
            forged_states.append(apply_x(state))
        elif clean_attack == "phase_flip":
            forged_states.append(apply_z(state))
        elif clean_attack == "intercept_resend":
            # Project onto |0> or |1>
            p0 = abs(state[0])**2
            collapsed = STATE_0 if rng.random() < p0 else STATE_1
            forged_states.append(np.copy(collapsed))

    return QDSSignature(
        message_hash=signature.message_hash,
        signature_states=forged_states,
        basis_metadata=list(signature.basis_metadata),
        protocol_version=f"{PROTOCOL_VERSION}-FORGED-{clean_attack.upper()}",
        num_qubits=signature.num_qubits
    )


# ==============================================================================
# PART 9 — NON-REPUDIATION PREPARATION
# ==============================================================================

def verify_non_repudiation_qds(
    bob_measurements: Sequence[Any],
    charlie_measurements: Sequence[Any],
    threshold: float = DEFAULT_T_VER
) -> Dict[str, Any]:
    """
    Verifies non-repudiation between two independent recipients (Bob and Charlie).
    
    In multi-recipient QDS protocols, Bob and Charlie compare verification outcomes
    to ensure Alice has not signed different quantum states to different parties.
    
    Args:
        bob_measurements: Sequence of Bob's measurement outcomes.
        charlie_measurements: Sequence of Charlie's measurement outcomes.
        threshold: Permissible mismatch threshold (default 0.10).
        
    Returns:
        Dict containing consistent flag, mismatch rate, and diagnostic details.
    """
    if len(bob_measurements) == 0 or len(charlie_measurements) == 0:
        raise ValueError("Measurement sequences cannot be empty.")

    if len(bob_measurements) != len(charlie_measurements):
        raise ValueError(
            f"Measurement length mismatch: Bob has {len(bob_measurements)}, "
            f"Charlie has {len(charlie_measurements)}."
        )

    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"Threshold must be in [0.0, 1.0], got {threshold}.")

    total = len(bob_measurements)
    mismatches = sum(1 for b, c in zip(bob_measurements, charlie_measurements) if b != c)
    mismatch_rate = mismatches / total

    consistent = bool(mismatch_rate <= threshold)

    return {
        "consistent": consistent,
        "mismatch_rate": round(mismatch_rate, 6),
        "threshold": threshold,
        "total_compared": total,
        "mismatches": mismatches,
        "explanation": (
            f"Non-repudiation {'VERIFIED' if consistent else 'REPUDIATION_SUSPECTED'}: "
            f"cross-recipient mismatch rate is {mismatch_rate:.4f} "
            f"({'<=' if consistent else '>'} threshold {threshold:.2f})."
        )
    }
