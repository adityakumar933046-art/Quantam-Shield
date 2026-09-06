from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.core.db import Base

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="DIGITAL_SIGNATURE_USER")
    status = Column(String(20), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    keypairs = relationship("KeyPair", back_populates="user", cascade="all, delete-orphan")
    verification_activities = relationship("VerificationActivity", back_populates="user")


class KeyPair(Base):
    """
    Cryptographic KeyPair model storing public keys and encrypted-at-rest private keys.
    Private keys are NEVER serialized or returned in API responses.
    """
    __tablename__ = "key_pairs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False, index=True)
    algorithm = Column(String(50), default="RSA-2048")
    public_key = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False) # AES-GCM encrypted PEM, backend-only
    key_fingerprint = Column(String(128), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(20), default="ACTIVE")

    user = relationship("User", back_populates="keypairs")


class SignedDocument(Base):
    __tablename__ = "documents"

    document_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    signature_id = Column(String(100), unique=True, index=True, nullable=True) # e.g. QSHIELD-SIGN-XXXXXXXX
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    original_file_path = Column(String(500), nullable=False)
    file_path = Column(String(500), nullable=True)
    file_type = Column(String(50), default="PDF")
    signed_filename = Column(String(255), nullable=True)
    signed_file_path = Column(String(500), nullable=True)
    document_hash = Column(String(128), nullable=False)
    hash_algorithm = Column(String(50), default="SHA-256")
    content_type = Column(String(50), default="PDF")
    raw_text_content = Column(Text, nullable=True)
    canonical_hash = Column(String(128), nullable=True)
    signature_type = Column(String(50), default="EMBEDDED_PKCS7")
    signature_algorithm = Column(String(50), default="RSA-SHA256")
    signature_value = Column(Text, nullable=True)
    public_key_fingerprint = Column(String(128), nullable=True)
    key_reference = Column(String(100), nullable=True)
    nonce = Column(String(100), nullable=True)
    message_id = Column(String(100), nullable=True)
    file_size = Column(Integer, default=0)
    status = Column(String(50), default="UPLOADED")
    signed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    signature = relationship("DigitalSignature", back_populates="document", uselist=False, cascade="all, delete-orphan")


class DigitalSignature(Base):
    __tablename__ = "digital_signatures"

    signature_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    document_id = Column(Integer, ForeignKey("documents.document_id"), nullable=False, unique=True)
    signature_algorithm = Column(String(50), default="RSA-SHA256")
    hash_algorithm = Column(String(50), default="SHA-256")
    certificate_subject = Column(String(255), nullable=False)
    certificate_issuer = Column(String(255), nullable=False)
    certificate_serial_number = Column(String(100), nullable=False)
    certificate_fingerprint = Column(String(128), nullable=False)
    signature_fingerprint = Column(String(128), nullable=False)
    signing_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verification_status = Column(String(50), default="VALID")

    document = relationship("SignedDocument", back_populates="signature")


class AnalyzedDocument(Base):
    __tablename__ = "analyzed_documents"

    analysis_document_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_id = Column(String(100), unique=True, index=True, nullable=True) # e.g. QSHIELD-ANALYSIS-XXXXXXXX
    signature_id = Column(String(100), nullable=True) # Linked QSHIELD-SIGN-XXXXXXXX
    analyst_user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    original_file_name = Column(String(255), nullable=False)
    stored_file_name = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    uploaded_file = Column(String(500), nullable=True)
    file_type = Column(String(50), default="PDF")
    content_type = Column(String(50), default="PDF")
    raw_text_content = Column(Text, nullable=True)
    canonical_hash = Column(String(128), nullable=True)
    signature_type = Column(String(50), default="EMBEDDED_PKCS7")
    file_size = Column(Integer, default=0)
    document_hash = Column(String(128), nullable=False)
    signature_present = Column(Boolean, default=False)
    signature_status = Column(String(50), nullable=False)
    signature_verified = Column(Boolean, default=False)
    integrity_verified = Column(Boolean, default=False)
    certificate_status = Column(String(50), default="UNKNOWN")
    public_key_status = Column(String(50), default="UNKNOWN")
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    final_decision = Column(String(50), default="REQUIRES_CAUTION")
    analysis_summary = Column(Text, nullable=True)
    upload_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    analysed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    extracted_metadata = relationship("ExtractedSignatureMetadata", back_populates="analyzed_document", uselist=False, cascade="all, delete-orphan")
    verifications = relationship("SignatureVerification", back_populates="analyzed_document", cascade="all, delete-orphan")
    quantum_analysis = relationship("QuantumInspiredAnalysis", back_populates="analyzed_document", uselist=False, cascade="all, delete-orphan")
    threat_incidents = relationship("ThreatIncident", back_populates="analyzed_document", cascade="all, delete-orphan")
    certificate_analysis = relationship("CertificateSecurityAnalysis", back_populates="analyzed_document", uselist=False, cascade="all, delete-orphan")
    security_report = relationship("SecurityReport", back_populates="analyzed_document", uselist=False, cascade="all, delete-orphan")
    verification_activities = relationship("VerificationActivity", back_populates="analyzed_document")

    @property
    def file_name(self) -> str:
        return self.original_file_name


class ExtractedSignatureMetadata(Base):
    __tablename__ = "extracted_signature_metadata"

    signature_analysis_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=False, unique=True)
    signature_detected = Column(Boolean, default=False)
    signature_status = Column(String(50), nullable=False)
    signature_algorithm = Column(String(50), default="Not Available")
    hash_algorithm = Column(String(50), default="Not Available")
    signature_fingerprint = Column(String(128), default="Not Available")
    field_name = Column(String(100), default="Not Available")
    signing_time = Column(DateTime, nullable=True)
    certificate_subject = Column(String(500), default="Not Available")
    certificate_issuer = Column(String(500), default="Not Available")
    certificate_serial_number = Column(String(100), default="Not Available")
    validity_start = Column(DateTime, nullable=True)
    validity_end = Column(DateTime, nullable=True)
    certificate_fingerprint = Column(String(128), default="Not Available")
    public_key_algorithm = Column(String(50), default="Not Available")
    public_key_size = Column(Integer, default=0)
    signer_name = Column(String(150), default="Not Available")
    signer_organization = Column(String(200), default="Not Available")

    analyzed_document = relationship("AnalyzedDocument", back_populates="extracted_metadata")


class SignatureVerification(Base):
    __tablename__ = "signature_verifications"

    verification_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=False)
    signature_identifier = Column(String(100), default="Signature1")
    signature_index = Column(Integer, default=0)
    verification_status = Column(String(50), nullable=False)
    integrity_status = Column(String(50), nullable=False)
    signature_algorithm = Column(String(50), default="RSA-SHA256")
    hash_algorithm = Column(String(50), default="SHA-256")
    certificate_time_status = Column(String(50), default="UNKNOWN")
    verification_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verification_details = Column(Text, nullable=True)
    error_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyzed_document = relationship("AnalyzedDocument", back_populates="verifications")


class QuantumInspiredAnalysis(Base):
    __tablename__ = "quantum_inspired_analyses"

    quantum_analysis_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=False, unique=True)
    security_state_vector = Column(Text, nullable=False) # JSON string representation
    secure_consistency_score = Column(Float, default=0.0)
    disturbance_score = Column(Float, default=0.0)
    pauli_x_score = Column(Float, default=0.0)
    pauli_y_score = Column(Float, default=0.0)
    pauli_z_score = Column(Float, default=0.0)
    secure_measurement_score = Column(Float, default=0.0)
    suspicious_measurement_score = Column(Float, default=0.0)
    high_risk_measurement_score = Column(Float, default=0.0)
    forgery_risk_score = Column(Float, default=0.0)
    analysis_confidence_score = Column(Float, default=0.0)
    confidence_level = Column(String(20), default="LOW")
    final_classification = Column(String(50), nullable=False)
    analysis_version = Column(String(20), default="QIA-1.0")
    state_consistency = Column(Float, default=0.0)
    state_disturbance = Column(Float, default=0.0)
    measurement_secure_probability = Column(Float, default=0.0)
    measurement_threat_probability = Column(Float, default=0.0)
    pauli_x_disturbance = Column(Float, default=0.0)
    pauli_y_disturbance = Column(Float, default=0.0)
    pauli_z_disturbance = Column(Float, default=0.0)
    combined_pauli_disturbance = Column(Float, default=0.0)
    forgery_risk_estimate = Column(Float, default=0.0)
    quantum_analysis_version = Column(String(20), default="QIA-2.0")
    explanation_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyzed_document = relationship("AnalyzedDocument", back_populates="quantum_analysis")


class ThreatIncident(Base):
    __tablename__ = "threat_incidents"

    incident_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=True)
    threat_category = Column(String(50), nullable=False)
    threat_type = Column(String(50), nullable=True) # Standardized threat type
    severity = Column(String(20), nullable=False)
    threat_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    threat_status = Column(String(30), default="OPEN")
    description = Column(Text, nullable=False)
    evidence_data = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    analyzed_document = relationship("AnalyzedDocument", back_populates="threat_incidents")

    @property
    def created_at(self):
        return self.detected_at

    @property
    def evidence_json(self):
        return self.evidence_data


# Backward compatibility alias
SecurityIncident = ThreatIncident


class VerificationActivity(Base):
    """
    Verification Activity model tracking all upload, verification, and failure events.
    Required for deterministic replay detection and history analysis.
    """
    __tablename__ = "verification_activities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=True)
    document_hash = Column(String(128), index=True, nullable=False)
    signature_fingerprint = Column(String(128), index=True, nullable=True)
    action = Column(String(50), nullable=False) # UPLOAD, VERIFY, FAILED_VERIFY, REPLAY_SUSPECT, UNAUTHORIZED_ATTEMPT
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    result = Column(String(50), nullable=True) # VALID, INVALID, SUSPICIOUS, TAMPERED, UNKNOWN
    source_identifier = Column(String(100), default="127.0.0.1")
    metadata_json = Column(Text, nullable=True)

    user = relationship("User", back_populates="verification_activities")
    analyzed_document = relationship("AnalyzedDocument", back_populates="verification_activities")


class CertificateSecurityAnalysis(Base):
    __tablename__ = "certificate_security_analyses"

    certificate_analysis_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=False, unique=True)
    certificate_fingerprint = Column(String(128), default="Not Available")
    structure_status = Column(String(50), default="STRUCTURALLY_VALID")
    time_validity_status = Column(String(50), default="UNKNOWN")
    trust_status = Column(String(50), default="UNTRUSTED")
    chain_status = Column(String(50), default="UNKNOWN")
    revocation_status = Column(String(50), default="NOT_AVAILABLE")
    ocsp_status = Column(String(50), default="NOT_CONFIGURED")
    crl_status = Column(String(50), default="NOT_CONFIGURED")
    algorithm_security_status = Column(String(50), default="SECURE_PARAMETERS")
    certificate_security_score = Column(Float, default=0.0)
    analysis_confidence = Column(Float, default=0.0)
    details = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyzed_document = relationship("AnalyzedDocument", back_populates="certificate_analysis")


class SecurityReport(Base):
    __tablename__ = "security_reports"

    report_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    report_reference = Column(String(100), unique=True, index=True, nullable=True)  # QSHIELD-REPORT-XXXXXXXX
    report_type = Column(String(50), default="ANALYSIS_REPORT", index=True)  # ANALYSIS_REPORT, THREAT_REPORT, SIMULATION_REPORT, AUDIT_REPORT, PERFORMANCE_REPORT
    analysis_document_id = Column(Integer, ForeignKey("analyzed_documents.analysis_document_id"), nullable=True)
    simulation_id = Column(Integer, ForeignKey("attack_simulations.id"), nullable=True)
    generated_by = Column(String(100), default="Q-SHIELD Security Engine")
    document_name = Column(String(255), nullable=True)
    document_hash = Column(String(128), nullable=True)
    signature_id = Column(String(128), nullable=True)
    overall_status = Column(String(50), default="AUTHENTIC")
    final_security_decision = Column(String(50), default="AUTHENTIC")
    risk_score = Column(Float, default=0.0)
    overall_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    summary = Column(Text, nullable=True)
    report_data = Column(Text, nullable=True)  # JSON serialization
    report_path = Column(String(500), nullable=True, default="")
    report_hash = Column(String(128), nullable=True, default="")
    report_version = Column(String(20), default="SR-2.0")
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    analyzed_document = relationship("AnalyzedDocument", back_populates="security_report")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(100), unique=True, index=True, nullable=True)  # EVT-XXXXXXXX
    user_id = Column(Integer, nullable=True)
    user_email = Column(String(150), nullable=False)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)  # DOCUMENT, SIGNATURE, ANALYSIS, SIMULATION, REPORT, USER, SYSTEM
    resource_id = Column(String(100), nullable=True)
    result = Column(String(50), default="SUCCESS")  # SUCCESS, FAILURE, BLOCKED, WARNING
    details = Column(Text, nullable=True)
    previous_log_hash = Column(String(64), nullable=True)
    current_log_hash = Column(String(64), nullable=True)
    ip_address = Column(String(50), default="127.0.0.1")
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class QDSSimulationSession(Base):
    __tablename__ = "qds_simulation_sessions"

    simulation_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(100), unique=True, index=True, nullable=False)
    simulation_seed = Column(Integer, nullable=False)
    signer_id = Column(String(100), nullable=False)
    verifier_id = Column(String(100), nullable=False)
    initial_state = Column(String(50), nullable=False)
    initial_state_vector = Column(Text, nullable=False)
    bell_state = Column(String(50), nullable=False)
    protocol_parameters = Column(Text, nullable=True)
    measurement_bits = Column(String(20), nullable=False)
    measurement_outcome = Column(String(50), nullable=False)
    pauli_correction = Column(String(20), nullable=False)
    reconstructed_state = Column(Text, nullable=False)
    fidelity = Column(Float, nullable=False)
    verification_result = Column(String(50), nullable=False)
    session_status = Column(String(50), default="COMPLETED")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    attack_simulations = relationship("QDSAttackSimulation", back_populates="simulation", cascade="all, delete-orphan")
    threat_events = relationship("QDSThreatEvent", back_populates="simulation", cascade="all, delete-orphan")


class QDSAttackSimulation(Base):
    __tablename__ = "qds_attack_simulations"

    attack_simulation_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    simulation_id = Column(Integer, ForeignKey("qds_simulation_sessions.simulation_id"), nullable=True)
    attack_type = Column(String(100), nullable=False)
    attack_parameters = Column(Text, nullable=True)
    number_of_trials = Column(Integer, default=100)
    expected_distribution = Column(Text, nullable=True)
    observed_distribution = Column(Text, nullable=True)
    mean_fidelity = Column(Float, default=0.0)
    measurement_error_rate = Column(Float, default=0.0)
    acceptance_rate = Column(Float, default=0.0)
    rejection_rate = Column(Float, default=0.0)
    detection_rate = Column(Float, default=0.0)
    false_acceptance_rate = Column(Float, default=0.0)
    execution_time_ms = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    simulation = relationship("QDSSimulationSession", back_populates="attack_simulations")
    threat_events = relationship("QDSThreatEvent", back_populates="attack_simulation", cascade="all, delete-orphan")


class QDSThreatEvent(Base):
    __tablename__ = "qds_threat_events"

    event_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    simulation_id = Column(Integer, ForeignKey("qds_simulation_sessions.simulation_id"), nullable=True)
    attack_simulation_id = Column(Integer, ForeignKey("qds_attack_simulations.attack_simulation_id"), nullable=True)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    detection_score = Column(Float, default=0.0)
    detection_reason = Column(Text, nullable=False)
    threshold_used = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    simulation = relationship("QDSSimulationSession", back_populates="threat_events")
    attack_simulation = relationship("QDSAttackSimulation", back_populates="threat_events")


class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    simulation_id = Column(String(100), unique=True, index=True, nullable=False)
    initiated_by = Column(String(150), nullable=False)
    attack_type = Column(String(100), nullable=False)
    target_document_reference = Column(String(200), nullable=True)
    target_analysis_id = Column(Integer, nullable=True)
    parameters = Column(Text, nullable=True)  # JSON string
    status = Column(String(50), default="COMPLETED")
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    result = relationship("AttackSimulationResult", back_populates="simulation", uselist=False, cascade="all, delete-orphan")


class AttackSimulationResult(Base):
    __tablename__ = "attack_simulation_results"

    result_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    simulation_id = Column(Integer, ForeignKey("attack_simulations.id"), nullable=False, unique=True)
    attack_type = Column(String(100), nullable=False)
    detection_success = Column(Boolean, default=False)
    detection_status = Column(String(50), default="NOT_DETECTED")
    signature_valid = Column(Boolean, default=False)
    integrity_valid = Column(Boolean, default=False)
    threats_detected = Column(Text, nullable=True)  # JSON list
    state_consistency = Column(Float, default=0.0)
    state_disturbance = Column(Float, default=0.0)
    pauli_disturbance = Column(Float, default=0.0)
    measurement_secure_probability = Column(Float, default=0.0)
    measurement_threat_probability = Column(Float, default=0.0)
    forgery_risk_estimate = Column(Float, default=0.0)
    final_risk_score = Column(Float, default=0.0)
    final_risk_level = Column(String(20), default="LOW")
    baseline_comparison = Column(Text, nullable=True)  # JSON object
    explanation = Column(Text, nullable=True)
    execution_time_ms = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    simulation = relationship("AttackSimulation", back_populates="result")
