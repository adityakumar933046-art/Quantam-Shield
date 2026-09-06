import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator

# Authentication Schemas
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    full_name: str
    email: str
    role: str
    status: str

# User Schemas
class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    role: str
    status: str = "ACTIVE"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    user_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserStatusUpdate(BaseModel):
    status: str

# Digital Signature Schemas
class SignatureDetailsResponse(BaseModel):
    signature_id: int
    document_id: int
    signature_algorithm: str
    hash_algorithm: str
    certificate_subject: str
    certificate_issuer: str
    certificate_serial_number: str
    certificate_fingerprint: str
    signature_fingerprint: str
    signing_timestamp: datetime
    verification_status: str

    model_config = ConfigDict(from_attributes=True)

class DocumentUploadResponse(BaseModel):
    document_id: int
    original_filename: str
    document_hash: str
    file_size: int
    status: str
    content_type: Optional[str] = "PDF"
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class DocumentResponse(BaseModel):
    document_id: int
    user_id: int
    original_filename: str
    signed_filename: Optional[str] = None
    document_hash: str
    content_type: Optional[str] = "PDF"
    raw_text_content: Optional[str] = None
    canonical_hash: Optional[str] = None
    signature_type: Optional[str] = "EMBEDDED_PKCS7"
    signature_value: Optional[str] = None
    file_size: int
    status: str
    created_at: datetime
    signature: Optional[SignatureDetailsResponse] = None

    model_config = ConfigDict(from_attributes=True)

# Multi-Format Signing Request & Response Schemas
class TextSignRequest(BaseModel):
    text_content: str
    filename: Optional[str] = "signed_message.txt"

class JsonSignRequest(BaseModel):
    json_content: Any
    filename: Optional[str] = "signed_data.json"
    canonicalize: bool = True

class StructuredMessageSignRequest(BaseModel):
    sender: str
    receiver: str
    message: str
    amount_data: Optional[str] = ""
    nonce: Optional[str] = None

class MultiFormatSignResponse(BaseModel):
    document_id: int
    content_type: str
    original_filename: str
    content_hash: str
    canonical_hash: Optional[str] = None
    signature_algorithm: str
    signature_value: str
    signed_message_json: Optional[str] = None
    public_key_fingerprint: str
    signing_timestamp: datetime
    status: str

class MultiFormatAnalysisRequest(BaseModel):
    input_type: str # FILE, RAW_TEXT, SIGNED_MESSAGE, DETACHED_SIGNATURE
    content_text: Optional[str] = None
    signature_text: Optional[str] = None
    filename: Optional[str] = "input_content.txt"

# Security Analyst Extraction & Verification Schemas
class ExtractedMetadataResponse(BaseModel):
    signature_analysis_id: int
    analysis_document_id: int
    signature_detected: bool
    signature_status: str
    signature_algorithm: str
    hash_algorithm: str
    signature_fingerprint: str
    field_name: str
    signing_time: Optional[datetime] = None
    certificate_subject: str
    certificate_issuer: str
    certificate_serial_number: str
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None
    certificate_fingerprint: str
    public_key_algorithm: str
    public_key_size: int
    signer_name: str
    signer_organization: str

    model_config = ConfigDict(from_attributes=True)

class SignatureVerificationResponse(BaseModel):
    verification_id: int
    analysis_document_id: int
    signature_identifier: str
    signature_index: int
    verification_status: str
    integrity_status: str
    signature_algorithm: str
    hash_algorithm: str
    certificate_time_status: str
    verification_timestamp: datetime
    verification_details: str
    error_details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Quantum-Inspired Security Analysis Schemas
class QuantumAnalysisResponse(BaseModel):
    quantum_analysis_id: int
    analysis_document_id: int
    security_state_vector: List[float]
    secure_consistency_score: float
    disturbance_score: float
    pauli_x_score: float
    pauli_y_score: float
    pauli_z_score: float
    secure_measurement_score: float
    suspicious_measurement_score: float
    high_risk_measurement_score: float
    forgery_risk_score: float
    analysis_confidence_score: float
    confidence_level: str
    final_classification: str
    analysis_version: str = "QIA-1.0"
    state_consistency: Optional[float] = None
    state_disturbance: Optional[float] = None
    measurement_secure_probability: Optional[float] = None
    measurement_threat_probability: Optional[float] = None
    pauli_x_disturbance: Optional[float] = None
    pauli_y_disturbance: Optional[float] = None
    pauli_z_disturbance: Optional[float] = None
    combined_pauli_disturbance: Optional[float] = None
    forgery_risk_estimate: Optional[float] = None
    quantum_analysis_version: Optional[str] = "QIA-2.0"
    explanation_json: Optional[str] = None
    created_at: datetime

    @field_validator('security_state_vector', mode='before')
    @classmethod
    def parse_state_vector(cls, v: Any) -> List[float]:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return [0.5, 0.5, 0.5, 0.5, 0.5]
        return v

    model_config = ConfigDict(from_attributes=True)

class AnalysisExplanationResponse(BaseModel):
    analysis_id: int
    document_id: int
    final_classification: str
    forgery_risk_score: float
    confidence_level: str
    step1_feature_mapping: str
    step2_state_vector: str
    step3_pauli_analysis: str
    step4_measurement: str
    step5_decision: str

# Historical Threat Detection Schemas
class ThreatIncidentResponse(BaseModel):
    incident_id: int
    analysis_document_id: Optional[int] = None
    threat_category: str
    severity: str
    threat_score: float
    threat_status: str
    description: str
    evidence_data: Optional[str] = None
    detected_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ThreatIncidentUpdateStatus(BaseModel):
    threat_status: str

class ReplayAnalysisResponse(BaseModel):
    document_hash: str
    signature_fingerprint: str
    total_upload_count: int
    total_verification_count: int
    time_window_minutes: int
    frequency_score: float
    time_proximity_score: float
    repeated_failure_score: float
    session_variation_score: float
    replay_suspicion_score: float
    replay_classification: str

class TimeWindowActivityStats(BaseModel):
    time_window: str
    total_uploads: int
    total_verifications: int
    successful_verifications: int
    failed_verifications: int
    repeated_verifications: int
    unique_documents: int
    unique_signatures: int
    avg_verification_frequency_per_min: float
    max_verification_burst: int
    unauthorized_attempt_count: int
    avg_replay_suspicion_score: float

class ActivityStatsResponse(BaseModel):
    stats_5m: TimeWindowActivityStats
    stats_15m: TimeWindowActivityStats
    stats_1h: TimeWindowActivityStats
    stats_24h: TimeWindowActivityStats
    total_incidents_count: int
    open_incidents_count: int

# Step 7 Certificate Security & Final Report Schemas
class CertificateAnalysisResponse(BaseModel):
    certificate_analysis_id: int
    analysis_document_id: int
    certificate_fingerprint: str
    structure_status: str
    time_validity_status: str
    trust_status: str
    chain_status: str
    revocation_status: str
    ocsp_status: str
    crl_status: str
    algorithm_security_status: str
    certificate_security_score: float
    analysis_confidence: float
    details: Optional[str] = None
    checked_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class FinalDecisionResponse(BaseModel):
    analysis_document_id: int
    final_security_decision: str
    overall_risk_score: float
    summary_justification: str
    recommended_action: str
    layer1_signature_status: str
    layer2_integrity_status: str
    layer3_certificate_status: str
    layer4_quantum_status: str
    layer5_threat_status: str

class SecurityReportResponse(BaseModel):
    report_id: int
    report_reference: Optional[str] = None
    report_type: Optional[str] = "ANALYSIS_REPORT"
    analysis_document_id: Optional[int] = None
    simulation_id: Optional[int] = None
    document_name: Optional[str] = None
    document_hash: Optional[str] = None
    signature_id: Optional[str] = None
    overall_status: Optional[str] = "EVALUATED"
    final_security_decision: Optional[str] = "EVALUATED"
    overall_risk_score: Optional[float] = 0.0
    risk_score: Optional[float] = 0.0
    risk_level: Optional[str] = "LOW"
    summary: Optional[str] = None
    report_data: Optional[Any] = None
    report_path: Optional[str] = None
    report_hash: Optional[str] = None
    report_version: Optional[str] = "QSR-2.0"
    generated_by: Optional[str] = "system"
    generated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @field_validator('report_data', mode='before')
    @classmethod
    def parse_json_report_data(cls, v: Any) -> Any:
        from app.core.audit_engine import sanitize_sensitive_data
        if isinstance(v, str):
            clean = sanitize_sensitive_data(v)
            try:
                return json.loads(clean)
            except Exception:
                return clean
        elif isinstance(v, (dict, list)):
            clean = sanitize_sensitive_data(json.dumps(v))
            try:
                return json.loads(clean)
            except Exception:
                return v
        return v

    model_config = ConfigDict(from_attributes=True)

class AnalysisDocumentResponse(BaseModel):
    analysis_document_id: int
    analyst_user_id: int
    original_file_name: str
    file_size: int
    document_hash: str
    signature_present: bool
    signature_status: str
    upload_timestamp: datetime
    created_at: datetime
    extracted_metadata: Optional[ExtractedMetadataResponse] = None
    verifications: Optional[List[SignatureVerificationResponse]] = None
    quantum_analysis: Optional[QuantumAnalysisResponse] = None
    threat_incidents: Optional[List[ThreatIncidentResponse]] = None
    certificate_analysis: Optional[CertificateAnalysisResponse] = None
    security_report: Optional[SecurityReportResponse] = None

    model_config = ConfigDict(from_attributes=True)

# Metrics / Dashboard Stats Schemas
class DigitalSignatureStats(BaseModel):
    total_documents: int
    signed_documents: int
    pending_signatures: int
    recent_activity_count: int

class SecurityAnalystStats(BaseModel):
    total_analyzed: int
    valid_signatures: int
    threats_detected: int
    high_risk_incidents: int

class SuperAdminStats(BaseModel):
    total_users: int
    active_analysts: int
    total_signed_documents: int
    total_analyzed_documents: int
    system_status: str

# Audit Log Schema
class AuditLogResponse(BaseModel):
    log_id: int
    user_id: Optional[int]
    user_email: str
    action: str
    details: Optional[str]
    ip_address: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Step 8 Teleportation-Based QDS Schemas
class QDSSimulationRunRequest(BaseModel):
    initial_state: str = "|+>"
    bell_state: str = "|Phi+>"
    simulation_seed: int = 42
    signer_id: str = "Alice (Signer)"
    verifier_id: str = "Bob (Verifier)"
    acceptance_threshold: float = 0.95
    attack_simulation: str = "none"
    noise_model: Optional[str] = "none"
    depolarizing_error_prob: float = 0.0
    phase_flip_error_prob: float = 0.0
    amplitude_damping_prob: Optional[float] = 0.0

    model_config = ConfigDict(extra="ignore")

class QDSSimulationResponse(BaseModel):
    simulation_id: int
    session_id: str
    simulation_seed: int
    signer_id: str
    verifier_id: str
    initial_state: str
    initial_state_vector: str
    bell_state: str
    protocol_parameters: Optional[str] = None
    measurement_bits: str
    measurement_outcome: str
    pauli_correction: str
    reconstructed_state: str
    fidelity: float
    verification_result: str
    session_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class QDSAttackRunRequest(BaseModel):
    attack_type: str = "BIT_FLIP"
    number_of_trials: int = 100
    attack_probability: Optional[float] = 0.5
    noise_level: Optional[float] = None
    initial_state: str = "|+>"
    bell_state: Optional[str] = "|Phi+>"
    simulation_seed: int = 1234
    detection_threshold: Optional[float] = 0.95
    acceptance_threshold: Optional[float] = None
    signer_id: str = "Alice (Signer)"
    verifier_id: str = "Bob (Verifier)"

    model_config = ConfigDict(extra="ignore")

class QDSAttackSimulationResponse(BaseModel):
    attack_simulation_id: int
    simulation_id: Optional[int] = None
    attack_type: str
    attack_parameters: Optional[str] = None
    number_of_trials: int
    expected_distribution: Optional[str] = None
    observed_distribution: Optional[str] = None
    mean_fidelity: float
    measurement_error_rate: float
    acceptance_rate: float
    rejection_rate: float
    detection_rate: float
    false_acceptance_rate: float
    execution_time_ms: float
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class QDSThreatEventResponse(BaseModel):
    event_id: int
    simulation_id: Optional[int] = None
    attack_simulation_id: Optional[int] = None
    threat_type: str
    severity: str
    detection_score: float
    detection_reason: str
    threshold_used: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class QDSPerformanceMetricsResponse(BaseModel):
    total_simulations: int
    successful_teleportations: int
    attack_simulations_count: int
    threats_detected_count: int
    average_fidelity: float
    average_execution_time_ms: float
    attack_detection_accuracy: float
    false_acceptance_rate: float
    false_rejection_rate: float
    time_complexity_explanation: str
    space_complexity_explanation: str


# Canonical Step 4 Schemas
class CanonicalSignatureResponse(BaseModel):
    signature_id: str
    document_id: int
    original_filename: str
    file_type: str
    hash_algorithm: str
    document_hash: str
    signature_algorithm: str
    signature_value: Optional[str] = None
    public_key: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    status: str
    signed_at: Optional[datetime] = None
    download_url: Optional[str] = None
    package_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class CanonicalThreatSummary(BaseModel):
    incident_id: Optional[int] = None
    threat_category: str
    threat_type: Optional[str] = None
    severity: str
    threat_score: float
    threat_status: str
    description: str

    model_config = ConfigDict(from_attributes=True)


class CanonicalAnalysisResponse(BaseModel):
    analysis_id: str
    analysis_document_id: int
    signature_id: Optional[str] = None
    original_file_name: str
    file_type: str
    current_hash: str
    stored_hash: Optional[str] = None
    signature_verified: bool
    integrity_verified: bool
    certificate_status: str
    public_key_status: str
    risk_score: float
    risk_level: str
    final_decision: str
    analysis_summary: Optional[str] = None
    analysed_at: Optional[datetime] = None
    threats: List[CanonicalThreatSummary] = []
    quantum_metrics: Optional[Dict[str, Any]] = None
    verification_details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PlatformStatisticsSummary(BaseModel):
    total_signatures: int
    total_verifications: int
    total_threats_detected: int
    valid_signatures: int
    tampered_signatures: int
    replay_attacks_detected: int
    average_risk_score: float


# Step 6 Controlled Attack Simulation Schemas
class AttackSimulationCreateRequest(BaseModel):
    attack_type: str  # DOCUMENT_TAMPERING, SIGNATURE_FORGERY, REPLAY_ATTACK, IMPERSONATION, UNAUTHORIZED_VERIFICATION, SIGNATURE_MANIPULATION, QUANTUM_CHANNEL_MANIPULATION
    target_document_reference: Optional[str] = "synthetic_sample.txt"
    target_analysis_id: Optional[int] = None
    parameters: Optional[Dict[str, Any]] = None


class SimulationResultResponse(BaseModel):
    result_id: int
    simulation_id: int
    attack_type: str
    detection_success: bool
    detection_status: str
    signature_valid: bool
    integrity_valid: bool
    threats_detected: Optional[Any] = None
    state_consistency: float
    state_disturbance: float
    pauli_disturbance: float
    measurement_secure_probability: float
    measurement_threat_probability: float
    forgery_risk_estimate: float
    final_risk_score: float
    final_risk_level: str
    baseline_comparison: Optional[Any] = None
    explanation: Optional[Any] = None
    execution_time_ms: float
    created_at: datetime

    @field_validator('threats_detected', 'baseline_comparison', 'explanation', mode='before')
    @classmethod
    def parse_json_fields(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return v
        return v

    model_config = ConfigDict(from_attributes=True)


class AttackSimulationResponse(BaseModel):
    id: int
    simulation_id: str
    initiated_by: str
    attack_type: str
    target_document_reference: Optional[str] = None
    target_analysis_id: Optional[int] = None
    parameters: Optional[str] = None
    status: str
    started_at: datetime
    completed_at: datetime
    created_at: datetime
    result: Optional[SimulationResultResponse] = None

    model_config = ConfigDict(from_attributes=True)


class SimulationMetricsSummaryResponse(BaseModel):
    total_simulations: int
    threats_correctly_detected: int
    detection_rate: float
    missed_simulations: int
    average_detection_time_ms: float
    average_risk_score: float
    attack_type_breakdown: Dict[str, Any]
    disclaimer: str


# ==============================================================================
# Step 7: Security Reports, Audit Logs, Performance Evaluation, Dashboard Schemas
# ==============================================================================

class SecurityReportResponse(BaseModel):
    report_id: int
    report_reference: Optional[str] = None
    report_type: str
    analysis_document_id: Optional[int] = None
    simulation_id: Optional[int] = None
    generated_by: str
    document_name: Optional[str] = None
    document_hash: Optional[str] = None
    signature_id: Optional[str] = None
    overall_status: str
    final_security_decision: Optional[str] = None
    risk_score: float
    overall_risk_score: Optional[float] = None
    risk_level: str
    summary: Optional[str] = None
    report_data: Optional[Any] = None
    report_path: Optional[str] = None
    report_hash: Optional[str] = None
    report_version: Optional[str] = None
    generated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @field_validator('report_data', mode='before')
    @classmethod
    def parse_json_report_data(cls, v: Any) -> Any:
        from app.core.audit_engine import sanitize_sensitive_data
        if isinstance(v, str):
            clean = sanitize_sensitive_data(v)
            try:
                return json.loads(clean)
            except Exception:
                return clean
        elif isinstance(v, (dict, list)):
            clean = sanitize_sensitive_data(json.dumps(v))
            try:
                return json.loads(clean)
            except Exception:
                return v
        return v

    model_config = ConfigDict(from_attributes=True)


class ReportGenerateRequest(BaseModel):
    report_type: str = "ANALYSIS_REPORT"  # ANALYSIS_REPORT, THREAT_REPORT, SIMULATION_REPORT, AUDIT_REPORT, PERFORMANCE_REPORT
    analysis_id: Optional[int] = None
    simulation_id: Optional[int] = None
    notes: Optional[str] = None


class AuditLogDetailedResponse(BaseModel):
    log_id: int
    event_id: Optional[str] = None
    user_id: Optional[int] = None
    user_email: str
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    result: str
    details: Optional[str] = None
    previous_log_hash: Optional[str] = None
    current_log_hash: Optional[str] = None
    ip_address: str
    metadata_json: Optional[Any] = None
    created_at: datetime

    @field_validator('metadata_json', mode='before')
    @classmethod
    def parse_metadata_json(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return v
        return v

    model_config = ConfigDict(from_attributes=True)


class AuditIntegrityVerificationResponse(BaseModel):
    status: str  # AUDIT_LOG_VALID or AUDIT_LOG_INTEGRITY_WARNING
    total_records_verified: int
    chain_intact: bool
    verified_at: datetime
    genesis_hash: Optional[str] = None
    latest_hash: Optional[str] = None
    corrupted_event_id: Optional[str] = None
    discrepancy_details: Optional[str] = None


class PerformanceMetricsResponse(BaseModel):
    total_analyses: int
    successful_verifications: int
    failed_verifications: int
    threats_detected: int
    total_simulations: int
    detected_simulations: int
    missed_simulations: int
    detection_rate: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    average_analysis_time_ms: float
    average_detection_time_ms: float
    average_risk_score: float
    attack_type_breakdown: Dict[str, Any]
    disclaimer: str


class DashboardOverviewResponse(BaseModel):
    total_documents_analyzed: int
    verified_documents: int
    failed_verifications: int
    threats_detected: int
    high_risk_documents: int
    critical_risk_documents: int
    system_status: str


class DashboardRiskResponse(BaseModel):
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    critical_risk_count: int
    average_risk_score: float


class DashboardThreatsResponse(BaseModel):
    threat_type_distribution: Dict[str, int]
    recent_threats: List[Dict[str, Any]]
    highest_severity_threats: List[Dict[str, Any]]


class DashboardActivityResponse(BaseModel):
    recent_uploads: List[Dict[str, Any]]
    recent_analyses: List[Dict[str, Any]]
    recent_threats: List[Dict[str, Any]]
    recent_simulations: List[Dict[str, Any]]
    recent_reports: List[Dict[str, Any]]


class DashboardQuantumAnalysisResponse(BaseModel):
    average_state_consistency: float
    average_state_disturbance: float
    average_threat_probability: float
    average_pauli_disturbance: float
    analyzed_sample_count: int




