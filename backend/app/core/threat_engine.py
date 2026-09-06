import json
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import (
    AnalyzedDocument,
    ExtractedSignatureMetadata,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    AuditLog,
    User,
    VerificationActivity
)
from app.core.config import REPLAY_WINDOW_MINUTES, REPLAY_THRESHOLD_COUNT

# Configurable Weights for Replay Suspicion Score (Sum to 1.0)
WEIGHT_FREQUENCY = 0.35
WEIGHT_PROXIMITY = 0.30
WEIGHT_FAILURE = 0.20
WEIGHT_SESSION = 0.15

def analyze_replay_suspicion(
    db: Session,
    document_hash: str,
    signature_fingerprint: str = "Not Available",
    time_window_minutes: int = REPLAY_WINDOW_MINUTES
) -> Dict[str, Any]:
    """
    100% Deterministic Replay Suspicion Engine.
    Evaluates frequency, time proximity, failure rates, and session variation
    to calculate a normalized Replay Suspicion Score (0.0 to 100.0).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=time_window_minutes)

    # 1. Query Upload / Analysis records with matching document hash
    matching_docs = db.query(AnalyzedDocument).filter(
        AnalyzedDocument.document_hash == document_hash,
        AnalyzedDocument.created_at >= cutoff
    ).order_by(AnalyzedDocument.created_at.asc()).all()

    doc_ids = [d.analysis_document_id for d in matching_docs]
    upload_count = len(matching_docs)

    # 2. Query Verifications for these documents
    verifications = []
    if doc_ids:
        verifications = db.query(SignatureVerification).filter(
            SignatureVerification.analysis_document_id.in_(doc_ids),
            SignatureVerification.created_at >= cutoff
        ).order_by(SignatureVerification.created_at.asc()).all()

    verification_count = len(verifications)

    # Also incorporate historical VerificationActivity records
    activities = db.query(VerificationActivity).filter(
        VerificationActivity.document_hash == document_hash,
        VerificationActivity.timestamp >= cutoff
    ).all()
    act_count = len(activities)
    if act_count > 0:
        verification_count = max(verification_count, act_count)
        upload_count = max(upload_count, 1)

    failed_verifications = [
        v for v in verifications
        if v.verification_status != "VALID" or v.integrity_status == "MODIFIED"
    ]
    failed_count = len(failed_verifications)

    # 3. User / Session Variation Count
    unique_analyst_ids = set(d.analyst_user_id for d in matching_docs if d.analyst_user_id)
    if activities:
        unique_analyst_ids.update(a.user_id for a in activities if a.user_id)
    session_variation_count = len(unique_analyst_ids)


    # If single upload and single verification, it's normal repeat activity
    if upload_count <= 1 and verification_count <= 1:
        return {
            "document_hash": document_hash,
            "signature_fingerprint": signature_fingerprint,
            "total_upload_count": upload_count,
            "total_verification_count": verification_count,
            "time_window_minutes": time_window_minutes,
            "frequency_score": 0.0,
            "time_proximity_score": 0.0,
            "repeated_failure_score": 0.0,
            "session_variation_score": 0.0,
            "replay_suspicion_score": 0.0,
            "replay_classification": "NORMAL_REPEAT"
        }

    # 4. Frequency Score (0 to 100)
    total_activity = upload_count + verification_count
    frequency_score = round(min(100.0, max(0.0, (total_activity - 1) * 20.0)), 2)

    # 5. Time Proximity Score (0 to 100)
    timestamps = [d.created_at for d in matching_docs] + [v.created_at for v in verifications]
    timestamps.sort()

    if len(timestamps) > 1:
        deltas = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
        avg_delta = sum(deltas) / len(deltas)

        if avg_delta <= 10.0:
            time_proximity_score = 100.0
        elif avg_delta <= 60.0:
            time_proximity_score = 75.0
        elif avg_delta <= 300.0:
            time_proximity_score = 45.0
        elif avg_delta <= 900.0:
            time_proximity_score = 20.0
        else:
            time_proximity_score = 0.0
    else:
        time_proximity_score = 0.0

    # 6. Repeated Failure Score (0 to 100)
    repeated_failure_score = round(min(100.0, failed_count * 35.0), 2)

    # 7. Session Variation Score (0 to 100)
    session_variation_score = round(min(100.0, max(0, session_variation_count - 1) * 40.0), 2)

    # 8. Replay Suspicion Score
    replay_score = round(
        WEIGHT_FREQUENCY * frequency_score +
        WEIGHT_PROXIMITY * time_proximity_score +
        WEIGHT_FAILURE * repeated_failure_score +
        WEIGHT_SESSION * session_variation_score,
        2
    )

    if verification_count >= REPLAY_THRESHOLD_COUNT:
        replay_score = max(replay_score, 45.0)
    if verification_count >= (REPLAY_THRESHOLD_COUNT + 2):
        replay_score = max(replay_score, 75.0)

    # 9. Replay Classification
    if replay_score >= 65.0:
        replay_classification = "HIGH_REPLAY_SUSPICION"
    elif replay_score >= 40.0:
        replay_classification = "SUSPICIOUS_REPLAY"
    elif replay_score >= 15.0:
        replay_classification = "LOW_REPLAY_SUSPICION"
    else:
        replay_classification = "NORMAL_REPEAT"

    return {
        "document_hash": document_hash,
        "signature_fingerprint": signature_fingerprint,
        "total_upload_count": upload_count,
        "total_verification_count": verification_count,
        "time_window_minutes": time_window_minutes,
        "frequency_score": frequency_score,
        "time_proximity_score": time_proximity_score,
        "repeated_failure_score": repeated_failure_score,
        "session_variation_score": session_variation_score,
        "replay_suspicion_score": replay_score,
        "replay_classification": replay_classification
    }


def evaluate_and_generate_threats(
    db: Session,
    analysis_document_id: int
) -> List[ThreatIncident]:
    """
    Evaluates all 6 deterministic threat categories for a target analyzed document.
    Creates and stores ThreatIncident records in DB if suspicious rules trigger.
    """
    doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == analysis_document_id).first()
    if not doc:
        return []

    # Clear existing incidents for this document if re-evaluating
    db.query(ThreatIncident).filter(ThreatIncident.analysis_document_id == analysis_document_id).delete()
    db.commit()

    meta = doc.extracted_metadata
    verifs = doc.verifications
    quantum = doc.quantum_analysis

    sig_fingerprint = meta.signature_fingerprint if meta else "Not Available"
    new_incidents = []

    # ------------------------------------------------------------------
    # CATEGORY 1: REPLAY_SUSPECTED
    # ------------------------------------------------------------------
    replay_res = analyze_replay_suspicion(
        db,
        document_hash=doc.document_hash,
        signature_fingerprint=sig_fingerprint,
        time_window_minutes=15
    )

    if replay_res["replay_classification"] in ["SUSPICIOUS_REPLAY", "HIGH_REPLAY_SUSPICION"]:
        sev = "HIGH" if replay_res["replay_classification"] == "HIGH_REPLAY_SUSPICION" else "MEDIUM"
        desc = (
            f"Suspicious document replay activity detected. Document SHA-256 ({doc.document_hash[:16]}...) "
            f"has {replay_res['total_upload_count']} uploads and {replay_res['total_verification_count']} verifications "
            f"within 15 minutes (Replay Score: {replay_res['replay_suspicion_score']}/100)."
        )
        t_replay = ThreatIncident(
            analysis_document_id=doc.analysis_document_id,
            threat_category="REPLAY_SUSPECTED",
            severity=sev,
            threat_score=replay_res["replay_suspicion_score"],
            threat_status="OPEN",
            description=desc,
            evidence_data=json.dumps(replay_res)
        )
        new_incidents.append(t_replay)

    # ------------------------------------------------------------------
    # CATEGORY 2: SUSPICIOUS_REPEATED_VERIFICATION
    # ------------------------------------------------------------------
    verif_audit_count = db.query(AuditLog).filter(
        AuditLog.action == "SIGNATURE_VERIFICATION_STARTED",
        AuditLog.details.like(f"%{doc.analysis_document_id}%")
    ).count()

    v_count = max(len(verifs) if verifs else 0, verif_audit_count)
    if v_count >= 3:
        failed_v = [v for v in verifs if v.verification_status != "VALID"] if verifs else []
        sev = "HIGH" if len(failed_v) >= 2 or v_count >= 5 else "MEDIUM"
        desc = (
            f"High-frequency repeated verification requests ({v_count} attempts) "
            f"detected for document #{doc.analysis_document_id} ({doc.original_file_name})."
        )
        evidence = {
            "verification_count": v_count,
            "failed_verification_count": len(failed_v),
            "document_hash": doc.document_hash
        }
        t_verif = ThreatIncident(
            analysis_document_id=doc.analysis_document_id,
            threat_category="SUSPICIOUS_REPEATED_VERIFICATION",
            severity=sev,
            threat_score=min(100.0, v_count * 15.0 + len(failed_v) * 20.0),
            threat_status="OPEN",
            description=desc,
            evidence_data=json.dumps(evidence)
        )
        new_incidents.append(t_verif)

    # ------------------------------------------------------------------
    # CATEGORY 3: UNAUTHORIZED_VERIFICATION_ATTEMPT
    # ------------------------------------------------------------------
    unauth_logs = db.query(AuditLog).filter(
        AuditLog.action.in_(["UNAUTHORIZED_ACCESS_ATTEMPT", "UNAUTHORIZED_VERIFICATION_DENIED", "ACCESS_DENIED_ROLE"])
    ).all()

    if unauth_logs:
        log_count = len(unauth_logs)
        sev = "CRITICAL" if log_count >= 3 else "HIGH"
        desc = (
            f"Unauthorized authorization policy violations detected ({log_count} attempts) "
            f"in security inspection logs."
        )
        evidence = {
            "unauthorized_attempts": log_count,
            "log_details": [l.details for l in unauth_logs[:5]],
            "user_emails": list(set(l.user_email for l in unauth_logs))
        }
        t_unauth = ThreatIncident(
            analysis_document_id=doc.analysis_document_id,
            threat_category="UNAUTHORIZED_VERIFICATION_ATTEMPT",
            severity=sev,
            threat_score=min(100.0, 50.0 + log_count * 20.0),
            threat_status="OPEN",
            description=desc,
            evidence_data=json.dumps(evidence)
        )
        new_incidents.append(t_unauth)

    # ------------------------------------------------------------------
    # CATEGORY 4: IMPERSONATION_SUSPECTED
    # ------------------------------------------------------------------
    if meta and meta.signature_detected:
        subject = meta.certificate_subject or ""
        issuer = meta.certificate_issuer or ""
        signer = meta.signer_name or ""
        org = meta.signer_organization or ""

        impersonation_score = 0.0
        reasons = []

        # Check CN vs Signer Name mismatch
        if signer != "Not Available" and signer not in subject:
            impersonation_score += 40.0
            reasons.append(f"Signer name '{signer}' does not match certificate subject '{subject}'.")

        # Check self-signed root pretending to be corporate CA
        if subject == issuer and "Development" not in subject and "Demo" not in subject and "Enterprise" in subject:
            impersonation_score += 50.0
            reasons.append("Self-signed certificate claims enterprise CA authority without trusted chain.")

        if impersonation_score >= 40.0:
            t_imp = ThreatIncident(
                analysis_document_id=doc.analysis_document_id,
                threat_category="IMPERSONATION_SUSPECTED",
                severity="HIGH" if impersonation_score >= 60.0 else "MEDIUM",
                threat_score=impersonation_score,
                threat_status="OPEN",
                description=f"Potential signer identity impersonation indicator detected. " + " ".join(reasons),
                evidence_data=json.dumps({
                    "signer_name": signer,
                    "organization": org,
                    "certificate_subject": subject,
                    "certificate_issuer": issuer,
                    "impersonation_reasons": reasons
                })
            )
            new_incidents.append(t_imp)

    # ------------------------------------------------------------------
    # CATEGORY 5: SIGNATURE_REUSE_ANOMALY
    # ------------------------------------------------------------------
    if sig_fingerprint != "Not Available" and len(sig_fingerprint) > 10:
        # Check if the same signature fingerprint is attached to DIFFERENT document hashes
        other_sig_metas = db.query(ExtractedSignatureMetadata).filter(
            ExtractedSignatureMetadata.signature_fingerprint == sig_fingerprint,
            ExtractedSignatureMetadata.analysis_document_id != doc.analysis_document_id
        ).all()

        conflicting_hashes = set()
        for o_meta in other_sig_metas:
            o_doc = db.query(AnalyzedDocument).filter(AnalyzedDocument.analysis_document_id == o_meta.analysis_document_id).first()
            if o_doc and o_doc.document_hash != doc.document_hash:
                conflicting_hashes.add(o_doc.document_hash)

        if conflicting_hashes:
            desc = (
                f"Signature Reuse Anomaly detected! Signature Fingerprint ({sig_fingerprint[:16]}...) "
                f"is attached to {len(conflicting_hashes)} distinct document content hashes."
            )
            t_reuse = ThreatIncident(
                analysis_document_id=doc.analysis_document_id,
                threat_category="SIGNATURE_REUSE_ANOMALY",
                severity="CRITICAL",
                threat_score=90.0,
                threat_status="OPEN",
                description=desc,
                evidence_data=json.dumps({
                    "signature_fingerprint": sig_fingerprint,
                    "target_document_hash": doc.document_hash,
                    "conflicting_document_hashes": list(conflicting_hashes)
                })
            )
            new_incidents.append(t_reuse)

    # ------------------------------------------------------------------
    # CATEGORY 6: EXCESSIVE_ANALYSIS_ACTIVITY
    # ------------------------------------------------------------------
    recent_uploads = db.query(AnalyzedDocument).filter(
        AnalyzedDocument.analyst_user_id == doc.analyst_user_id,
        AnalyzedDocument.created_at >= datetime.now(timezone.utc) - timedelta(minutes=15)
    ).count()

    if recent_uploads >= 8:
        t_exc = ThreatIncident(
            analysis_document_id=doc.analysis_document_id,
            threat_category="EXCESSIVE_ANALYSIS_ACTIVITY",
            severity="MEDIUM",
            threat_score=min(100.0, recent_uploads * 10.0),
            threat_status="OPEN",
            description=f"Excessive analysis upload activity detected ({recent_uploads} uploads in 15 minutes by analyst #{doc.analyst_user_id}).",
            evidence_data=json.dumps({
                "analyst_user_id": doc.analyst_user_id,
                "recent_uploads_15m": recent_uploads
            })
        )
        new_incidents.append(t_exc)

    # Add all detected incidents to DB
    if new_incidents:
        db.add_all(new_incidents)
        db.commit()

    return new_incidents


def calculate_activity_statistics(db: Session) -> Dict[str, Any]:
    """
    Computes time-window aggregated activity statistics over 5m, 15m, 1h, 24h.
    """
    now = datetime.now(timezone.utc)

    def get_stats_for_window(minutes: int, window_name: str) -> Dict[str, Any]:
        cutoff = now - timedelta(minutes=minutes)

        uploads = db.query(AnalyzedDocument).filter(AnalyzedDocument.created_at >= cutoff).all()
        doc_ids = [d.analysis_document_id for d in uploads]

        verifs = []
        if doc_ids:
            verifs = db.query(SignatureVerification).filter(
                SignatureVerification.analysis_document_id.in_(doc_ids),
                SignatureVerification.created_at >= cutoff
            ).all()

        total_uploads = len(uploads)
        total_verifs = len(verifs)

        successful_v = sum(1 for v in verifs if v.verification_status == "VALID" and v.integrity_status == "INTACT")
        failed_v = total_verifs - successful_v

        unique_docs = len(set(d.document_hash for d in uploads))
        repeated_verifs = max(0, total_verifs - unique_docs)

        # Unique signatures
        sig_metas = db.query(ExtractedSignatureMetadata).filter(
            ExtractedSignatureMetadata.analysis_document_id.in_(doc_ids)
        ).all() if doc_ids else []
        unique_sigs = len(set(m.signature_fingerprint for m in sig_metas if m.signature_fingerprint != "Not Available"))

        avg_freq = round((total_uploads + total_verifs) / float(minutes), 2)
        max_burst = max(total_uploads, total_verifs)

        unauth_count = db.query(AuditLog).filter(
            AuditLog.action.in_(["UNAUTHORIZED_ACCESS_ATTEMPT", "UNAUTHORIZED_VERIFICATION_DENIED", "ACCESS_DENIED_ROLE"]),
            AuditLog.created_at >= cutoff
        ).count()

        # Replay scores average
        replay_scores = []
        for d in uploads:
            r = analyze_replay_suspicion(db, d.document_hash, time_window_minutes=minutes)
            replay_scores.append(r["replay_suspicion_score"])

        avg_replay = round(sum(replay_scores) / len(replay_scores), 2) if replay_scores else 0.0

        return {
            "time_window": window_name,
            "total_uploads": total_uploads,
            "total_verifications": total_verifs,
            "successful_verifications": successful_v,
            "failed_verifications": failed_v,
            "repeated_verifications": repeated_verifs,
            "unique_documents": unique_docs,
            "unique_signatures": unique_sigs,
            "avg_verification_frequency_per_min": avg_freq,
            "max_verification_burst": max_burst,
            "unauthorized_attempt_count": unauth_count,
            "avg_replay_suspicion_score": avg_replay
        }

    total_incidents = db.query(ThreatIncident).count()
    open_incidents = db.query(ThreatIncident).filter(ThreatIncident.threat_status == "OPEN").count()

    return {
        "stats_5m": get_stats_for_window(5, "5m"),
        "stats_15m": get_stats_for_window(15, "15m"),
        "stats_1h": get_stats_for_window(60, "1h"),
        "stats_24h": get_stats_for_window(1440, "24h"),
        "total_incidents_count": total_incidents,
        "open_incidents_count": open_incidents
    }
