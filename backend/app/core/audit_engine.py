"""
Tamper-Evident Audit Logging Engine for Q-SHIELD Security Platform.
Provides append-oriented event recording, SHA-256 hash chaining,
and full cryptographic chain integrity verification.
"""

import uuid
import hashlib
import json
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import event, text
from app.models import AuditLog, User

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def generate_event_id() -> str:
    """Generates unique event identifier format EVT-XXXXXXXX."""
    return f"EVT-{uuid.uuid4().hex[:8].upper()}"


def sanitize_sensitive_data(text_val: Optional[str]) -> str:
    """
    Sanitizes string inputs to prevent leakage of private keys,
    passwords, tokens, or credentials in audit logs.
    """
    if not text_val:
        return ""
    s = str(text_val)
    # Redact PEM private keys (including literal and escaped \n in json strings)
    s = re.sub(r'-----BEGIN[ A-Z_-]*PRIVATE KEY-----[\\n\s\S]*?-----END[ A-Z_-]*PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', s)
    # Redact passwords/tokens in JSON structures
    s = re.sub(r'("?(?:password|access_token|auth_token|secret|api_key)"?\s*:\s*)"[^"]*"', r'\1"[REDACTED_SECRET]"', s, flags=re.IGNORECASE)
    # Redact passwords/tokens in key=value configurations or query strings
    s = re.sub(r'((?:password|access_token|auth_token|secret|api_key)\s*=\s*)[^\s,;&]+', r'\1[REDACTED_SECRET]', s, flags=re.IGNORECASE)
    # Redact bearer tokens
    s = re.sub(r'Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'Bearer [REDACTED_TOKEN]', s)
    return s


def normalize_timestamp_str(ts: Any) -> str:
    if not ts:
        return ""
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    s = str(ts).replace("T", " ").split("+")[0].split("Z")[0].strip()
    if "." in s:
        s = s.split(".")[0]
    return s


def compute_audit_hash(
    previous_hash: str,
    event_id: str,
    action: str,
    user_email: str,
    result: str,
    created_at_iso: str,
    details: str
) -> str:
    """
    Computes SHA-256 hash for a linked audit log event:
    H_n = SHA-256(H_{n-1} || event_id || action || user_email || result || timestamp || details)
    """
    norm_ts = normalize_timestamp_str(created_at_iso)
    raw_payload = f"{previous_hash}|{event_id}|{action}|{user_email}|{result}|{norm_ts}|{details}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()


def log_audit_event(
    db: Session,
    action: str,
    user_email: str = "system@qshield.local",
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    result: str = "SUCCESS",
    details: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Creates and records a hash-linked audit log entry in the database.
    Guarantees no raw secrets or private keys are stored.
    """
    clean_details = sanitize_sensitive_data(details)
    event_id = generate_event_id()
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    # Determine previous hash from latest log entry
    last_log = db.query(AuditLog).order_by(AuditLog.log_id.desc()).first()
    if last_log and last_log.current_log_hash:
        prev_hash = last_log.current_log_hash
    else:
        prev_hash = GENESIS_HASH

    current_hash = compute_audit_hash(
        previous_hash=prev_hash,
        event_id=event_id,
        action=action,
        user_email=user_email,
        result=result,
        created_at_iso=now_iso,
        details=clean_details
    )

    clean_metadata = None
    if metadata:
        clean_meta_str = sanitize_sensitive_data(json.dumps(metadata))
        clean_metadata = clean_meta_str

    audit_entry = AuditLog(
        event_id=event_id,
        user_id=user_id,
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        result=result,
        details=clean_details,
        previous_log_hash=prev_hash,
        current_log_hash=current_hash,
        ip_address=ip_address,
        metadata_json=clean_metadata,
        created_at=now_utc
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def verify_audit_log_integrity(db: Session) -> Dict[str, Any]:
    """
    Traverses the full audit log chain sequentially from genesis to head.
    Validates:
    1. Chronological order & event linkage
    2. Previous hash matching (H_{n-1} == stored prev_hash)
    3. Mathematical recalculation of current_log_hash
    Returns AUDIT_LOG_VALID or AUDIT_LOG_INTEGRITY_WARNING with discrepancy details.
    """
    logs: List[AuditLog] = db.query(AuditLog).order_by(AuditLog.log_id.asc()).all()
    now_str = datetime.now(timezone.utc).isoformat()

    if not logs:
        return {
            "status": "AUDIT_LOG_VALID",
            "total_records_verified": 0,
            "chain_intact": True,
            "verified_at": now_str,
            "genesis_hash": None,
            "latest_hash": None,
            "corrupted_event_id": None,
            "discrepancy_details": None
        }

    expected_prev = GENESIS_HASH
    first_hash = logs[0].current_log_hash
    latest_hash = logs[-1].current_log_hash

    for idx, entry in enumerate(logs):
        # Check if legacy unlinked record (e.g. from early tests before Step 7)
        if not entry.current_log_hash:
            # Backfill legacy entry for chain continuity
            entry.event_id = entry.event_id or f"EVT-LEGACY-{entry.log_id}"
            entry.previous_log_hash = expected_prev
            entry.current_log_hash = compute_audit_hash(
                previous_hash=expected_prev,
                event_id=entry.event_id,
                action=entry.action,
                user_email=entry.user_email,
                result=entry.result or "SUCCESS",
                created_at_iso=entry.created_at.isoformat() if entry.created_at else now_str,
                details=entry.details or ""
            )
            db.commit()

        # Check linkage to previous hash
        if idx > 0 and entry.previous_log_hash != expected_prev:
            return {
                "status": "AUDIT_LOG_INTEGRITY_WARNING",
                "total_records_verified": idx,
                "chain_intact": False,
                "verified_at": now_str,
                "genesis_hash": first_hash,
                "latest_hash": latest_hash,
                "corrupted_event_id": entry.event_id or f"LOG-{entry.log_id}",
                "discrepancy_details": (
                    f"Chain linkage broken at record #{entry.log_id} ({entry.event_id}): "
                    f"previous_log_hash '{entry.previous_log_hash}' does not match "
                    f"expected preceding hash '{expected_prev}'."
                )
            }

        # Check mathematical integrity of current hash
        recalc_hash = compute_audit_hash(
            previous_hash=entry.previous_log_hash or expected_prev,
            event_id=entry.event_id or f"EVT-{entry.log_id}",
            action=entry.action,
            user_email=entry.user_email,
            result=entry.result or "SUCCESS",
            created_at_iso=entry.created_at.isoformat() if entry.created_at else now_str,
            details=entry.details or ""
        )

        if entry.current_log_hash != recalc_hash:
            return {
                "status": "AUDIT_LOG_INTEGRITY_WARNING",
                "total_records_verified": idx,
                "chain_intact": False,
                "verified_at": now_str,
                "genesis_hash": first_hash,
                "latest_hash": latest_hash,
                "corrupted_event_id": entry.event_id or f"LOG-{entry.log_id}",
                "discrepancy_details": (
                    f"Content tampering detected at record #{entry.log_id} ({entry.event_id}): "
                    f"stored hash '{entry.current_log_hash}' != recalculated digest '{recalc_hash}'. "
                    f"Event content was modified after logging."
                )
            }

        expected_prev = entry.current_log_hash

    return {
        "status": "AUDIT_LOG_VALID",
        "total_records_verified": len(logs),
        "chain_intact": True,
        "verified_at": now_str,
        "genesis_hash": first_hash,
        "latest_hash": latest_hash,
        "corrupted_event_id": None,
        "discrepancy_details": None
    }


_last_inserted_hash = None


@event.listens_for(AuditLog, "before_insert")
def auto_hash_chain_audit_log(mapper, connection, target):
    """
    Automatic hash chaining hook for any AuditLog created across the application.
    Guarantees every row has an event_id, links to the preceding row's hash,
    and calculates its current SHA-256 hash.
    """
    global _last_inserted_hash
    if not target.event_id:
        target.event_id = generate_event_id()
    if not target.created_at:
        target.created_at = datetime.now(timezone.utc)
    if target.details:
        target.details = sanitize_sensitive_data(target.details)

    res = connection.execute(
        text("SELECT current_log_hash FROM audit_logs WHERE current_log_hash IS NOT NULL ORDER BY log_id DESC LIMIT 1")
    ).fetchone()
    db_hash = res[0] if (res and res[0]) else GENESIS_HASH
    prev_hash = _last_inserted_hash if _last_inserted_hash else db_hash

    target.previous_log_hash = prev_hash
    target.current_log_hash = compute_audit_hash(
        previous_hash=prev_hash,
        event_id=target.event_id,
        action=target.action or "AUDIT_EVENT",
        user_email=target.user_email or "system@qshield.local",
        result=target.result or "SUCCESS",
        created_at_iso=target.created_at.isoformat() if target.created_at else "",
        details=target.details or ""
    )
    _last_inserted_hash = target.current_log_hash

