"""
Step 4 Canonical Endpoints for Q-SHIELD Security Platform.
Seamlessly bridges Digital Signature Generation, Storage, Cryptographic Verification,
and Security Analyst Threat Analysis across all file formats.
"""

import os
import json
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.db import get_db
from app.core.config import (
    MEDIA_ORIGINALS,
    MEDIA_SIGNED,
    MEDIA_PACKAGES,
    MEDIA_ANALYSIS,
    REPLAY_WINDOW_MINUTES,
    REPLAY_THRESHOLD_COUNT
)
from app.models import (
    User,
    SignedDocument,
    DigitalSignature,
    AnalyzedDocument,
    ExtractedSignatureMetadata,
    SignatureVerification,
    QuantumInspiredAnalysis,
    ThreatIncident,
    AuditLog,
    KeyPair,
    VerificationActivity
)
from app.schemas import (
    CanonicalSignatureResponse,
    CanonicalAnalysisResponse,
    CanonicalThreatSummary,
    PlatformStatisticsSummary
)
from app.api.auth import get_current_user
from app.core.key_manager import (
    get_or_create_user_keypair,
    get_user_private_key,
    compute_public_key_fingerprint
)
from app.core.id_generator import generate_signature_id, generate_analysis_id
from app.core.package_manager import create_detached_signature_package, parse_detached_signature_metadata
from app.core.signer import compute_sha256, sign_pdf_document, sign_text_content, sign_json_content
from app.core.extractor import extract_multiformat_signature_info
from app.core.verifier import verify_multiformat_signature, verify_pdf_signatures
from app.core.format_processors import (
    detect_content_format,
    ContentType,
    canonicalize_json,
    rsa_sign_hash_bytes,
    rsa_verify_signature,
    format_qshield_signed_message
)
from app.core.quantum_engine import analyze_quantum_security_state
from app.core.threat_engine import evaluate_and_generate_threats, analyze_replay_suspicion

router = APIRouter(tags=["Step 4 Database Integration & Canonical Pipelines"])

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


def require_signer_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["DIGITAL_SIGNATURE_USER", "SUPER_ADMIN", "SECURITY_ANALYST"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Valid authenticated role required."
        )
    return current_user


def require_analyst_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["SECURITY_ANALYST", "SUPER_ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Security Analyst role required."
        )
    return current_user


# ====================================================================
# 1. SIGNATURE GENERATION AND RETRIEVAL
# ====================================================================

@router.post("/signatures/create/", response_model=CanonicalSignatureResponse)
def create_signature_canonical(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signer_or_admin)
):
    """
    Creates a real cryptographic digital signature for uploaded file or raw text,
    stores record in database with readable QSHIELD-SIGN-XXXXXXXX identifier,
    writes signed file/package into media directories, and logs VerificationActivity.
    Private key is NEVER returned in response.
    """
    if not file and not raw_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either a document file or raw text content must be provided."
        )

    # 1. Resolve content bytes and filename
    if file:
        content_bytes = file.file.read()
        chosen_filename = file.filename or "document.txt"
    else:
        content_bytes = raw_text.encode('utf-8')
        chosen_filename = filename or "signed_document.txt"

    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Content exceeds 25MB limit.")

    file_fmt = detect_content_format(content_bytes, chosen_filename)
    safe_name = Path(chosen_filename).name.replace(" ", "_")
    file_id = str(uuid.uuid4())[:8]

    # Save original file to MEDIA_ORIGINALS
    orig_saved_name = f"{current_user.user_id}_{file_id}_{safe_name}"
    orig_path = MEDIA_ORIGINALS / orig_saved_name
    with open(orig_path, "wb") as f:
        f.write(content_bytes)

    # Compute original SHA-256 hash
    doc_hash = hashlib.sha256(content_bytes).hexdigest()

    # Retrieve or create user KeyPair
    keypair = get_or_create_user_keypair(db, current_user.user_id)
    sig_id = generate_signature_id()
    now_utc = datetime.now(timezone.utc)

    # Perform real cryptographic signing
    signed_saved_name = f"signed_{current_user.user_id}_{file_id}_{safe_name}"
    signed_path = MEDIA_SIGNED / signed_saved_name
    package_url = None

    if file_fmt == ContentType.PDF or safe_name.lower().endswith(".pdf"):
        # Sign PDF using pyhanko
        sig_meta = sign_pdf_document(orig_path, signed_path)
        sig_val = sig_meta.get("signature_fingerprint")
        sig_fp = sig_meta.get("signature_fingerprint")
        pubkey_fp = sig_meta.get("certificate_fingerprint")
        file_type_str = "PDF"
    else:
        # Sign text/JSON using user RSA key or dev key
        try:
            from cryptography.hazmat.primitives import hashes, padding
            import base64
            priv_key = get_user_private_key(db, current_user.user_id)
            sig_raw = priv_key.sign(content_bytes, padding.PKCS1v15(), hashes.SHA256())
            sig_b64 = base64.b64encode(sig_raw).decode('utf-8')
            sig_val = sig_b64
            sig_fp = hashlib.sha256(sig_raw).hexdigest()
            pubkey_fp = keypair.key_fingerprint
        except Exception:
            sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(content_bytes)
            sig_val = sig_b64
            pubkey_fp = cert_fp

        if file_fmt == ContentType.JSON:
            file_type_str = "JSON"
            envelope = {
                "format_version": "QSHIELD-1.0",
                "signature_id": sig_id,
                "content": content_bytes.decode('utf-8', errors='replace'),
                "content_hash": doc_hash,
                "signature": sig_val,
                "public_key_fingerprint": pubkey_fp,
                "signed_at": now_utc.isoformat()
            }
            with open(signed_path, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=2)
        else:
            file_type_str = "TXT"
            signed_msg = format_qshield_signed_message(
                content=content_bytes.decode('utf-8', errors='replace'),
                content_hash=doc_hash,
                signature_b64=sig_val,
                pubkey_fingerprint=pubkey_fp,
                signature_id=sig_id
            )
            with open(signed_path, "w", encoding="utf-8") as f:
                f.write(signed_msg)

        # Create detached signature package in MEDIA_PACKAGES
        pkg = create_detached_signature_package(
            filename=safe_name,
            content_bytes=content_bytes,
            signature_b64=sig_val,
            signature_id=sig_id,
            public_key_fingerprint=pubkey_fp,
            signature_fingerprint=sig_fp,
            signed_at=now_utc
        )
        package_url = f"/api/signatures/{sig_id}/download-package"

    # Store in database SignedDocument
    signed_doc = SignedDocument(
        signature_id=sig_id,
        user_id=current_user.user_id,
        original_filename=safe_name,
        original_file_path=str(orig_path),
        file_path=str(signed_path),
        file_type=file_type_str,
        signed_filename=signed_saved_name,
        signed_file_path=str(signed_path),
        document_hash=doc_hash,
        hash_algorithm="SHA-256",
        signature_algorithm="RSA-SHA256",
        signature_value=sig_val,
        public_key_fingerprint=pubkey_fp,
        key_reference=f"USER-KEY-{current_user.user_id}",
        file_size=len(content_bytes),
        status="SIGNED",
        signed_at=now_utc
    )
    db.add(signed_doc)
    db.commit()
    db.refresh(signed_doc)

    # Store DigitalSignature record
    db_sig = DigitalSignature(
        document_id=signed_doc.document_id,
        signature_algorithm="RSA-SHA256",
        hash_algorithm="SHA-256",
        certificate_subject=f"CN=User-{current_user.user_id}, O=Q-SHIELD Platform",
        certificate_issuer="CN=Q-SHIELD Root Authority",
        certificate_serial_number=str(abs(hash(sig_id))),
        certificate_fingerprint=pubkey_fp,
        signature_fingerprint=sig_fp,
        signing_timestamp=now_utc,
        verification_status="VALID"
    )
    db.add(db_sig)

    # Log VerificationActivity (action=SIGN)
    activity = VerificationActivity(
        user_id=current_user.user_id,
        document_hash=doc_hash,
        signature_fingerprint=sig_fp,
        action="SIGN",
        result="SUCCESS",
        source_identifier=f"user_{current_user.user_id}",
        metadata_json=json.dumps({"signature_id": sig_id, "filename": safe_name})
    )
    db.add(activity)

    # Audit Trail
    audit = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="SIGNATURE_GENERATED",
        details=f"Created digital signature {sig_id} for file {safe_name} ({len(content_bytes)} bytes)"
    )
    db.add(audit)
    db.commit()

    return CanonicalSignatureResponse(
        signature_id=sig_id,
        document_id=signed_doc.document_id,
        original_filename=safe_name,
        file_type=file_type_str,
        hash_algorithm="SHA-256",
        document_hash=doc_hash,
        signature_algorithm="RSA-SHA256",
        signature_value=sig_val,
        public_key=keypair.public_key,
        public_key_fingerprint=pubkey_fp,
        status="SIGNED",
        signed_at=now_utc,
        download_url=f"/api/signatures/{sig_id}/download",
        package_url=package_url
    )


@router.get("/signatures/", response_model=List[CanonicalSignatureResponse])
def list_signatures(
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists signed documents. Regular signers see their own signatures;
    Analysts and Admins see all signatures across the platform.
    """
    query = db.query(SignedDocument)
    if current_user.role == "DIGITAL_SIGNATURE_USER":
        query = query.filter(SignedDocument.user_id == current_user.user_id)

    if search:
        query = query.filter(
            (SignedDocument.original_filename.ilike(f"%{search}%")) |
            (SignedDocument.signature_id.ilike(f"%{search}%")) |
            (SignedDocument.document_hash.ilike(f"%{search}%"))
        )

    docs = query.order_by(SignedDocument.created_at.desc()).limit(limit).all()

    # Pre-fetch keypairs
    user_ids = list(set(d.user_id for d in docs))
    keypairs = {kp.user_id: kp for kp in db.query(KeyPair).filter(KeyPair.user_id.in_(user_ids)).all()}

    results = []
    for d in docs:
        kp = keypairs.get(d.user_id)
        pub_key = kp.public_key if kp else None
        s_id = d.signature_id or f"QSHIELD-SIGN-{str(d.document_id).zfill(8)}"
        results.append(CanonicalSignatureResponse(
            signature_id=s_id,
            document_id=d.document_id,
            original_filename=d.original_filename,
            file_type=d.file_type or "PDF",
            hash_algorithm=d.hash_algorithm or "SHA-256",
            document_hash=d.document_hash,
            signature_algorithm=d.signature_algorithm or "RSA-SHA256",
            signature_value=d.signature_value,
            public_key=pub_key,
            public_key_fingerprint=d.public_key_fingerprint,
            status=d.status,
            signed_at=d.signed_at or d.created_at,
            download_url=f"/api/signatures/{s_id}/download",
            package_url=f"/api/signatures/{s_id}/download-package" if d.file_type != "PDF" else None
        ))
    return results


@router.get("/signatures/{signature_id}/", response_model=CanonicalSignatureResponse)
def get_signature_by_id(
    signature_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Fetches details of a specific digital signature by its readable QSHIELD-SIGN-XXXXXXXX id
    or integer document_id. Private keys are NEVER included.
    """
    query = db.query(SignedDocument).filter(
        (SignedDocument.signature_id == signature_id) |
        (SignedDocument.document_id == int(signature_id) if signature_id.isdigit() else False)
    )
    doc = query.first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Signature '{signature_id}' not found.")

    if current_user.role == "DIGITAL_SIGNATURE_USER" and doc.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied. You do not own this signature record.")

    kp = db.query(KeyPair).filter(KeyPair.user_id == doc.user_id).first()
    pub_key = kp.public_key if kp else None
    s_id = doc.signature_id or f"QSHIELD-SIGN-{str(doc.document_id).zfill(8)}"

    return CanonicalSignatureResponse(
        signature_id=s_id,
        document_id=doc.document_id,
        original_filename=doc.original_filename,
        file_type=doc.file_type or "PDF",
        hash_algorithm=doc.hash_algorithm or "SHA-256",
        document_hash=doc.document_hash,
        signature_algorithm=doc.signature_algorithm or "RSA-SHA256",
        signature_value=doc.signature_value,
        public_key=pub_key,
        public_key_fingerprint=doc.public_key_fingerprint,
        status=doc.status,
        signed_at=doc.signed_at or doc.created_at,
        download_url=f"/api/signatures/{s_id}/download",
        package_url=f"/api/signatures/{s_id}/download-package" if doc.file_type != "PDF" else None
    )


@router.get("/signatures/{signature_id}/download")
def download_signed_file(
    signature_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Downloads the signed document file."""
    query = db.query(SignedDocument).filter(
        (SignedDocument.signature_id == signature_id) |
        (SignedDocument.document_id == int(signature_id) if signature_id.isdigit() else False)
    )
    doc = query.first()
    if not doc:
        raise HTTPException(status_code=404, detail="Signature document not found.")

    target_path = Path(doc.signed_file_path or doc.file_path or doc.original_file_path)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Signed file content not found on server.")

    # Log activity
    db.add(VerificationActivity(
        user_id=current_user.user_id,
        document_hash=doc.document_hash,
        action="DOWNLOAD",
        result="SUCCESS",
        source_identifier=f"user_{current_user.user_id}"
    ))
    db.commit()

    return FileResponse(
        path=str(target_path),
        filename=f"signed_{doc.original_filename}",
        media_type="application/octet-stream"
    )


# ====================================================================
# 2. COMPLETE VERIFICATION AND ANALYSIS PIPELINES
# ====================================================================

@router.post("/analysis/upload/", response_model=CanonicalAnalysisResponse)
def upload_document_for_analysis(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """
    Initializes an analysis record from uploaded file or text,
    calculates current SHA-256 hash, detects format, and extracts initial metadata.
    """
    if not file and not raw_text:
        raise HTTPException(status_code=400, detail="No file or text provided for analysis.")

    if file:
        content_bytes = file.file.read()
        chosen_name = file.filename or "analysis_input.txt"
    else:
        content_bytes = raw_text.encode('utf-8')
        chosen_name = filename or "analysis_input.txt"

    file_id = str(uuid.uuid4())[:8]
    safe_name = Path(chosen_name).name.replace(" ", "_")
    saved_filename = f"analysis_{analyst.user_id}_{file_id}_{safe_name}"
    saved_filepath = MEDIA_ANALYSIS / saved_filename

    with open(saved_filepath, "wb") as f:
        f.write(content_bytes)

    current_hash = hashlib.sha256(content_bytes).hexdigest()
    fmt = detect_content_format(content_bytes, safe_name)
    analysis_id = generate_analysis_id()

    # Extract metadata
    extraction = extract_multiformat_signature_info(content_bytes, safe_name)
    sig_detected = extraction.get("signature_detected", False)
    sig_status = extraction.get("signature_status", "EXTRACTION_ERROR")

    analyzed_doc = AnalyzedDocument(
        analysis_id=analysis_id,
        analyst_user_id=analyst.user_id,
        original_file_name=safe_name,
        stored_file_name=saved_filename,
        file_path=str(saved_filepath),
        uploaded_file=str(saved_filepath),
        content_type=fmt,
        file_type="PDF" if fmt == ContentType.PDF else ("JSON" if fmt == ContentType.JSON else "TXT"),
        file_size=len(content_bytes),
        document_hash=current_hash,
        signature_present=sig_detected,
        signature_status=sig_status,
        signature_verified=False,
        integrity_verified=False,
        final_decision="PENDING_VERIFICATION",
        risk_score=0.0,
        risk_level="LOW"
    )
    db.add(analyzed_doc)
    db.commit()
    db.refresh(analyzed_doc)

    # Save extracted signature metadata
    db_meta = ExtractedSignatureMetadata(
        analysis_document_id=analyzed_doc.analysis_document_id,
        signature_detected=sig_detected,
        signature_status=sig_status,
        signature_algorithm=extraction.get("signature_algorithm", "Not Available"),
        hash_algorithm=extraction.get("hash_algorithm", "SHA-256"),
        signature_fingerprint=extraction.get("signature_fingerprint", "Not Available"),
        field_name=extraction.get("field_name", "Not Available"),
        signing_time=extraction.get("signing_time", None),
        certificate_subject=extraction.get("certificate_subject", "Not Available"),
        certificate_issuer=extraction.get("certificate_issuer", "Not Available"),
        certificate_fingerprint=extraction.get("certificate_fingerprint", "Not Available"),
        public_key_algorithm=extraction.get("public_key_algorithm", "RSA"),
        public_key_size=extraction.get("public_key_size", 2048),
        signer_name=extraction.get("signer_name", "Not Available"),
        signer_organization=extraction.get("signer_organization", "Not Available")
    )
    db.add(db_meta)
    db.commit()

    return CanonicalAnalysisResponse(
        analysis_id=analysis_id,
        analysis_document_id=analyzed_doc.analysis_document_id,
        signature_id=None,
        original_file_name=safe_name,
        file_type=analyzed_doc.file_type,
        current_hash=current_hash,
        stored_hash=None,
        signature_verified=False,
        integrity_verified=False,
        certificate_status="UNKNOWN",
        public_key_status="UNKNOWN",
        risk_score=0.0,
        risk_level="LOW",
        final_decision="PENDING_VERIFICATION",
        analysis_summary="Document uploaded and parsed. Ready for cryptographic verification.",
        analysed_at=analyzed_doc.analysed_at,
        threats=[]
    )


@router.post("/verify/analyze/", response_model=CanonicalAnalysisResponse)
def verify_and_analyze_canonical(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    signature: Optional[str] = Form(None),
    signature_id: Optional[str] = Form(None),
    analysis_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """
    Complete End-to-End Verification Pipeline:
    1. Reads payload, calculates current SHA-256 hash.
    2. Detects format and extracts signature metadata.
    3. Queries DB for matching SignedDocument and KeyPair.
    4. Performs real cryptographic verification with RSA public key / certificate.
    5. Checks document integrity (current hash vs stored hash).
    6. Logs VerificationActivity (action=VERIFY).
    7. Analyzes replay attacks based on recent verifications.
    8. Executes quantum-inspired security analysis.
    9. Detects threats (tampering, forgery, replay) without falsely flagging unknown signatures.
    10. Stores AnalyzedDocument with QSHIELD-ANALYSIS-XXXXXXXX and returns comprehensive report.
    """
    content_bytes = None
    safe_name = "analyzed_document.bin"

    # Step A: Resolve input bytes
    if file:
        content_bytes = file.file.read()
        safe_name = Path(file.filename or "uploaded_file.bin").name.replace(" ", "_")
    elif raw_text:
        content_bytes = raw_text.encode('utf-8')
        safe_name = filename or "raw_text_input.txt"
    elif analysis_id:
        existing = db.query(AnalyzedDocument).filter(
            (AnalyzedDocument.analysis_id == analysis_id) |
            (AnalyzedDocument.analysis_document_id == int(analysis_id) if analysis_id.isdigit() else False)
        ).first()
        if existing and Path(existing.file_path).exists():
            with open(existing.file_path, "rb") as f:
                content_bytes = f.read()
            safe_name = existing.original_file_name
    elif signature_id:
        signed_ref = db.query(SignedDocument).filter(
            (SignedDocument.signature_id == signature_id) |
            (SignedDocument.document_id == int(signature_id) if signature_id.isdigit() else False)
        ).first()
        if signed_ref:
            p = Path(signed_ref.signed_file_path or signed_ref.file_path or signed_ref.original_file_path)
            if p.exists():
                with open(p, "rb") as f:
                    content_bytes = f.read()
                safe_name = signed_ref.original_filename

    if content_bytes is None or len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid file, raw text, or document identifier must be provided for verification."
        )

    # Step B: Current SHA-256 and Format Detection
    current_hash = hashlib.sha256(content_bytes).hexdigest()
    fmt = detect_content_format(content_bytes, safe_name)
    file_type_str = "PDF" if fmt == ContentType.PDF else ("JSON" if fmt == ContentType.JSON else "TXT")

    # Step C: Extract Signature Info
    extraction = extract_multiformat_signature_info(content_bytes, safe_name)
    extracted_sig_val = extraction.get("signature_value") or extraction.get("raw_signature_b64")
    extracted_sig_id = extraction.get("signature_id") or signature_id
    sig_fp = extraction.get("signature_fingerprint", "Not Available")

    # Step D: Query DB for matching SignedDocument
    matched_doc = None
    if extracted_sig_id:
        matched_doc = db.query(SignedDocument).filter(SignedDocument.signature_id == extracted_sig_id).first()

    if not matched_doc:
        # Check by exact document hash
        matched_doc = db.query(SignedDocument).filter(SignedDocument.document_hash == current_hash).first()

    if not matched_doc and extracted_sig_val:
        matched_doc = db.query(SignedDocument).filter(SignedDocument.signature_value == extracted_sig_val).first()

    stored_hash = matched_doc.document_hash if matched_doc else None
    resolved_sig_id = matched_doc.signature_id if matched_doc else extracted_sig_id

    # Retrieve signer's public key if known
    user_pubkey_pem = None
    if matched_doc:
        kp = db.query(KeyPair).filter(KeyPair.user_id == matched_doc.user_id).first()
        if kp:
            user_pubkey_pem = kp.public_key

    # Step E: Cryptographic Verification
    sig_verified = False
    integrity_verified = False
    cert_status = "UNKNOWN"
    pubkey_status = "UNKNOWN"
    verif_details = ""
    error_details = None

    # Check for detached signature input or embedded signature
    actual_sig_input = signature or extracted_sig_val
    has_any_signature = extraction.get("signature_detected", False) or bool(actual_sig_input)

    if fmt == ContentType.PDF:
        # Save temp copy for pyhanko verification
        tmp_id = str(uuid.uuid4())[:8]
        tmp_pdf = MEDIA_ANALYSIS / f"tmp_verify_{tmp_id}.pdf"
        with open(tmp_pdf, "wb") as f:
            f.write(content_bytes)
        try:
            pdf_verifs = verify_pdf_signatures(tmp_pdf)
            first_v = pdf_verifs[0] if pdf_verifs else {}
            sig_verified = (first_v.get("verification_status") == "VALID")
            integrity_verified = (first_v.get("integrity_status") == "INTACT")
            cert_status = first_v.get("certificate_time_status", "UNKNOWN")
            pubkey_status = "VALID" if sig_verified else "UNTRUSTED"
            verif_details = first_v.get("verification_details", "")
            error_details = first_v.get("error_details")
        finally:
            if tmp_pdf.exists():
                tmp_pdf.unlink()
    elif has_any_signature:
        # Multi-format verification
        verif_list = verify_multiformat_signature(
            content_bytes=content_bytes,
            filename=safe_name,
            signature_input=actual_sig_input,
            public_key_pem=user_pubkey_pem
        )
        first_v = verif_list[0] if verif_list else {}
        is_math_valid = (first_v.get("verification_status") == "VALID")
        verif_details = first_v.get("verification_details", "")
        error_details = first_v.get("error_details")

        if is_math_valid:
            sig_verified = True
            pubkey_status = "VALID"
            cert_status = "VALID"
            # Compare hash with stored document if available
            if matched_doc:
                payload_hash = extraction.get("document_hash")
                if matched_doc.document_hash in [current_hash, payload_hash]:
                    integrity_verified = True
                else:
                    integrity_verified = False
                    verif_details += " Stored document hash mismatch: content altered after signing."
            else:
                integrity_verified = True
        else:
            # Check if signature was simply unknown vs mathematically invalid
            if not matched_doc and not user_pubkey_pem and not actual_sig_input:
                sig_verified = False
                integrity_verified = False
                pubkey_status = "PUBLIC_KEY_NOT_FOUND"
                cert_status = "NOT_AVAILABLE"
            else:
                sig_verified = False
                integrity_verified = False
                pubkey_status = "INVALID"
                cert_status = "INVALID"
    else:
        # No signature found on document
        sig_verified = False
        integrity_verified = False
        pubkey_status = "PUBLIC_KEY_NOT_FOUND"
        cert_status = "NOT_AVAILABLE"
        verif_details = "Document contains no embedded or detached signature."

    # Step F: Integrity check against stored record
    if matched_doc:
        payload_hash = extraction.get("document_hash")
        if matched_doc.document_hash in [current_hash, payload_hash] and sig_verified:
            integrity_verified = True
        elif matched_doc.document_hash not in [current_hash, payload_hash]:
            integrity_verified = False

    # Step G: Log VerificationActivity (action=VERIFY)
    now_utc = datetime.now(timezone.utc)
    v_act = VerificationActivity(
        user_id=analyst.user_id,
        document_hash=current_hash,
        signature_fingerprint=sig_fp if sig_fp != "Not Available" else None,
        action="VERIFY",
        result="SUCCESS" if (sig_verified and integrity_verified) else "FAIL",
        source_identifier=f"analyst_{analyst.user_id}",
        metadata_json=json.dumps({"filename": safe_name, "signature_id": resolved_sig_id})
    )
    db.add(v_act)
    db.commit()

    # Step H: Check Replay Suspicion
    replay_analysis = analyze_replay_suspicion(
        db,
        document_hash=current_hash,
        signature_fingerprint=sig_fp,
        time_window_minutes=REPLAY_WINDOW_MINUTES
    )
    is_replay = (
        replay_analysis.get("replay_classification") in ["SUSPICIOUS_REPLAY", "HIGH_REPLAY_SUSPICION"] or
        replay_analysis.get("total_verification_count", 0) >= REPLAY_THRESHOLD_COUNT
    )

    # Step I: Quantum-Inspired Security Analysis
    meta_dict = {
        "signature_detected": has_any_signature,
        "signature_status": "VALID" if sig_verified else ("UNKNOWN" if not has_any_signature else "INVALID"),
        "signature_algorithm": "RSA-SHA256",
        "public_key_size": 2048
    }
    verif_sim = [{
        "verification_status": "VALID" if sig_verified else "INVALID",
        "integrity_status": "INTACT" if integrity_verified else "MODIFIED",
        "certificate_time_status": cert_status
    }]
    quantum_res = analyze_quantum_security_state(meta_dict, verif_sim)

    # Step J: Determine Final Decision, Risk Score, and Threat Incidents
    threats: List[ThreatIncident] = []
    final_decision = "REQUIRES_CAUTION"
    risk_score = 15.0
    risk_level = "LOW"
    summary_reasons = []

    # Save AnalyzedDocument record
    analysis_uuid = generate_analysis_id()
    saved_name = f"verify_{analyst.user_id}_{str(uuid.uuid4())[:8]}_{safe_name}"
    saved_path = MEDIA_ANALYSIS / saved_name
    with open(saved_path, "wb") as f:
        f.write(content_bytes)

    analyzed_doc = AnalyzedDocument(
        analysis_id=analysis_uuid,
        signature_id=resolved_sig_id,
        analyst_user_id=analyst.user_id,
        original_file_name=safe_name,
        stored_file_name=saved_name,
        file_path=str(saved_path),
        uploaded_file=str(saved_path),
        content_type=fmt,
        file_type=file_type_str,
        file_size=len(content_bytes),
        document_hash=current_hash,
        signature_present=has_any_signature,
        signature_status="VALID" if sig_verified else ("UNKNOWN_SIGNATURE" if not has_any_signature else "INVALID_SIGNATURE"),
        signature_verified=sig_verified,
        integrity_verified=integrity_verified,
        certificate_status=cert_status,
        public_key_status=pubkey_status,
        analysed_at=now_utc
    )
    db.add(analyzed_doc)
    db.commit()
    db.refresh(analyzed_doc)

    # 1. Check Document Tampering: Signature present but hash mismatch
    payload_hash = extraction.get("document_hash")
    if has_any_signature and matched_doc and (matched_doc.document_hash not in [current_hash, payload_hash] or not integrity_verified):
        final_decision = "INTEGRITY_MISMATCH"
        risk_score = max(risk_score, 88.0)
        risk_level = "CRITICAL"
        desc = f"Document content altered after signing! Original hash {matched_doc.document_hash[:12]}... does not match current hash {current_hash[:12]}..."
        summary_reasons.append(desc)
        threats.append(ThreatIncident(
            analysis_document_id=analyzed_doc.analysis_document_id,
            threat_category="DOCUMENT_TAMPERING",
            threat_type="DOCUMENT_TAMPERING",
            confidence=0.95,
            severity="CRITICAL",
            threat_score=95.0,
            threat_status="OPEN",
            description=desc,
            evidence_data=json.dumps({"original_hash": matched_doc.document_hash, "current_hash": current_hash})
        ))

    # 2. Check Cryptographic Forgery: Signature present and verification actually failed
    elif has_any_signature and not sig_verified and (matched_doc or user_pubkey_pem or actual_sig_input):
        final_decision = "INVALID_SIGNATURE"
        risk_score = max(risk_score, 90.0)
        risk_level = "CRITICAL"
        desc = "Cryptographic signature verification mathematically failed. Invalid signature value or corrupted signature block."
        summary_reasons.append(desc)
        threats.append(ThreatIncident(
            analysis_document_id=analyzed_doc.analysis_document_id,
            threat_category="FORGERY",
            threat_type="FORGERY",
            confidence=0.92,
            severity="CRITICAL",
            threat_score=92.0,
            threat_status="OPEN",
            description=desc,
            evidence_data=json.dumps({"verification_details": verif_details, "error": error_details})
        ))

    # 3. Check Unknown Signature: Not in database, no public key available
    elif not has_any_signature or (not matched_doc and not user_pubkey_pem and not sig_verified):
        # Per specification: Unknown signature must NOT be automatically flagged as forgery!
        final_decision = "UNKNOWN_SIGNATURE" if not has_any_signature else "PUBLIC_KEY_NOT_FOUND"
        risk_score = 30.0
        risk_level = "MEDIUM"
        desc = "Document signature is untracked or missing. No cryptographic forgery detected; signature could not be verified."
        summary_reasons.append(desc)

    # 4. Valid Signature
    elif sig_verified and integrity_verified:
        final_decision = "VALID"
        risk_score = 10.0
        risk_level = "LOW"
        summary_reasons.append("Cryptographic digital signature and document integrity verified successfully.")

    # 5. Check Replay Attack
    if is_replay:
        risk_score = min(100.0, risk_score + 35.0)
        if risk_level != "CRITICAL":
            risk_level = "HIGH"
        replay_desc = (
            f"Replay attack pattern detected: document verified {replay_analysis.get('total_verification_count')} times "
            f"within {REPLAY_WINDOW_MINUTES} minutes (Replay score: {replay_analysis.get('replay_suspicion_score', 80.0)}/100)."
        )
        summary_reasons.append(replay_desc)
        threats.append(ThreatIncident(
            analysis_document_id=analyzed_doc.analysis_document_id,
            threat_category="REPLAY_ATTACK",
            threat_type="REPLAY_ATTACK",
            confidence=0.85,
            severity="HIGH",
            threat_score=float(replay_analysis.get("replay_suspicion_score", 80.0)),
            threat_status="OPEN",
            description=replay_desc,
            evidence_data=json.dumps(replay_analysis)
        ))

    # Commit threats
    if threats:
        db.add_all(threats)

    # Update AnalyzedDocument
    analyzed_doc.risk_score = risk_score
    analyzed_doc.risk_level = risk_level
    analyzed_doc.final_decision = final_decision
    analyzed_doc.analysis_summary = " | ".join(summary_reasons)
    db.commit()
    db.refresh(analyzed_doc)

    # Convert threats for schema response
    threat_summaries = [
        CanonicalThreatSummary(
            incident_id=t.incident_id,
            threat_category=t.threat_category,
            threat_type=t.threat_type or t.threat_category,
            severity=t.severity,
            threat_score=t.threat_score,
            threat_status=t.threat_status,
            description=t.description
        )
        for t in threats
    ]

    return CanonicalAnalysisResponse(
        analysis_id=analyzed_doc.analysis_id,
        analysis_document_id=analyzed_doc.analysis_document_id,
        signature_id=resolved_sig_id,
        original_file_name=safe_name,
        file_type=file_type_str,
        current_hash=current_hash,
        stored_hash=stored_hash,
        signature_verified=sig_verified,
        integrity_verified=integrity_verified,
        certificate_status=cert_status,
        public_key_status=pubkey_status,
        risk_score=risk_score,
        risk_level=risk_level,
        final_decision=final_decision,
        analysis_summary=analyzed_doc.analysis_summary,
        analysed_at=analyzed_doc.analysed_at,
        threats=threat_summaries,
        quantum_metrics=quantum_res,
        verification_details=verif_details
    )


@router.get("/analysis/history/", response_model=List[CanonicalAnalysisResponse])
def get_analysis_history(
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    decision: Optional[str] = None,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """Lists historical document security analyses."""
    query = db.query(AnalyzedDocument)
    if search:
        query = query.filter(
            (AnalyzedDocument.original_file_name.ilike(f"%{search}%")) |
            (AnalyzedDocument.analysis_id.ilike(f"%{search}%")) |
            (AnalyzedDocument.document_hash.ilike(f"%{search}%"))
        )
    if decision:
        query = query.filter(AnalyzedDocument.final_decision == decision)

    docs = query.order_by(AnalyzedDocument.created_at.desc()).limit(limit).all()

    results = []
    for d in docs:
        t_list = [
            CanonicalThreatSummary(
                incident_id=t.incident_id,
                threat_category=t.threat_category,
                threat_type=t.threat_type or t.threat_category,
                severity=t.severity,
                threat_score=t.threat_score,
                threat_status=t.threat_status,
                description=t.description
            )
            for t in (d.threat_incidents or [])
        ]
        results.append(CanonicalAnalysisResponse(
            analysis_id=d.analysis_id or f"QSHIELD-ANALYSIS-{str(d.analysis_document_id).zfill(8)}",
            analysis_document_id=d.analysis_document_id,
            signature_id=d.signature_id,
            original_file_name=d.original_file_name,
            file_type=d.file_type or "PDF",
            current_hash=d.document_hash,
            stored_hash=None,
            signature_verified=bool(d.signature_verified),
            integrity_verified=bool(d.integrity_verified),
            certificate_status=d.certificate_status or "UNKNOWN",
            public_key_status=d.public_key_status or "UNKNOWN",
            risk_score=d.risk_score or 0.0,
            risk_level=d.risk_level or "LOW",
            final_decision=d.final_decision or "REQUIRES_CAUTION",
            analysis_summary=d.analysis_summary,
            analysed_at=d.analysed_at or d.created_at,
            threats=t_list
        ))
    return results


@router.get("/analysis/{analysis_id}/", response_model=CanonicalAnalysisResponse)
def get_analysis_by_id(
    analysis_id: str,
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """Fetches details of a specific analysis record by readable analysis_id or numeric id."""
    query = db.query(AnalyzedDocument).filter(
        (AnalyzedDocument.analysis_id == analysis_id) |
        (AnalyzedDocument.analysis_document_id == int(analysis_id) if analysis_id.isdigit() else False)
    )
    doc = query.first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")

    t_list = [
        CanonicalThreatSummary(
            incident_id=t.incident_id,
            threat_category=t.threat_category,
            threat_type=t.threat_type or t.threat_category,
            severity=t.severity,
            threat_score=t.threat_score,
            threat_status=t.threat_status,
            description=t.description
        )
        for t in (doc.threat_incidents or [])
    ]

    return CanonicalAnalysisResponse(
        analysis_id=doc.analysis_id or f"QSHIELD-ANALYSIS-{str(doc.analysis_document_id).zfill(8)}",
        analysis_document_id=doc.analysis_document_id,
        signature_id=doc.signature_id,
        original_file_name=doc.original_file_name,
        file_type=doc.file_type or "PDF",
        current_hash=doc.document_hash,
        stored_hash=None,
        signature_verified=bool(doc.signature_verified),
        integrity_verified=bool(doc.integrity_verified),
        certificate_status=doc.certificate_status or "UNKNOWN",
        public_key_status=doc.public_key_status or "UNKNOWN",
        risk_score=doc.risk_score or 0.0,
        risk_level=doc.risk_level or "LOW",
        final_decision=doc.final_decision or "REQUIRES_CAUTION",
        analysis_summary=doc.analysis_summary,
        analysed_at=doc.analysed_at or doc.created_at,
        threats=t_list
    )


# ====================================================================
# 3. THREATS AND PLATFORM STATISTICS
# ====================================================================

@router.get("/threats/", response_model=List[CanonicalThreatSummary])
def list_threat_incidents(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    threat_status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """Lists threat incidents detected across historical document verifications."""
    query = db.query(ThreatIncident)
    if category:
        query = query.filter(
            (ThreatIncident.threat_category == category) |
            (ThreatIncident.threat_type == category)
        )
    if severity:
        query = query.filter(ThreatIncident.severity == severity)
    if threat_status:
        query = query.filter(ThreatIncident.threat_status == threat_status)

    incidents = query.order_by(ThreatIncident.detected_at.desc()).limit(limit).all()
    return [
        CanonicalThreatSummary(
            incident_id=t.incident_id,
            threat_category=t.threat_category,
            threat_type=t.threat_type or t.threat_category,
            severity=t.severity,
            threat_score=t.threat_score,
            threat_status=t.threat_status,
            description=t.description
        )
        for t in incidents
    ]


@router.get("/statistics/", response_model=PlatformStatisticsSummary)
def get_platform_statistics(
    db: Session = Depends(get_db),
    analyst: User = Depends(require_analyst_or_admin)
):
    """
    Computes global platform statistics:
    total signatures, verifications, threats detected, valid vs tampered signatures,
    replay attacks detected, and average risk score.
    """
    total_signatures = db.query(SignedDocument).count()
    total_verifications = db.query(VerificationActivity).filter(VerificationActivity.action == "VERIFY").count()
    if total_verifications == 0:
        total_verifications = db.query(AnalyzedDocument).count()

    total_threats = db.query(ThreatIncident).count()

    valid_signatures = db.query(AnalyzedDocument).filter(
        AnalyzedDocument.final_decision == "VALID"
    ).count()

    tampered_signatures = db.query(AnalyzedDocument).filter(
        (AnalyzedDocument.final_decision == "INTEGRITY_MISMATCH") |
        (AnalyzedDocument.final_decision == "INVALID_SIGNATURE")
    ).count()

    replay_attacks = db.query(ThreatIncident).filter(
        (ThreatIncident.threat_category.in_(["REPLAY_ATTACK", "REPLAY_SUSPECTED"])) |
        (ThreatIncident.threat_type == "REPLAY_ATTACK")
    ).count()

    avg_score_res = db.query(func.avg(AnalyzedDocument.risk_score)).scalar()
    avg_risk_score = round(float(avg_score_res or 0.0), 2)

    return PlatformStatisticsSummary(
        total_signatures=total_signatures,
        total_verifications=total_verifications,
        total_threats_detected=total_threats,
        valid_signatures=valid_signatures,
        tampered_signatures=tampered_signatures,
        replay_attacks_detected=replay_attacks,
        average_risk_score=avg_risk_score
    )
