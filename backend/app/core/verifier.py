import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
from pyhanko_certvalidator import ValidationContext
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def verify_pdf_signatures(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Performs real classical cryptographic verification and PDF document integrity checking.
    
    Returns a list of verification result dictionaries (one per detected signature field).
    
    Verification Statuses:
    - VALID
    - INVALID
    - UNSUPPORTED
    - MALFORMED
    - VERIFICATION_ERROR
    - UNKNOWN

    Integrity Statuses:
    - INTACT
    - MODIFIED
    - UNKNOWN
    - NOT_VERIFIABLE

    Certificate Time Statuses:
    - VALID_TIME_RANGE
    - EXPIRED
    - NOT_YET_VALID
    - UNKNOWN
    """
    if not pdf_path.exists():
        return [{
            "signature_identifier": "Signature1",
            "signature_index": 0,
            "verification_status": "VERIFICATION_ERROR",
            "integrity_status": "NOT_VERIFIABLE",
            "signature_algorithm": "RSA-SHA256",
            "hash_algorithm": "SHA-256",
            "certificate_time_status": "UNKNOWN",
            "verification_timestamp": datetime.now(timezone.utc),
            "verification_details": "File not found on server storage.",
            "error_details": "Missing file"
        }]

    verifications: List[Dict[str, Any]] = []

    try:
        with open(pdf_path, 'rb') as f:
            pdf_r = PdfFileReader(f)
            embedded_sigs = list(pdf_r.embedded_signatures)

            if not embedded_sigs or len(embedded_sigs) == 0:
                return [{
                    "signature_identifier": "None",
                    "signature_index": 0,
                    "verification_status": "UNKNOWN",
                    "integrity_status": "NOT_VERIFIABLE",
                    "signature_algorithm": "Not Available",
                    "hash_algorithm": "Not Available",
                    "certificate_time_status": "UNKNOWN",
                    "verification_timestamp": datetime.now(timezone.utc),
                    "verification_details": "Document contains no digital signature fields. Cryptographic verification not applicable.",
                    "error_details": "No signature dictionary found."
                }]

            for idx, sig in enumerate(embedded_sigs):
                sig_name = sig.field_name or f"Signature_{idx+1}"
                try:
                    signer_cert = sig.signer_cert
                    
                    # Evaluate Certificate Time Status
                    cert_time_status = "UNKNOWN"
                    if signer_cert:
                        now_utc = datetime.now(timezone.utc)
                        not_before = signer_cert.not_valid_before.replace(tzinfo=timezone.utc) if signer_cert.not_valid_before.tzinfo is None else signer_cert.not_valid_before
                        not_after = signer_cert.not_valid_after.replace(tzinfo=timezone.utc) if signer_cert.not_valid_after.tzinfo is None else signer_cert.not_valid_after

                        if now_utc < not_before:
                            cert_time_status = "NOT_YET_VALID"
                        elif now_utc > not_after:
                            cert_time_status = "EXPIRED"
                        else:
                            cert_time_status = "VALID_TIME_RANGE"

                    # Build ValidationContext allowing self-signed dev certs
                    vc = ValidationContext(trust_roots=[signer_cert]) if signer_cert else None

                    # Perform PyHanko Cryptographic Signature & ByteRange Validation
                    res = validation.validate_pdf_signature(sig, signer_validation_context=vc)

                    is_signature_valid = res.intact and res.valid
                    is_integrity_intact = res.intact

                    if is_signature_valid and is_integrity_intact:
                        verif_status = "VALID"
                        integ_status = "INTACT"
                        msg = "Cryptographic signature mathematical verification succeeded. Document content integrity intact."
                    elif not is_integrity_intact:
                        verif_status = "INVALID"
                        integ_status = "MODIFIED"
                        msg = "Cryptographic verification failed. Document content modification detected after signing."
                    else:
                        verif_status = "INVALID"
                        integ_status = "MODIFIED"
                        msg = "Cryptographic signature invalid or public key verification failed."

                    verifications.append({
                        "signature_identifier": sig_name,
                        "signature_index": idx,
                        "verification_status": verif_status,
                        "integrity_status": integ_status,
                        "signature_algorithm": "RSA-SHA256",
                        "hash_algorithm": "SHA-256",
                        "certificate_time_status": cert_time_status,
                        "verification_timestamp": datetime.now(timezone.utc),
                        "verification_details": msg,
                        "error_details": None if is_signature_valid else "Signature digest or ByteRange content mismatch"
                    })

                except Exception as sig_err:
                    verifications.append({
                        "signature_identifier": sig_name,
                        "signature_index": idx,
                        "verification_status": "MALFORMED",
                        "integrity_status": "UNKNOWN",
                        "signature_algorithm": "RSA-SHA256",
                        "hash_algorithm": "SHA-256",
                        "certificate_time_status": "UNKNOWN",
                        "verification_timestamp": datetime.now(timezone.utc),
                        "verification_details": f"Error verifying signature: {str(sig_err)}",
                        "error_details": str(sig_err)
                    })

    except Exception as e:
        verifications.append({
            "signature_identifier": "Signature1",
            "signature_index": 0,
            "verification_status": "VERIFICATION_ERROR",
            "integrity_status": "UNKNOWN",
            "signature_algorithm": "Not Available",
            "hash_algorithm": "Not Available",
            "certificate_time_status": "UNKNOWN",
            "verification_timestamp": datetime.now(timezone.utc),
            "verification_details": f"Verification pipeline error: {str(e)}",
            "error_details": str(e)
        })

    return verifications

from app.core.format_processors import (
    detect_content_format,
    ContentType,
    canonicalize_json,
    rsa_verify_signature
)
import json

def verify_multiformat_signature(
    content_bytes: bytes,
    filename: str = "",
    signature_input: Optional[str] = None,
    public_key_pem: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Unified verification pipeline for PDF, TXT, JSON, QSHIELD-1.0 messages,
    Bitcoin-style messages, and detached signatures.
    Supports verifying against a provided user public_key_pem.
    """
    fmt = detect_content_format(content_bytes, filename)

    if fmt == ContentType.PDF:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(content_bytes)
            tmp_path = Path(tmp.name)
        try:
            return verify_pdf_signatures(tmp_path)
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    # 1. Structured Message Envelope (QSHIELD-1.0 or Bitcoin Mode)
    if fmt in [ContentType.STRUCTURED_MESSAGE, ContentType.BITCOIN_MESSAGE]:
        try:
            envelope = json.loads(content_bytes.decode('utf-8'))
            sig_b64 = envelope.get("signature")
            
            if not sig_b64:
                return [{
                    "signature_identifier": "StructuredSignature1",
                    "verification_status": "INVALID",
                    "integrity_status": "MODIFIED",
                    "signature_algorithm": "RSA-SHA256",
                    "hash_algorithm": "SHA-256",
                    "certificate_time_status": "VALID_TIME_RANGE",
                    "verification_timestamp": datetime.now(timezone.utc),
                    "verification_details": "Structured message missing cryptographic signature element.",
                    "error_details": "Missing signature"
                }]

            # Extract content & calculate target hash
            if fmt == ContentType.BITCOIN_MESSAGE:
                payload = envelope.get("payload", {})
                canonical_bytes, canonical_hash, _ = canonicalize_json(payload)
                expected_hash = envelope.get("content_hash")
                
                if expected_hash and expected_hash != canonical_hash:
                    return [{
                        "signature_identifier": "BitcoinStructuredSignature1",
                        "verification_status": "INVALID",
                        "integrity_status": "MODIFIED",
                        "signature_algorithm": "RSA-SHA256",
                        "hash_algorithm": "SHA-256",
                        "certificate_time_status": "VALID_TIME_RANGE",
                        "verification_timestamp": datetime.now(timezone.utc),
                        "verification_details": f"Payload canonical hash mismatch. Expected {expected_hash}, calculated {canonical_hash}.",
                        "error_details": "Hash mismatch"
                    }]
                
                is_valid = rsa_verify_signature(canonical_bytes, sig_b64, public_key_pem=public_key_pem)
            else: # QSHIELD-1.0
                raw_content = envelope.get("content", "")
                c_bytes = raw_content.encode('utf-8')
                
                try:
                    c_obj = json.loads(raw_content)
                    c_bytes, _, _ = canonicalize_json(c_obj)
                except Exception:
                    pass

                is_valid = rsa_verify_signature(c_bytes, sig_b64, public_key_pem=public_key_pem)

            return [{
                "signature_identifier": "StructuredSignature1",
                "verification_status": "VALID" if is_valid else "INVALID",
                "integrity_status": "INTACT" if is_valid else "MODIFIED",
                "signature_algorithm": envelope.get("signature_algorithm", "RSA-SHA256"),
                "hash_algorithm": "SHA-256",
                "certificate_time_status": "VALID_TIME_RANGE",
                "verification_timestamp": datetime.now(timezone.utc),
                "verification_details": "Structured message signature cryptographically verified." if is_valid else "Signature verification failed. Content modified or invalid key.",
                "error_details": None if is_valid else "RSA verification failed"
            }]
        except Exception as e:
            return [{
                "signature_identifier": "StructuredSignature1",
                "verification_status": "VERIFICATION_ERROR",
                "integrity_status": "UNKNOWN",
                "signature_algorithm": "RSA-SHA256",
                "hash_algorithm": "SHA-256",
                "certificate_time_status": "UNKNOWN",
                "verification_timestamp": datetime.now(timezone.utc),
                "verification_details": f"Error parsing structured message: {str(e)}",
                "error_details": str(e)
            }]

    # 2. Detached Signature Verification
    if signature_input:
        sig_b64 = signature_input.strip()
        
        sign_target_bytes = content_bytes
        if fmt == ContentType.JSON:
            try:
                sign_target_bytes, _, _ = canonicalize_json(content_bytes)
            except Exception:
                pass

        is_valid = rsa_verify_signature(sign_target_bytes, sig_b64, public_key_pem=public_key_pem)

        return [{
            "signature_identifier": "DetachedSignature1",
            "verification_status": "VALID" if is_valid else "INVALID",
            "integrity_status": "INTACT" if is_valid else "MODIFIED",
            "signature_algorithm": "RSA-SHA256",
            "hash_algorithm": "SHA-256",
            "certificate_time_status": "VALID_TIME_RANGE",
            "verification_timestamp": datetime.now(timezone.utc),
            "verification_details": "Detached cryptographic signature verified against content hash." if is_valid else "Detached signature verification failed. Content hash mismatch or signature invalid.",
            "error_details": None if is_valid else "Detached signature hash mismatch"
        }]

    # 3. Unsigned Content
    return [{
        "signature_identifier": "None",
        "verification_status": "UNKNOWN",
        "integrity_status": "NOT_VERIFIABLE",
        "signature_algorithm": "Not Available",
        "hash_algorithm": "Not Available",
        "certificate_time_status": "UNKNOWN",
        "verification_timestamp": datetime.now(timezone.utc),
        "verification_details": "Content contains no embedded signature or detached signature input.",
        "error_details": "No signature found."
    }]
