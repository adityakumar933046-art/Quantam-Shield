import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.core.cert_manager import get_or_create_dev_credentials, PRIVATE_KEY_PATH, CERTIFICATE_PATH

# PyHanko for PDF digital signature embedding
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import SigFieldSpec

from app.core.format_processors import (
    ContentType,
    canonicalize_json,
    format_qshield_signed_message,
    rsa_sign_hash_bytes
)
import json

def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def sign_pdf_document(input_pdf_path: Path, output_pdf_path: Path) -> dict:
    """
    Applies a real cryptographic digital signature (PKCS#7 / CMS) to a PDF document using
    the development RSA-2048 key pair and X.509 certificate.
    """
    if not input_pdf_path.exists():
        raise FileNotFoundError(f"Input PDF not found: {input_pdf_path}")

    # 1. Get dev credentials
    private_key, cert, cert_bytes = get_or_create_dev_credentials()

    # 2. Compute SHA-256 Hash of original document
    original_hash = compute_sha256(input_pdf_path)

    # 3. Prepare PyHanko SimpleSigner using PEM credentials
    signer = signers.SimpleSigner.load(
        key_file=str(PRIVATE_KEY_PATH),
        cert_file=str(CERTIFICATE_PATH),
        key_passphrase=None
    )

    # 4. Perform PDF incremental write & digital signature embedding
    with open(input_pdf_path, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        # Add a digital signature field spec
        fields.append_signature_field(
            w, sig_field_spec=SigFieldSpec(sig_field_name='QSHIELD_Signature1')
        )
        
        with open(output_pdf_path, 'wb') as outf:
            meta = signers.PdfSignatureMetadata(field_name='QSHIELD_Signature1', reason='Q-SHIELD Cryptographic Digital Signature')
            pdf_signer = signers.PdfSigner(meta, signer=signer)
            pdf_signer.sign_pdf(w, output=outf)

    # 5. Extract metadata from Certificate & Signature
    cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    signed_hash = compute_sha256(output_pdf_path)
    
    # Compute signature fingerprint from output signed bytes difference or cert
    sig_fingerprint = hashlib.sha256(signed_hash.encode()).hexdigest()

    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    serial_str = str(cert.serial_number)
    signing_time = datetime.now(timezone.utc)

    return {
        "original_hash": original_hash,
        "signed_hash": signed_hash,
        "signature_algorithm": "RSA-SHA256",
        "hash_algorithm": "SHA-256",
        "certificate_subject": subject_str,
        "certificate_issuer": issuer_str,
        "certificate_serial_number": serial_str,
        "certificate_fingerprint": cert_fingerprint,
        "signature_fingerprint": sig_fingerprint,
        "signing_timestamp": signing_time,
        "file_size": os.path.getsize(output_pdf_path),
        "content_type": ContentType.PDF
    }

def sign_text_content(text_content: str, filename: str = "signed_message.txt") -> dict:
    content_bytes = text_content.encode('utf-8')
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(content_bytes)
    
    _, cert, _ = get_or_create_dev_credentials()
    
    signed_json = format_qshield_signed_message(
        content=text_content,
        content_hash=content_hash,
        signature_b64=sig_b64,
        pubkey_fingerprint=cert_fp,
        content_type="text/plain"
    )
    
    return {
        "content_type": ContentType.TEXT,
        "original_filename": filename,
        "original_hash": content_hash,
        "signed_hash": content_hash,
        "canonical_hash": content_hash,
        "signature_algorithm": "RSA-SHA256",
        "hash_algorithm": "SHA-256",
        "signature_value": sig_b64,
        "certificate_subject": cert.subject.rfc4514_string(),
        "certificate_issuer": cert.issuer.rfc4514_string(),
        "certificate_serial_number": str(cert.serial_number),
        "certificate_fingerprint": cert_fp,
        "signature_fingerprint": sig_fp,
        "signing_timestamp": datetime.now(timezone.utc),
        "signed_message_json": signed_json,
        "raw_text_content": text_content,
        "file_size": len(content_bytes)
    }

def sign_json_content(json_input: Any, filename: str = "signed_data.json", canonicalize: bool = True) -> dict:
    if isinstance(json_input, str):
        content_bytes = json_input.encode('utf-8')
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
    else:
        content_bytes = json.dumps(json_input).encode('utf-8')
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        
    canonical_bytes, canonical_hash, parsed_obj = canonicalize_json(json_input)
    sign_target_bytes = canonical_bytes if canonicalize else content_bytes
    
    sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(sign_target_bytes)
    _, cert, _ = get_or_create_dev_credentials()
    
    signed_json = format_qshield_signed_message(
        content=json.dumps(parsed_obj),
        content_hash=canonical_hash if canonicalize else raw_hash,
        signature_b64=sig_b64,
        pubkey_fingerprint=cert_fp,
        content_type="application/json"
    )
    
    return {
        "content_type": ContentType.JSON,
        "original_filename": filename,
        "original_hash": raw_hash,
        "signed_hash": canonical_hash if canonicalize else raw_hash,
        "canonical_hash": canonical_hash,
        "signature_algorithm": "RSA-SHA256",
        "hash_algorithm": "SHA-256",
        "signature_value": sig_b64,
        "certificate_subject": cert.subject.rfc4514_string(),
        "certificate_issuer": cert.issuer.rfc4514_string(),
        "certificate_serial_number": str(cert.serial_number),
        "certificate_fingerprint": cert_fp,
        "signature_fingerprint": sig_fp,
        "signing_timestamp": datetime.now(timezone.utc),
        "signed_message_json": signed_json,
        "raw_text_content": json.dumps(parsed_obj, indent=2),
        "file_size": len(content_bytes)
    }

def sign_structured_message(sender: str, receiver: str, message: str, amount_data: str = "", nonce: str = "") -> dict:
    if not nonce:
        import uuid
        nonce = uuid.uuid4().hex[:12]
        
    timestamp_str = datetime.now(timezone.utc).isoformat()
    
    payload = {
        "sender": sender,
        "receiver": receiver,
        "message": message,
        "amount_data": amount_data,
        "nonce": nonce,
        "timestamp": timestamp_str
    }
    
    canonical_bytes, canonical_hash, parsed_payload = canonicalize_json(payload)
    sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(canonical_bytes)
    _, cert, _ = get_or_create_dev_credentials()
    
    signed_structure = {
        "format_version": "QSHIELD-BITCOIN-MODE-1.0",
        "content_type": "application/json-structured",
        "payload": parsed_payload,
        "content_hash": canonical_hash,
        "signature_algorithm": "RSA-SHA256",
        "signature": sig_b64,
        "public_key_fingerprint": cert_fp,
        "signing_timestamp": timestamp_str
    }
    
    signed_json = json.dumps(signed_structure, indent=2)
    
    return {
        "content_type": ContentType.BITCOIN_MESSAGE,
        "original_filename": f"msg_{nonce}.json",
        "original_hash": canonical_hash,
        "signed_hash": canonical_hash,
        "canonical_hash": canonical_hash,
        "signature_algorithm": "RSA-SHA256",
        "hash_algorithm": "SHA-256",
        "signature_value": sig_b64,
        "certificate_subject": cert.subject.rfc4514_string(),
        "certificate_issuer": cert.issuer.rfc4514_string(),
        "certificate_serial_number": str(cert.serial_number),
        "certificate_fingerprint": cert_fp,
        "signature_fingerprint": sig_fp,
        "signing_timestamp": datetime.now(timezone.utc),
        "signed_message_json": signed_json,
        "raw_text_content": signed_json,
        "nonce": nonce,
        "file_size": len(signed_json.encode('utf-8'))
    }
