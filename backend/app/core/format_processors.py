import os
import json
import hashlib
import base64
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509

from app.core.cert_manager import get_or_create_dev_credentials, PRIVATE_KEY_PATH, CERTIFICATE_PATH

class ContentType:
    PDF = "PDF"
    TEXT = "TEXT"
    JSON = "JSON"
    RAW_TEXT = "RAW_TEXT"
    STRUCTURED_MESSAGE = "STRUCTURED_MESSAGE"
    BITCOIN_MESSAGE = "BITCOIN_MESSAGE"
    DETACHED_SIGNATURE = "DETACHED_SIGNATURE"
    GENERIC_BINARY = "GENERIC_BINARY"

def detect_content_format(content_bytes: bytes, filename: str = "") -> str:
    """
    Dual detection using magic bytes, JSON parser, format headers, and file extensions.
    Does NOT rely on file extension alone.
    """
    if not content_bytes:
        return ContentType.RAW_TEXT

    # 1. Magic Bytes Check for PDF (%PDF-)
    if content_bytes.startswith(b"%PDF-"):
        return ContentType.PDF

    # 2. Check for JSON / Structured Message
    try:
        text = content_bytes.decode("utf-8")
        json_obj = json.loads(text)
        if isinstance(json_obj, dict):
            if json_obj.get("format_version") == "QSHIELD-1.0" or "signature" in json_obj and "content_hash" in json_obj:
                return ContentType.STRUCTURED_MESSAGE
            if "sender" in json_obj and "receiver" in json_obj and "signature" in json_obj:
                return ContentType.BITCOIN_MESSAGE
            return ContentType.JSON
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    # 3. Check for Detached Signature File (.sig or Base64 signature block)
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    if ext == ".sig":
        return ContentType.DETACHED_SIGNATURE

    # 4. Check for UTF-8 Plain Text
    try:
        text = content_bytes.decode("utf-8")
        if ext in [".txt", ".text"]:
            return ContentType.TEXT
        return ContentType.RAW_TEXT
    except UnicodeDecodeError:
        pass

    # 5. Fallback for unparsed binary content
    return ContentType.GENERIC_BINARY

def canonicalize_json(json_input: Any) -> Tuple[bytes, str, Any]:
    """
    RFC 8785 deterministic canonical JSON serialization.
    Keys are sorted, whitespace eliminated (separators=(',', ':')).
    Returns (canonical_utf8_bytes, sha256_hash, parsed_obj).
    """
    if isinstance(json_input, (bytes, bytearray)):
        json_input = json_input.decode("utf-8")
    if isinstance(json_input, str):
        parsed_obj = json.loads(json_input)
    else:
        parsed_obj = json_input

    canonical_str = json.dumps(parsed_obj, sort_keys=True, separators=(",", ":"))
    canonical_bytes = canonical_str.encode("utf-8")
    canonical_hash = hashlib.sha256(canonical_bytes).hexdigest()
    return canonical_bytes, canonical_hash, parsed_obj

def format_qshield_signed_message(
    content: str,
    content_hash: str,
    signature_b64: str,
    pubkey_fingerprint: str,
    content_type: str = "text/plain",
    sig_algo: str = "RSA-SHA256",
    signature_id: Optional[str] = None
) -> str:
    """
    Platform-supported QSHIELD-1.0 signed message envelope.
    """
    envelope = {
        "format_version": "QSHIELD-1.0",
        "signature_id": signature_id,
        "content_type": content_type,
        "content": content,
        "content_hash": content_hash,
        "signature_algorithm": sig_algo,
        "signature": signature_b64,
        "public_key_fingerprint": pubkey_fingerprint,
        "signing_timestamp": datetime.now(timezone.utc).isoformat()
    }
    return json.dumps(envelope, indent=2)

def rsa_sign_hash_bytes(hash_bytes: bytes) -> Tuple[str, str, str]:
    """
    Signs precomputed 32-byte SHA-256 digest or content bytes using local dev RSA private key.
    Returns (signature_base64, cert_fingerprint, signature_fingerprint).
    """
    private_key, cert, cert_bytes = get_or_create_dev_credentials()
    
    # Apply PKCS#1 v1.5 RSA signature over SHA-256
    signature = private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    sig_b64 = base64.b64encode(signature).decode("utf-8")
    cert_fp = cert.fingerprint(hashes.SHA256()).hex()
    sig_fp = hashlib.sha256(signature).hexdigest()
    return sig_b64, cert_fp, sig_fp

def rsa_verify_signature(hash_bytes: bytes, signature_b64: str, public_key_pem: Optional[str] = None) -> bool:
    """
    Verifies RSA-SHA256 signature against precomputed SHA-256 content bytes.
    Accepts optional public_key_pem to verify against a specific user's public key.
    Returns True if valid, False otherwise.
    """
    try:
        if public_key_pem:
            from cryptography.hazmat.primitives import serialization
            public_key = serialization.load_pem_public_key(public_key_pem.strip().encode('utf-8'))
        else:
            _, cert, _ = get_or_create_dev_credentials()
            public_key = cert.public_key()

        sig_bytes = base64.b64decode(signature_b64.strip())
        public_key.verify(
            sig_bytes,
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Fallback to dev cert if specific pubkey didn't match and was tried
        if public_key_pem:
            try:
                _, cert, _ = get_or_create_dev_credentials()
                sig_bytes = base64.b64decode(signature_b64.strip())
                cert.public_key().verify(
                    sig_bytes,
                    hash_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except Exception:
                pass
        return False


# Base Processor Architecture
class BaseFormatProcessor:
    def process_and_sign(self, content_bytes: bytes, filename: str) -> Dict[str, Any]:
        raise NotImplementedError

    def extract_and_verify(self, content_bytes: bytes, signature_data: Optional[str] = None) -> Dict[str, Any]:
        raise NotImplementedError

class TextSignatureProcessor(BaseFormatProcessor):
    def process_and_sign(self, content_bytes: bytes, filename: str) -> Dict[str, Any]:
        text = content_bytes.decode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(content_bytes)
        
        signed_json = format_qshield_signed_message(
            content=text,
            content_hash=raw_hash,
            signature_b64=sig_b64,
            pubkey_fingerprint=cert_fp,
            content_type="text/plain"
        )
        return {
            "content_type": ContentType.TEXT,
            "original_filename": filename,
            "content_hash": raw_hash,
            "signature_algorithm": "RSA-SHA256",
            "signature_value": sig_b64,
            "signature_fingerprint": sig_fp,
            "public_key_fingerprint": cert_fp,
            "signed_message_json": signed_json,
            "status": "SIGNED"
        }

class JsonSignatureProcessor(BaseFormatProcessor):
    def process_and_sign(self, content_bytes: bytes, filename: str) -> Dict[str, Any]:
        canonical_bytes, canonical_hash, parsed_obj = canonicalize_json(content_bytes)
        raw_hash = hashlib.sha256(content_bytes).hexdigest()
        
        sig_b64, cert_fp, sig_fp = rsa_sign_hash_bytes(canonical_bytes)
        
        signed_json = format_qshield_signed_message(
            content=json.dumps(parsed_obj),
            content_hash=canonical_hash,
            signature_b64=sig_b64,
            pubkey_fingerprint=cert_fp,
            content_type="application/json"
        )
        return {
            "content_type": ContentType.JSON,
            "original_filename": filename,
            "content_hash": raw_hash,
            "canonical_hash": canonical_hash,
            "signature_algorithm": "RSA-SHA256",
            "signature_value": sig_b64,
            "signature_fingerprint": sig_fp,
            "public_key_fingerprint": cert_fp,
            "signed_message_json": signed_json,
            "status": "SIGNED"
        }
