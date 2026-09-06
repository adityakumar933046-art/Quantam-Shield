import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from pyhanko.pdf_utils.reader import PdfFileReader
from pypdf import PdfReader
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from asn1crypto import cms

def compute_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_pdf_signature_info(pdf_path: Path) -> Dict[str, Any]:
    """
    Parses a PDF document, detects whether standard PKCS#7 / CMS digital signatures are present,
    and extracts signature metadata and embedded X.509 certificates.
    
    Status states:
    - SIGNATURE_FOUND
    - NO_SIGNATURE_FOUND
    - SIGNATURE_STRUCTURE_INVALID
    - SIGNATURE_UNSUPPORTED
    - EXTRACTION_ERROR
    """
    if not pdf_path.exists():
        return {
            "signature_detected": False,
            "signature_status": "EXTRACTION_ERROR",
            "error_detail": "File not found on server storage."
        }

    document_hash = compute_sha256(pdf_path)
    raw_sig_bytes: Optional[bytes] = None
    field_name: str = "Signature1"

    # METHOD 1: PyHanko PdfFileReader object tree inspection
    try:
        with open(pdf_path, 'rb') as f:
            pdf_r = PdfFileReader(f)
            if '/AcroForm' in pdf_r.root and '/Fields' in pdf_r.root['/AcroForm']:
                fields = pdf_r.root['/AcroForm']['/Fields']
                for field in fields:
                    f_obj = field.get_object()
                    if isinstance(f_obj, dict) and '/V' in f_obj:
                        v_obj = f_obj['/V'].get_object()
                        if isinstance(v_obj, dict) and '/Contents' in v_obj:
                            contents_val = v_obj['/Contents']
                            raw_sig_bytes = bytes(contents_val)
                            if '/T' in f_obj:
                                field_name = str(f_obj['/T'])
                            break
    except Exception:
        pass

    # METHOD 2: Fallback scanning using pypdf fields
    if not raw_sig_bytes:
        try:
            pypdf_r = PdfReader(str(pdf_path))
            if pypdf_r.fields:
                for fname, fval in pypdf_r.fields.items():
                    if isinstance(fval, dict) and '/V' in fval:
                        v_val = fval.get('/V')
                        if isinstance(v_val, dict) and '/Contents' in v_val:
                            raw_sig_bytes = bytes(v_val.get('/Contents'))
                            field_name = str(fname)
                            break
        except Exception:
            pass

    # METHOD 3: Fallback raw byte scan for /ByteRange ... /Contents <hex>
    if not raw_sig_bytes:
        try:
            with open(pdf_path, 'rb') as f:
                pdf_content = f.read()
                if b'/ByteRange' in pdf_content and b'/Contents' in pdf_content:
                    c_idx = pdf_content.find(b'/Contents')
                    if c_idx != -1:
                        start_hex = pdf_content.find(b'<', c_idx)
                        end_hex = pdf_content.find(b'>', start_hex)
                        if start_hex != -1 and end_hex != -1:
                            hex_str = pdf_content[start_hex+1:end_hex].replace(b'\x00', b'').replace(b' ', b'').replace(b'\r', b'').replace(b'\n', b'')
                            try:
                                raw_sig_bytes = bytes.fromhex(hex_str.decode('ascii'))
                            except Exception:
                                pass
                elif b'/Type /Sig' in pdf_content or b'/Type/Sig' in pdf_content:
                    return {
                        "signature_detected": True,
                        "signature_status": "SIGNATURE_STRUCTURE_INVALID",
                        "document_hash": document_hash,
                        "error_detail": "Signature object present but stream bytes are unreadable or malformed."
                    }
        except Exception as e:
            return {
                "signature_detected": False,
                "signature_status": "EXTRACTION_ERROR",
                "document_hash": document_hash,
                "error_detail": f"File stream reading error: {str(e)}"
            }

    # If no signature bytes found at all
    if not raw_sig_bytes or len(raw_sig_bytes) == 0:
        return {
            "signature_detected": False,
            "signature_status": "NO_SIGNATURE_FOUND",
            "document_hash": document_hash,
            "message": "No digital signature dictionary found in PDF document."
        }

    # Clean raw bytes if zero padded or wrapped in hex string
    clean_bytes = raw_sig_bytes.rstrip(b'\x00')
    if clean_bytes.startswith(b'<') and clean_bytes.endswith(b'>'):
        try:
            clean_bytes = bytes.fromhex(clean_bytes[1:-1].decode('ascii'))
        except Exception:
            pass

    sig_fingerprint = hashlib.sha256(clean_bytes).hexdigest()

    # 4. Parse ASN.1 PKCS#7 / CMS ContentInfo & extract X.509 Certificate
    try:
        content_info = cms.ContentInfo.load(clean_bytes)
        if content_info['content_type'].native != 'signed_data':
            return {
                "signature_detected": True,
                "signature_status": "SIGNATURE_UNSUPPORTED",
                "document_hash": document_hash,
                "signature_fingerprint": sig_fingerprint,
                "error_detail": "Signature content is not standard PKCS#7 SignedData."
            }

        signed_data = content_info['content']
        certificates = signed_data['certificates']

        if not certificates or len(certificates) == 0:
            return {
                "signature_detected": True,
                "signature_status": "SIGNATURE_STRUCTURE_INVALID",
                "document_hash": document_hash,
                "signature_fingerprint": sig_fingerprint,
                "error_detail": "PKCS#7 signature structure contains no embedded X.509 certificates."
            }

        # Extract primary signing certificate
        cert_choice = certificates[0]
        cert_der_bytes = cert_choice.dump()

        crypto_cert = x509.load_der_x509_certificate(cert_der_bytes)

        cert_subject_str = crypto_cert.subject.rfc4514_string()
        cert_issuer_str = crypto_cert.issuer.rfc4514_string()
        cert_serial_str = str(crypto_cert.serial_number)
        cert_fingerprint = crypto_cert.fingerprint(hashes.SHA256()).hex()

        # Signer Identity Fields (Common Name & Organization)
        signer_cn = "Not Available"
        signer_org = "Not Available"
        for attr in crypto_cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                signer_cn = attr.value
            elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                signer_org = attr.value

        # Public Key Info
        pub_key = crypto_cert.public_key()
        pub_key_algo = "RSA"
        pub_key_size = getattr(pub_key, "key_size", 2048)

        # Signing Time from signer_info or certificate validity
        signing_time = crypto_cert.not_valid_before
        signer_infos = signed_data['signer_infos']
        if len(signer_infos) > 0:
            s_info = signer_infos[0]
            if 'unsigned_attrs' in s_info and s_info['unsigned_attrs']:
                for uattr in s_info['unsigned_attrs']:
                    if uattr['type'].native == 'signing_time':
                        signing_time = uattr['values'][0].native

        return {
            "signature_detected": True,
            "signature_status": "SIGNATURE_FOUND",
            "document_hash": document_hash,
            "signature_algorithm": "RSA-SHA256",
            "hash_algorithm": "SHA-256",
            "signature_fingerprint": sig_fingerprint,
            "field_name": field_name,
            "signing_time": signing_time,
            "certificate_subject": cert_subject_str,
            "certificate_issuer": cert_issuer_str,
            "certificate_serial_number": cert_serial_str,
            "validity_start": crypto_cert.not_valid_before,
            "validity_end": crypto_cert.not_valid_after,
            "certificate_fingerprint": cert_fingerprint,
            "public_key_algorithm": pub_key_algo,
            "public_key_size": pub_key_size,
            "signer_name": signer_cn,
            "signer_organization": signer_org
        }

    except Exception as e:
        return {
            "signature_detected": True,
            "signature_status": "SIGNATURE_STRUCTURE_INVALID",
            "document_hash": document_hash,
            "signature_fingerprint": sig_fingerprint,
            "error_detail": f"Failed to parse PKCS#7 ASN.1 structure: {str(e)}"
        }

from app.core.format_processors import detect_content_format, ContentType, canonicalize_json

def extract_multiformat_signature_info(
    content_bytes: bytes,
    filename: str = "",
    signature_detached_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Unified extraction pipeline for PDF, TXT, JSON, QSHIELD-1.0 messages,
    Bitcoin-style messages, and detached signatures.
    """
    fmt = detect_content_format(content_bytes, filename)

    if fmt == ContentType.PDF:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(content_bytes)
            tmp_path = Path(tmp.name)
        try:
            res = extract_pdf_signature_info(tmp_path)
            res["content_type"] = ContentType.PDF
            return res
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    doc_hash = hashlib.sha256(content_bytes).hexdigest()

    # 1. Structured Message (QSHIELD-1.0 or Bitcoin Mode)
    if fmt in [ContentType.STRUCTURED_MESSAGE, ContentType.BITCOIN_MESSAGE]:
        try:
            obj = json.loads(content_bytes.decode('utf-8'))
            sig_val = obj.get("signature") or obj.get("signature_value")
            content_hash = obj.get("content_hash")
            pub_fp = obj.get("public_key_fingerprint") or "Dev Key"
            sig_algo = obj.get("signature_algorithm") or "RSA-SHA256"
            
            sig_fp = hashlib.sha256(sig_val.encode('utf-8')).hexdigest() if sig_val else "N/A"
            
            return {
                "signature_detected": True,
                "signature_status": "SIGNATURE_FOUND",
                "content_type": fmt,
                "signature_id": obj.get("signature_id"),
                "signature_value": sig_val,
                "document_hash": content_hash or doc_hash,
                "signature_algorithm": sig_algo,
                "hash_algorithm": "SHA-256",
                "signature_fingerprint": sig_fp,
                "field_name": "StructuredSignature1",
                "signing_time": datetime.now(timezone.utc),
                "certificate_subject": "CN=Q-SHIELD Development CA (Demo),O=Q-SHIELD Security Platform",
                "certificate_issuer": "CN=Q-SHIELD Development CA (Demo),O=Q-SHIELD Security Platform",
                "certificate_serial_number": "1001",
                "validity_start": datetime.now(timezone.utc),
                "validity_end": datetime.now(timezone.utc),
                "certificate_fingerprint": pub_fp,
                "public_key_algorithm": "RSA",
                "public_key_size": 2048,
                "signer_name": "Q-SHIELD Developer Key",
                "signer_organization": "Q-SHIELD Platform",
                "extracted_content": obj.get("content") or obj.get("payload"),
                "raw_signature_b64": sig_val
            }
        except Exception as e:
            return {
                "signature_detected": True,
                "signature_status": "SIGNATURE_STRUCTURE_INVALID",
                "content_type": fmt,
                "document_hash": doc_hash,
                "error_detail": f"Failed to parse structured signed message: {str(e)}"
            }

    # 2. Detached Signature
    if signature_detached_bytes or fmt == ContentType.DETACHED_SIGNATURE:
        sig_str = (signature_detached_bytes or content_bytes).decode('utf-8', errors='ignore').strip()
        sig_fp = hashlib.sha256(sig_str.encode('utf-8')).hexdigest()
        return {
            "signature_detected": True,
            "signature_status": "SIGNATURE_FOUND",
            "content_type": ContentType.DETACHED_SIGNATURE,
            "document_hash": doc_hash,
            "signature_algorithm": "RSA-SHA256",
            "hash_algorithm": "SHA-256",
            "signature_fingerprint": sig_fp,
            "field_name": "DetachedSignature1",
            "signing_time": datetime.now(timezone.utc),
            "certificate_subject": "CN=Q-SHIELD Development CA (Demo),O=Q-SHIELD Security Platform",
            "certificate_issuer": "CN=Q-SHIELD Development CA (Demo),O=Q-SHIELD Security Platform",
            "certificate_serial_number": "1001",
            "validity_start": datetime.now(timezone.utc),
            "validity_end": datetime.now(timezone.utc),
            "certificate_fingerprint": "Dev Key",
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "signer_name": "Q-SHIELD Developer Key",
            "signer_organization": "Q-SHIELD Platform",
            "raw_signature_b64": sig_str
        }

    # 3. Plain Text / JSON Content without embedded signature envelope
    return {
        "signature_detected": False,
        "signature_status": "NO_SIGNATURE_FOUND",
        "content_type": fmt,
        "document_hash": doc_hash,
        "error_detail": "Content contains no digital signature envelope or detached signature."
    }
