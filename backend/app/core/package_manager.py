"""
Detached Signature Package Generator and Serializer.

Creates standard signature packages for text and structured files:
1. document.ext (Original / normalized payload)
2. document.ext.sig (Base64-encoded signature)
3. document.ext.metadata.json (Non-sensitive metadata with QSHIELD-1.0 format)

Never exposes or stores private keys in metadata.
"""

import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from app.core.config import MEDIA_PACKAGES, MEDIA_SIGNED, MEDIA_ORIGINALS


def create_detached_signature_package(
    filename: str,
    content_bytes: bytes,
    signature_b64: str,
    signature_id: str,
    public_key_fingerprint: str,
    signature_fingerprint: str,
    signed_at: datetime = None
) -> Dict[str, Any]:
    """
    Creates detached signature artifacts on disk in media/signature_packages/:
    - <file_id>_<filename>
    - <file_id>_<filename>.sig
    - <file_id>_<filename>.metadata.json
    """
    if signed_at is None:
        signed_at = datetime.now(timezone.utc)

    file_id = str(uuid.uuid4())[:8]
    safe_name = Path(filename).name.replace(" ", "_")
    base_stem = f"{file_id}_{safe_name}"

    # Target file paths
    payload_path = MEDIA_PACKAGES / base_stem
    sig_path = MEDIA_PACKAGES / f"{base_stem}.sig"
    meta_path = MEDIA_PACKAGES / f"{base_stem}.metadata.json"

    # Write payload
    with open(payload_path, "wb") as f:
        f.write(content_bytes)

    # Write .sig file
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(signature_b64.strip())

    # Formulate safe metadata
    metadata = {
        "format_version": "QSHIELD-1.0",
        "signature_id": signature_id,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-SHA256",
        "public_key_fingerprint": public_key_fingerprint,
        "signature_fingerprint": signature_fingerprint,
        "signed_at": signed_at.isoformat(),
        "original_filename": safe_name
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return {
        "signature_id": signature_id,
        "payload_path": str(payload_path),
        "sig_path": str(sig_path),
        "metadata_path": str(meta_path),
        "metadata": metadata
    }


def parse_detached_signature_metadata(metadata_content: str) -> Dict[str, Any]:
    """Parses and validates signature package JSON metadata."""
    try:
        data = json.loads(metadata_content)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}
