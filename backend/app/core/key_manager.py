"""
Cryptographic KeyPair Management with Encryption-at-Rest.

Stores user RSA-2048 public keys and encrypted-at-rest private keys.
Private keys are NEVER exposed to API responses or frontend clients.
"""

import os
import base64
import hashlib
from datetime import datetime, timezone
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from app.core.config import SECRET_KEY


def _get_encryption_cipher() -> Fernet:
    """Derives a deterministic 32-byte key from server SECRET_KEY for Fernet AES-128-CBC/HMAC."""
    key_32 = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
    urlsafe_key = base64.urlsafe_b64encode(key_32)
    return Fernet(urlsafe_key)


def encrypt_private_key(pem_bytes: bytes) -> str:
    """Encrypts private key PEM bytes using server-side cipher."""
    cipher = _get_encryption_cipher()
    encrypted = cipher.encrypt(pem_bytes)
    return encrypted.decode('utf-8')


def decrypt_private_key(encrypted_str: str) -> bytes:
    """Decrypts encrypted-at-rest private key string back into PEM bytes."""
    cipher = _get_encryption_cipher()
    decrypted = cipher.decrypt(encrypted_str.encode('utf-8'))
    return decrypted


def compute_public_key_fingerprint(public_key_pem: str) -> str:
    """Calculates SHA-256 digest fingerprint of public key PEM."""
    clean_bytes = public_key_pem.strip().encode('utf-8')
    return hashlib.sha256(clean_bytes).hexdigest()


def get_or_create_user_keypair(db: Session, user_id: int):
    """
    Retrieves or generates a secure RSA-2048 KeyPair for a user.
    Stores the public key and encrypted-at-rest private key in database.
    """
    from app.models import KeyPair

    keypair = db.query(KeyPair).filter(KeyPair.user_id == user_id, KeyPair.status == "ACTIVE").first()
    if keypair:
        return keypair

    # Generate fresh RSA-2048 Keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    enc_priv = encrypt_private_key(priv_pem)
    fp = compute_public_key_fingerprint(pub_pem)

    keypair = KeyPair(
        user_id=user_id,
        algorithm="RSA-2048",
        public_key=pub_pem,
        private_key_encrypted=enc_priv,
        key_fingerprint=fp,
        status="ACTIVE"
    )
    db.add(keypair)
    db.commit()
    db.refresh(keypair)
    return keypair


def get_user_private_key(db: Session, user_id: int):
    """
    Loads and decrypts user's RSA private key.
    BACKEND INTERNAL USE ONLY. NEVER SERIALIZE IN API RESPONSES.
    """
    keypair = get_or_create_user_keypair(db, user_id)
    raw_pem = decrypt_private_key(keypair.private_key_encrypted)
    return serialization.load_pem_private_key(raw_pem, password=None)


def get_user_public_key(db: Session, user_id: int):
    """Loads user's public key from database for verification."""
    keypair = get_or_create_user_keypair(db, user_id)
    return serialization.load_pem_public_key(keypair.public_key.encode('utf-8'))
