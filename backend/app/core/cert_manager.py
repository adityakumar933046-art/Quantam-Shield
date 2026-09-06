import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.core.config import PROJECT_ROOT

CERTS_DIR = PROJECT_ROOT / "certs"
CERTS_DIR.mkdir(exist_ok=True)

PRIVATE_KEY_PATH = CERTS_DIR / "dev_private_key.pem"
CERTIFICATE_PATH = CERTS_DIR / "dev_certificate.pem"

def get_or_create_dev_credentials():
    """
    Ensures a development RSA-2048 private key and X.509 self-signed certificate exist.
    Generates new credentials if not present on disk.
    Private keys remain securely stored on disk and are NEVER stored in database records.
    """
    if not PRIVATE_KEY_PATH.exists() or not CERTIFICATE_PATH.exists():
        print("[Q-SHIELD] Generating Development RSA-2048 Private Key & Self-Signed X.509 Certificate...")
        
        # 1. Generate RSA-2048 Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 2. Build Self-Signed X.509 Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Q-SHIELD Security Platform (Demo)"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Q-SHIELD Development CA (Demo)"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Save Private Key (PEM format)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save Certificate (PEM format)
        with open(CERTIFICATE_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[Q-SHIELD] Development credentials created successfully at:", CERTS_DIR)

    # Read Private Key
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read Certificate
    with open(CERTIFICATE_PATH, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)

    return private_key, cert, cert_data
