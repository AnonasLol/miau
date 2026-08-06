"""Self-signed TLS certificate generator for Miau TCP listener.

Produces RSA 4096 cert + key, prints the SHA256 fingerprint of the DER cert.
The fingerprint is what gets pinned in the Nim client so that only Miau
endpoints are accepted (MITM by rogue CA is impossible).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from config import default

DEFAULT_DAYS = 3650


def generate(common_name: str, org: str, country: str, days: int, rsa_bits: int) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = _dt.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert.public_bytes(serialization.Encoding.DER)


def fingerprint_sha256(cert_der: bytes) -> str:
    return hashlib.sha256(cert_der).hexdigest().upper()


def main() -> int:
    cfg = default().tls
    out = Path(cfg.cert_dir)
    out.mkdir(parents=True, exist_ok=True)

    cert_pem, key_pem, der = generate(
        common_name=cfg.common_name,
        org=cfg.org,
        country=cfg.country,
        days=cfg.valid_days,
        rsa_bits=cfg.rsa_bits,
    )
    (out / "server.crt").write_bytes(cert_pem)
    (out / "server.key").write_bytes(key_pem)
    (out / "server.der").write_bytes(der)

    fp = fingerprint_sha256(der)
    (out / "fingerprint.txt").write_text(fp + "\n")

    print("[+] cert written to", out / "server.crt")
    print("[+] key  written to", out / "server.key")
    print("[+] der  written to", out / "server.der")
    print("[+] SHA256 fingerprint (pin this in client):")
    print("    " + fp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
