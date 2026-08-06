"""Token + AES-GCM key management utilities."""
from __future__ import annotations

import os
import secrets
import string


def generate_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_aes_key(bits: int = 256) -> bytes:
    if bits % 8:
        raise ValueError("bits must be multiple of 8")
    return os.urandom(bits // 8)


def generate_install_id() -> str:
    return secrets.token_hex(8)
