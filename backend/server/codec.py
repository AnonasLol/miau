"""Length-prefixed binary frames over TCP.

Wire format (big-endian):

    [ uint32 magic = 0x4D494155 ]         4 bytes
    [ uint32 payload_len ]                4 bytes
    [ payload ]                           payload_len bytes

Payload layout:

    [ uint16 nonce_len ][ nonce AES-GCM ][ ciphertext + tag ]

AES-GCM: key = per-token aes_key, nonce = 12 random bytes.
Ciphertext includes the 16-byte GCM tag.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = 0x4D494155
HEADER = 8
NONCE_LEN = 12

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


class CodecError(Exception):
    pass


@dataclass
class Frame:
    nonce: bytes
    ciphertext: bytes


def build_frame(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> bytes:
    if not _HAS_CRYPTO:
        raise CodecError("cryptography not installed")
    nonce = nonce or __import__("os").urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise CodecError(f"nonce must be {NONCE_LEN} bytes")
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    payload = struct.pack(f">H{NONCE_LEN}s", nonce_len := len(nonce), nonce) + ct
    return struct.pack(">II", MAGIC, len(payload)) + payload


def parse_frame(buf: bytes) -> tuple[Frame | None, bytes]:
    """Consume exactly one frame from buf. Returns (frame, rest).

    Raises CodecError on magic mismatch or length violation.
    """
    if len(buf) < HEADER:
        return None, buf
    magic, plen = struct.unpack(">II", buf[:HEADER])
    if magic != MAGIC:
        raise CodecError("bad magic")
    if plen > 64 * 1024 * 1024:
        raise CodecError("frame too large")
    total = HEADER + plen
    if len(buf) < total:
        return None, buf
    payload = buf[HEADER:total]
    rest = buf[total:]
    if len(payload) < 2 + NONCE_LEN:
        raise CodecError("truncated payload")
    nonce_len = struct.unpack(">H", payload[:2])[0]
    if nonce_len != NONCE_LEN:
        raise CodecError("bad nonce length")
    nonce = payload[2:2 + NONCE_LEN]
    ct = payload[2 + NONCE_LEN:]
    return Frame(nonce=nonce, ciphertext=ct), rest


def unwrap(key: bytes, frame: Frame) -> bytes:
    if not _HAS_CRYPTO:
        raise CodecError("cryptography not installed")
    return AESGCM(key).decrypt(frame.nonce, frame.ciphertext, None)
