"""Miau wire codec: AES-256-GCM encrypted frames over TLS.

Frame layout (over TCP/TLS):
    [ 4 bytes: uint32 big-endian total length = len(nonce)+len(ct) ]
    [ 12 bytes: nonce ]
    [ N bytes: ciphertext + 16-byte GCM tag ]

Plaintext inside each frame is a serialized protobuf `Envelope`, which itself
carries `type` + inner payload bytes. Encryption uses the per-token AES-256 key
stored in the backend store (or the pre-shared key for the auth handshake).
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

import cryptography.hazmat.primitives.ciphers.aead as aead

from messages_pb2 import Envelope

GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
MAX_FRAME = 8 * 1024 * 1024  # 8 MB hard cap
LEN_PREFIX = struct.Struct(">I")


class FrameError(Exception):
    pass


@dataclass
class Frame:
    env: Envelope


def encrypt_payload(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM: returns nonce(12) || ciphertext(16 tag)."""
    nonce = os.urandom(GCM_NONCE_LEN)
    a = aead.AESGCM(key)
    ct = a.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_payload(key: bytes, blob: bytes) -> bytes:
    if len(blob) < GCM_NONCE_LEN + GCM_TAG_LEN:
        raise FrameError("payload too short")
    nonce, ct = blob[:GCM_NONCE_LEN], blob[GCM_NONCE_LEN:]
    a = aead.AESGCM(key)
    try:
        return a.decrypt(nonce, ct, None)
    except Exception as exc:  # cryptography.exceptions.InvalidTag
        raise FrameError(f"decrypt failed: {exc}") from exc


def encode_frame(key: bytes, env: Envelope) -> bytes:
    """Serialize envelope -> AES-GCM -> length-prefixed frame."""
    raw = env.SerializeToString()
    body = encrypt_payload(key, raw)
    return LEN_PREFIX.pack(len(body)) + body


def read_frame(stream, key: bytes) -> Envelope:
    """Read one frame from a file-like socket stream."""
    header = _read_exact(stream, LEN_PREFIX.size)
    (n,) = LEN_PREFIX.unpack(header)
    if n == 0:
        return Envelope()
    if n > MAX_FRAME:
        raise FrameError(f"frame too large: {n}")
    body = _read_exact(stream, n)
    plaintext = decrypt_payload(key, body)
    env = Envelope()
    env.ParseFromString(plaintext)
    return env


async def _read_exact_async(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = await stream.read(n - len(buf))
        if not chunk:
            raise FrameError("connection closed")
        buf += chunk
    return buf


async def read_frame_async(stream, key: bytes) -> Envelope:
    """Async variant of read_frame for asyncio StreamReader."""
    header = await _read_exact_async(stream, LEN_PREFIX.size)
    (n,) = LEN_PREFIX.unpack(header)
    if n == 0:
        return Envelope()
    if n > MAX_FRAME:
        raise FrameError(f"frame too large: {n}")
    body = await _read_exact_async(stream, n)
    plaintext = decrypt_payload(key, body)
    env = Envelope()
    env.ParseFromString(plaintext)
    return env


def _read_exact(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise FrameError("connection closed")
        buf += chunk
    return buf
