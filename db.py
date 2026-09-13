"""SQLite para mensagens, grupos e fila LoRa."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

_lock = threading.Lock()
_conn = None
DB_PATH = None


def connect(data_dir: Path):
    global _conn, DB_PATH
    data_dir.mkdir(parents=True, exist_ok=True)
    DB_PATH = data_dir / "ftchat.db"
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.execute("PRAGMA temp_store=MEMORY")
    _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          client_id TEXT,
          group_id TEXT,
          payload TEXT NOT NULL,
          created_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_msg_group_time ON messages(group_id, created_at);
        CREATE TABLE IF NOT EXISTS groups (
          id TEXT PRIMARY KEY,
          payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lora (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          payload TEXT NOT NULL,
          created_at INTEGER
        );
        """
    )
    _conn.commit()
    return _conn


def _db():
    if _conn is None:
        raise RuntimeError("db not connected")
    return _conn


def replace_messages(messages: list) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM messages")
        rows = []
        for msg in messages[-400:]:
            rows.append((
                str(msg.get("id") or ""),
                str(msg.get("clientId") or ""),
                str(msg.get("groupId") or "aberto"),
                json.dumps(msg, ensure_ascii=False),
                int(msg.get("createdAt") or 0),
            ))
        if rows:
            db.executemany(
                "INSERT OR REPLACE INTO messages(id, client_id, group_id, payload, created_at) VALUES (?,?,?,?,?)",
                rows,
            )
        db.commit()


def load_messages() -> list:
    with _lock:
        cur = _db().execute("SELECT payload FROM messages ORDER BY created_at ASC")
        out = []
        for (payload,) in cur.fetchall():
            try:
                out.append(json.loads(payload))
            except Exception:
                pass
        return out


def upsert_message(msg: dict) -> None:
    with _lock:
        _db().execute(
            "INSERT OR REPLACE INTO messages(id, client_id, group_id, payload, created_at) VALUES (?,?,?,?,?)",
            (
                str(msg.get("id") or ""),
                str(msg.get("clientId") or ""),
                str(msg.get("groupId") or "aberto"),
                json.dumps(msg, ensure_ascii=False),
                int(msg.get("createdAt") or 0),
            ),
        )
        _db().commit()


def save_groups(groups: list) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM groups")
        for g in groups:
            db.execute(
                "INSERT OR REPLACE INTO groups(id, payload) VALUES (?,?)",
                (str(g.get("id") or ""), json.dumps(g, ensure_ascii=False)),
            )
        db.commit()


def load_groups() -> list:
    with _lock:
        cur = _db().execute("SELECT payload FROM groups")
        rows = []
        for (payload,) in cur.fetchall():
            try:
                rows.append(json.loads(payload))
            except Exception:
                pass
        return rows


def add_lora(packet: dict) -> None:
    with _lock:
        _db().execute(
            "INSERT INTO lora(payload, created_at) VALUES (?,?)",
            (json.dumps(packet, ensure_ascii=False), int(packet.get("createdAt") or 0)),
        )
        _db().commit()
