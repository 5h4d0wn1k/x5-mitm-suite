"""SQLite result store: event log + captured credentials."""

from __future__ import annotations

import datetime
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import DEFAULT_CONFIG

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    module TEXT NOT NULL,
    event TEXT NOT NULL,
    level TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    module TEXT NOT NULL,
    kind TEXT NOT NULL,
    username TEXT,
    password TEXT,
    url TEXT,
    remote TEXT,
    payload TEXT NOT NULL DEFAULT '{}'
);
"""


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _dumps(payload: Any) -> str:
    return json.dumps(payload or {}, separators=(",", ":"), default=str)


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return {}


class ResultStore:
    """Thread-safe SQLite store. Checkpointing-friendly (WAL enabled)."""

    def __init__(self, db_path: str = DEFAULT_CONFIG["db_path"]) -> None:
        self.path = str(db_path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record_event(
        self,
        module: str,
        event: str,
        level: str = "info",
        payload: Optional[Dict[str, Any]] = None,
        ts: Optional[str] = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, module, event, level, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts or _utcnow(), module, event, level, _dumps(payload)),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def record_capture(
        self,
        kind: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        remote: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        module: str = "http",
        ts: Optional[str] = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO captures (ts, module, kind, username, password, "
                "url, remote, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts or _utcnow(),
                    module,
                    kind,
                    username,
                    password,
                    url,
                    remote,
                    _dumps(payload),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def query_events(
        self, module: Optional[str] = None, limit: int = 200
    ) -> List[Dict[str, Any]]:
        if module:
            rows = self._conn.execute(
                "SELECT id, ts, module, event, level, payload FROM events "
                "WHERE module = ? ORDER BY id DESC LIMIT ?",
                (module, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, ts, module, event, level, payload FROM events "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "ts": r[1],
                "module": r[2],
                "event": r[3],
                "level": r[4],
                "payload": _loads(r[5]),
            }
            for r in rows
        ]

    def query_captures(
        self, module: Optional[str] = None, limit: int = 200
    ) -> List[Dict[str, Any]]:
        if module:
            rows = self._conn.execute(
                "SELECT id, ts, module, kind, username, password, url, remote, "
                "payload FROM captures WHERE module = ? ORDER BY id DESC LIMIT ?",
                (module, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, ts, module, kind, username, password, url, remote, "
                "payload FROM captures ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "ts": r[1],
                "module": r[2],
                "kind": r[3],
                "username": r[4],
                "password": r[5],
                "url": r[6],
                "remote": r[7],
                "payload": _loads(r[8]),
            }
            for r in rows
        ]

    def count_captures(self, since: Optional[str] = None) -> int:
        if since:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM captures WHERE ts >= ?", (since,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM captures").fetchone()
        return int(row[0])

    def count_events(self, module: Optional[str] = None) -> int:
        if module:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE module = ?", (module,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0])

    def first_last_capture_ts(self) -> Optional[Dict[str, str]]:
        row = self._conn.execute(
            "SELECT MIN(ts), MAX(ts) FROM captures WHERE ts IS NOT NULL"
        ).fetchone()
        if not row or not row[0]:
            return None
        return {"first": row[0], "last": row[1]}

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()

    def __enter__(self) -> "ResultStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()