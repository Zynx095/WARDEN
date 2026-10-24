"""Durable approval and delivery state (SQLite, standard library only).

What is stored, so it survives a restart:
- live pending approvals (the exact action, its digests, expiry, who may decide, advisory risk);
- resolved approvals (approved / rejected / expired / invalidated) and, for approved ones, the
  final outcome; an approval consumed before its outcome was recorded is marked INTERRUPTED
  on the next start and never runs again;
- chat replies by (sender, msg_id), so a redelivered message is answered from the record
  instead of being processed twice.

What is never stored: authorization tokens, signing keys, seeds or file contents read by
the executor (read replies are not cached here; see ``WardenACPHandler``).

A store that cannot be opened or fails SQLite's integrity check raises ``StateStoreError``;
callers must refuse to start rather than run with lost approval state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1
MAX_RESOLVED = 5000
MAX_REPLIES = 2000


class StateStoreError(RuntimeError):
    """The state database is unreadable, corrupt or from an incompatible version."""


class StateStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
            ok = self._db.execute("PRAGMA quick_check").fetchone()
            if not ok or ok[0] != "ok":
                raise StateStoreError(f"State database failed its integrity check: {self.path.name}")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pending (action_id TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS resolved (
                    action_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replies (
                    sender TEXT NOT NULL, msg_id TEXT NOT NULL, seq INTEGER NOT NULL, reply TEXT NOT NULL,
                    PRIMARY KEY (sender, msg_id));
                """
            )
            row = self._db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                self._db.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif row[0] != str(SCHEMA_VERSION):
                raise StateStoreError(f"State database schema {row[0]} is not supported (expected {SCHEMA_VERSION}).")
        except sqlite3.DatabaseError as exc:
            raise StateStoreError(f"State database {self.path.name} cannot be used: {type(exc).__name__}") from None

    def _exec(self, sql: str, params: tuple = ()) -> List[tuple]:
        with self._lock:
            try:
                return self._db.execute(sql, params).fetchall()
            except sqlite3.DatabaseError as exc:
                raise StateStoreError(f"State database error: {type(exc).__name__}") from None

    # --- approvals --------------------------------------------------------------------------

    def save_pending(self, action_id: str, record: Dict[str, Any]) -> None:
        self._exec("INSERT OR REPLACE INTO pending VALUES (?, ?)", (action_id, json.dumps(record)))

    def delete_pending(self, action_id: str) -> None:
        self._exec("DELETE FROM pending WHERE action_id = ?", (action_id,))

    def load_pending(self) -> List[Dict[str, Any]]:
        return [json.loads(r[0]) for r in self._exec("SELECT record FROM pending")]

    def save_resolved(self, action_id: str, record: Dict[str, Any]) -> None:
        """Record the resolution and drop the live entry in one transaction."""
        with self._lock:
            try:
                with self._db:
                    self._db.execute("BEGIN IMMEDIATE")
                    seq = (self._db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM resolved").fetchone())[0]
                    self._db.execute("INSERT OR REPLACE INTO resolved VALUES (?, ?, ?)",
                                     (action_id, seq, json.dumps(record)))
                    self._db.execute("DELETE FROM pending WHERE action_id = ?", (action_id,))
                    self._db.execute("DELETE FROM resolved WHERE seq <= ?", (seq - MAX_RESOLVED,))
            except sqlite3.DatabaseError as exc:
                raise StateStoreError(f"State database error: {type(exc).__name__}") from None

    def load_resolved(self) -> List[Dict[str, Any]]:
        return [json.loads(r[0]) for r in self._exec("SELECT record FROM resolved ORDER BY seq")]

    # --- delivered chat replies ---------------------------------------------------------------

    def put_reply(self, sender: str, msg_id: str, reply: str) -> None:
        with self._lock:
            try:
                with self._db:
                    self._db.execute("BEGIN IMMEDIATE")
                    seq = (self._db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM replies").fetchone())[0]
                    self._db.execute("INSERT OR REPLACE INTO replies VALUES (?, ?, ?, ?)", (sender, msg_id, seq, reply))
                    self._db.execute("DELETE FROM replies WHERE seq <= ?", (seq - MAX_REPLIES,))
            except sqlite3.DatabaseError as exc:
                raise StateStoreError(f"State database error: {type(exc).__name__}") from None

    def get_reply(self, sender: str, msg_id: str) -> Optional[str]:
        rows = self._exec("SELECT reply FROM replies WHERE sender = ? AND msg_id = ?", (sender, msg_id))
        return rows[0][0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._db.close()
