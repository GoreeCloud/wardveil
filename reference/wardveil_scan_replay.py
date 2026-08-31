"""Durable same-host replay protection for the Wardveil Scan transport."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path

from reference.wardveil_scan_service import ScanServiceRequest, ScanServiceRequestError

DEFAULT_BUSY_TIMEOUT_SECONDS = 5


def _epoch_microseconds(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("scan replay timestamps must be timezone-aware")
    utc = value.astimezone(timezone.utc)
    return int(utc.timestamp() * 1_000_000)


@dataclass(frozen=True)
class SQLiteReplayLedger:
    """Bounded, expiring replay ledger durable across same-host process restarts.

    SQLite serializes claim/finalize writes with BEGIN IMMEDIATE. The database stores
    authentication-bound request digests and sanitized response envelopes only; raw
    scanned bytes and caller secrets are never persisted here.
    """

    path: Path
    max_entries: int
    ttl: timedelta
    busy_timeout_seconds: int = DEFAULT_BUSY_TIMEOUT_SECONDS
    _path: Path = field(init=False, repr=False)

    def __post_init__(self) -> None:
        path = Path(self.path)
        object.__setattr__(self, "_path", path)
        if self.max_entries < 1:
            raise ValueError("scan replay max entries must be positive")
        if self.ttl <= timedelta(0):
            raise ValueError("scan replay TTL must be positive")
        if self.busy_timeout_seconds < 1:
            raise ValueError("scan replay busy timeout must be positive")
        if not path.is_absolute():
            raise ValueError("scan replay database path must be absolute")
        if not path.parent.is_dir():
            raise ValueError("scan replay database parent directory must exist")
        self._prepare_database_file()
        try:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS replay_entries (
                        caller_id TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        expires_at_us INTEGER NOT NULL,
                        response_json TEXT,
                        PRIMARY KEY (caller_id, key_id, nonce)
                    )
                    """
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS replay_entries_expiry_idx "
                    "ON replay_entries (expires_at_us)"
                )
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise OSError("initialize Wardveil Scan replay database") from exc

    def _prepare_database_file(self) -> None:
        path = self._path
        if path.is_symlink():
            raise ValueError("scan replay database must not be a symlink")
        try:
            info = path.stat()
        except FileNotFoundError:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                info = path.stat()
            else:
                os.close(fd)
                info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("scan replay database must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("scan replay database must not be accessible by group or others")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self._path),
            timeout=float(self.busy_timeout_seconds),
            isolation_level=None,
        )
        connection.execute(
            f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}"
        )
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _prune(self, connection: sqlite3.Connection, now_us: int) -> None:
        connection.execute(
            "DELETE FROM replay_entries WHERE expires_at_us <= ?",
            (now_us,),
        )

    @staticmethod
    def _key(request: ScanServiceRequest) -> tuple[str, str, str]:
        return request.caller_id, request.key_id, request.nonce

    @staticmethod
    def _store_unavailable(exc: BaseException) -> ScanServiceRequestError:
        return ScanServiceRequestError(
            "scan_replay_store_unavailable", HTTPStatus.SERVICE_UNAVAILABLE
        )

    def claim(
        self,
        request: ScanServiceRequest,
        request_digest: str,
        *,
        now: datetime,
    ) -> tuple[str, dict | None]:
        now_us = _epoch_microseconds(now)
        expires_at_us = _epoch_microseconds(now + self.ttl)
        key = self._key(request)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._prune(connection, now_us)
            row = connection.execute(
                "SELECT request_digest, response_json FROM replay_entries "
                "WHERE caller_id = ? AND key_id = ? AND nonce = ?",
                key,
            ).fetchone()
            if row is None:
                count = int(
                    connection.execute("SELECT COUNT(*) FROM replay_entries").fetchone()[0]
                )
                if count >= self.max_entries:
                    connection.execute("COMMIT")
                    return "capacity", None
                connection.execute(
                    "INSERT INTO replay_entries "
                    "(caller_id, key_id, nonce, request_digest, expires_at_us, response_json) "
                    "VALUES (?, ?, ?, ?, ?, NULL)",
                    (*key, request_digest, expires_at_us),
                )
                connection.execute("COMMIT")
                return "new", None

            stored_digest, response_json = row
            if stored_digest != request_digest:
                connection.execute("COMMIT")
                return "conflict", None
            if response_json is None:
                connection.execute("COMMIT")
                return "pending", None
            try:
                cached = json.loads(response_json)
            except (json.JSONDecodeError, TypeError) as exc:
                connection.execute("ROLLBACK")
                raise ScanServiceRequestError(
                    "scan_replay_cached_response_invalid",
                    HTTPStatus.SERVICE_UNAVAILABLE,
                ) from exc
            if not isinstance(cached, dict):
                connection.execute("ROLLBACK")
                raise ScanServiceRequestError(
                    "scan_replay_cached_response_invalid",
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
            connection.execute("COMMIT")
            return "exact_replay", cached
        except ScanServiceRequestError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise self._store_unavailable(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def finalize(
        self,
        request: ScanServiceRequest,
        request_digest: str,
        response: dict,
        *,
        now: datetime,
    ) -> None:
        now_us = _epoch_microseconds(now)
        try:
            response_json = json.dumps(
                response,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError("scan_replay_response_not_serializable") from exc

        key = self._key(request)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._prune(connection, now_us)
            row = connection.execute(
                "SELECT request_digest FROM replay_entries "
                "WHERE caller_id = ? AND key_id = ? AND nonce = ?",
                key,
            ).fetchone()
            if row is None or row[0] != request_digest:
                connection.execute("ROLLBACK")
                raise ScanServiceRequestError(
                    "scan_replay_claim_lost", HTTPStatus.SERVICE_UNAVAILABLE
                )
            connection.execute(
                "UPDATE replay_entries SET response_json = ? "
                "WHERE caller_id = ? AND key_id = ? AND nonce = ?",
                (response_json, *key),
            )
            connection.execute("COMMIT")
        except ScanServiceRequestError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise self._store_unavailable(exc) from exc
        finally:
            if connection is not None:
                connection.close()
