#!/usr/bin/env python3
"""Single-host durable execution state for Wardveil high-impact actions.

This adapter preserves the Foundation 0.9 execution-state semantics while
persisting claims and receipts across process restarts. It is intentionally a
bounded single-host reference and does not claim distributed production
acceptance.
"""
from __future__ import annotations

import copy
import json
import os
import sqlite3
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Iterator

from reference.wardveil_execution_state import (
    EXECUTION_STATE_CONTRACT_VERSION,
    FINAL_OUTCOMES,
    ClaimDecision,
    ExecutionClaim,
    ExecutionReceipt,
    _canonical,
    _parse_time,
    _utc,
    authorization_digest,
)

SQLITE_EXECUTION_STATE_VERSION = "0.1.0"


class SQLiteExecutionStateStore:
    """Durable local store with transactional nonce/idempotency claims."""

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 5000) -> None:
        self.path = Path(path)
        if str(self.path) in {"", ":memory:"}:
            raise ValueError("durable_execution_state_file_required")
        if busy_timeout_ms <= 0 or busy_timeout_ms > 60_000:
            raise ValueError("invalid_execution_state_busy_timeout")
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        created = not self.path.exists()
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS execution_claims (
                    nonce TEXT PRIMARY KEY,
                    authorization_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    authorization_digest_sha256 TEXT NOT NULL,
                    executor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    claimed_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    UNIQUE(executor_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS execution_receipts (
                    nonce TEXT PRIMARY KEY REFERENCES execution_claims(nonce),
                    receipt_json TEXT NOT NULL,
                    protection_record_digest_sha256 TEXT NOT NULL,
                    outcome TEXT NOT NULL
                );
                """
            )
        finally:
            connection.close()
        if os.name == "posix" and (created or self.path.exists()):
            self.path.chmod(0o600)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @staticmethod
    def _claim_from_row(row: sqlite3.Row) -> ExecutionClaim:
        return ExecutionClaim(
            nonce=str(row["nonce"]),
            authorization_id=str(row["authorization_id"]),
            idempotency_key=str(row["idempotency_key"]),
            authorization_digest_sha256=str(row["authorization_digest_sha256"]),
            executor_id=str(row["executor_id"]),
            action=str(row["action"]),
            correlation_id=str(row["correlation_id"]),
            scope=json.loads(str(row["scope_json"])),
            claimed_at=str(row["claimed_at"]),
            expires_at=str(row["expires_at"]),
            status=str(row["status"]),
        )

    @staticmethod
    def _receipt_from_json(raw: str) -> ExecutionReceipt:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid_persisted_execution_receipt")
        return ExecutionReceipt(
            receipt_id=str(value["receipt_id"]),
            nonce=str(value["nonce"]),
            authorization_id=str(value["authorization_id"]),
            authorization_digest_sha256=str(value["authorization_digest_sha256"]),
            executor_id=str(value["executor_id"]),
            action=str(value["action"]),
            correlation_id=str(value["correlation_id"]),
            scope=copy.deepcopy(value["scope"]),
            idempotency_key=str(value["idempotency_key"]),
            outcome=str(value["outcome"]),
            protection_record=copy.deepcopy(value["protection_record"]),
            protection_record_digest_sha256=str(value["protection_record_digest_sha256"]),
            completed_at=str(value["completed_at"]),
            receipt_digest_sha256=str(value["receipt_digest_sha256"]),
        )

    def claim(self, authorization: dict, *, now=None) -> ClaimDecision:
        observed = _utc(now)
        required = (
            "authorization_id",
            "executor_id",
            "action",
            "correlation_id",
            "idempotency_key",
            "nonce",
            "issued_at",
            "expires_at",
            "scope",
        )
        if any(not authorization.get(key) for key in required):
            return ClaimDecision("invalid_authorization_state")
        if not isinstance(authorization.get("scope"), dict):
            return ClaimDecision("invalid_authorization_state")
        expires = _parse_time(authorization.get("expires_at"))
        if expires is None or expires <= observed:
            return ClaimDecision("expired_authorization")

        digest = authorization_digest(authorization)
        nonce = str(authorization["nonce"])
        authorization_id = str(authorization["authorization_id"])
        idempotency_key = str(authorization["idempotency_key"])
        executor_id = str(authorization["executor_id"])

        with self._transaction() as connection:
            existing_row = connection.execute(
                "SELECT * FROM execution_claims WHERE nonce = ?",
                (nonce,),
            ).fetchone()
            if existing_row is not None:
                existing = self._claim_from_row(existing_row)
                same = (
                    existing.authorization_id == authorization_id
                    and existing.idempotency_key == idempotency_key
                    and existing.authorization_digest_sha256 == digest
                    and existing.executor_id == executor_id
                )
                if not same:
                    return ClaimDecision("authorization_nonce_conflict", existing)
                receipt_row = connection.execute(
                    "SELECT receipt_json FROM execution_receipts WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
                if receipt_row is not None:
                    return ClaimDecision(
                        "idempotent_finalized",
                        existing,
                        self._receipt_from_json(str(receipt_row["receipt_json"])),
                    )
                return ClaimDecision("execution_reconciliation_required", existing)

            idempotency_row = connection.execute(
                "SELECT * FROM execution_claims WHERE executor_id = ? AND idempotency_key = ?",
                (executor_id, idempotency_key),
            ).fetchone()
            if idempotency_row is not None:
                return ClaimDecision(
                    "executor_idempotency_conflict",
                    self._claim_from_row(idempotency_row),
                )

            claim = ExecutionClaim(
                nonce=nonce,
                authorization_id=authorization_id,
                idempotency_key=idempotency_key,
                authorization_digest_sha256=digest,
                executor_id=executor_id,
                action=str(authorization["action"]),
                correlation_id=str(authorization["correlation_id"]),
                scope=copy.deepcopy(authorization["scope"]),
                claimed_at=observed.isoformat(),
                expires_at=str(authorization["expires_at"]),
            )
            connection.execute(
                """
                INSERT INTO execution_claims (
                    nonce, authorization_id, idempotency_key,
                    authorization_digest_sha256, executor_id, action,
                    correlation_id, scope_json, claimed_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim.nonce,
                    claim.authorization_id,
                    claim.idempotency_key,
                    claim.authorization_digest_sha256,
                    claim.executor_id,
                    claim.action,
                    claim.correlation_id,
                    json.dumps(claim.scope, sort_keys=True, separators=(",", ":")),
                    claim.claimed_at,
                    claim.expires_at,
                    claim.status,
                ),
            )
            return ClaimDecision("new", claim)

    def finalize(self, authorization: dict, protection_record: dict, *, now=None) -> ExecutionReceipt:
        observed = _utc(now)
        nonce = str(authorization.get("nonce") or "")
        digest = authorization_digest(authorization)

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM execution_claims WHERE nonce = ?",
                (nonce,),
            ).fetchone()
            if row is None:
                raise ValueError("execution_claim_required")
            claim = self._claim_from_row(row)
            if digest != claim.authorization_digest_sha256:
                raise ValueError("authorization_claim_digest_mismatch")
            if authorization.get("authorization_id") != claim.authorization_id:
                raise ValueError("authorization_claim_identity_mismatch")

            outcome = protection_record.get("execution_status")
            if outcome not in FINAL_OUTCOMES:
                raise ValueError("invalid_protection_outcome")
            if protection_record.get("record_type") != "protection_action":
                raise ValueError("invalid_protection_record_type")
            producer = protection_record.get("producer") or {}
            if producer.get("authoritative") is not True or not producer.get("id"):
                raise ValueError("non_authoritative_protection_record")
            if protection_record.get("correlation_id") != claim.correlation_id:
                raise ValueError("protection_correlation_mismatch")
            if protection_record.get("policy_decision") != claim.action:
                raise ValueError("protection_action_mismatch")
            if protection_record.get("executor") != claim.executor_id:
                raise ValueError("protection_executor_mismatch")
            if protection_record.get("idempotency_key") != claim.idempotency_key:
                raise ValueError("protection_idempotency_mismatch")
            if protection_record.get("scope") != claim.scope:
                raise ValueError("protection_scope_mismatch")

            protection_digest = sha256(_canonical(protection_record)).hexdigest()
            receipt_row = connection.execute(
                """
                SELECT receipt_json, protection_record_digest_sha256, outcome
                FROM execution_receipts WHERE nonce = ?
                """,
                (nonce,),
            ).fetchone()
            if receipt_row is not None:
                if (
                    str(receipt_row["protection_record_digest_sha256"]) != protection_digest
                    or str(receipt_row["outcome"]) != outcome
                ):
                    raise ValueError("execution_receipt_conflict")
                return self._receipt_from_json(str(receipt_row["receipt_json"]))

            receipt_identity = {
                "authorization_digest_sha256": digest,
                "protection_record_digest_sha256": protection_digest,
                "outcome": outcome,
                "executor_id": claim.executor_id,
                "idempotency_key": claim.idempotency_key,
            }
            receipt_id = "exec-receipt-" + sha256(_canonical(receipt_identity)).hexdigest()[:32]
            receipt_body = {
                "contract_version": EXECUTION_STATE_CONTRACT_VERSION,
                "receipt_id": receipt_id,
                "nonce": nonce,
                "authorization_id": claim.authorization_id,
                "authorization_digest_sha256": digest,
                "executor_id": claim.executor_id,
                "action": claim.action,
                "correlation_id": claim.correlation_id,
                "scope": claim.scope,
                "idempotency_key": claim.idempotency_key,
                "outcome": outcome,
                "protection_record": protection_record,
                "protection_record_digest_sha256": protection_digest,
                "completed_at": observed.isoformat(),
            }
            receipt_digest = sha256(_canonical(receipt_body)).hexdigest()
            receipt = ExecutionReceipt(
                receipt_id=receipt_id,
                nonce=nonce,
                authorization_id=claim.authorization_id,
                authorization_digest_sha256=digest,
                executor_id=claim.executor_id,
                action=claim.action,
                correlation_id=claim.correlation_id,
                scope=copy.deepcopy(claim.scope),
                idempotency_key=claim.idempotency_key,
                outcome=str(outcome),
                protection_record=copy.deepcopy(protection_record),
                protection_record_digest_sha256=protection_digest,
                completed_at=observed.isoformat(),
                receipt_digest_sha256=receipt_digest,
            )
            connection.execute(
                """
                INSERT INTO execution_receipts (
                    nonce, receipt_json, protection_record_digest_sha256, outcome
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    nonce,
                    json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")),
                    protection_digest,
                    outcome,
                ),
            )
            connection.execute(
                "UPDATE execution_claims SET status = ? WHERE nonce = ?",
                (str(outcome), nonce),
            )
            return receipt

    def receipt(self, nonce: str) -> ExecutionReceipt | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT receipt_json FROM execution_receipts WHERE nonce = ?",
                (str(nonce),),
            ).fetchone()
            if row is None:
                return None
            return self._receipt_from_json(str(row["receipt_json"]))
        finally:
            connection.close()
