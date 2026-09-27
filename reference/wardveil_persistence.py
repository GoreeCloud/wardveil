"""Dependency-free Wardveil persistence abstraction and conformance reference."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import copy
import json
from typing import Protocol

SCHEMA_VERSION = 1


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


@dataclass(frozen=True)
class PersistenceRecord:
    sequence: int
    schema_version: int
    stored_at: str
    retention_class: str
    payload: dict
    digest: str
    encryption_state: str
    key_id: str | None = None


@dataclass(frozen=True)
class Checkpoint:
    consumer_id: str
    sequence: int
    updated_at: str
    generation: int


@dataclass(frozen=True)
class StorageHealthEvidence:
    observed_at: str
    backend: str
    transactional_writes: bool
    integrity_verified: bool
    encryption_at_rest: str
    retention_enforcement: str
    backup_state: str
    recovery_verification: str
    degraded_reasons: tuple[str, ...] = ()

    @property
    def healthy(self) -> bool:
        return not self.degraded_reasons

    def as_dict(self) -> dict:
        return {
            "observed_at": self.observed_at,
            "backend": self.backend,
            "transactional_writes": self.transactional_writes,
            "integrity_verified": self.integrity_verified,
            "encryption_at_rest": self.encryption_at_rest,
            "retention_enforcement": self.retention_enforcement,
            "backup_state": self.backup_state,
            "recovery_verification": self.recovery_verification,
            "degraded_reasons": list(self.degraded_reasons),
            "healthy": self.healthy,
            "protection_claim": False,
        }


class EncryptionProvider(Protocol):
    provider_id: str
    def protect(self, payload: dict) -> tuple[dict, str | None]: ...
    def reveal(self, payload: dict, key_id: str | None) -> dict: ...


class PassthroughEncryption:
    provider_id = "reference-none"
    def protect(self, payload: dict) -> tuple[dict, str | None]:
        return copy.deepcopy(payload), None
    def reveal(self, payload: dict, key_id: str | None) -> dict:
        return copy.deepcopy(payload)


class Transaction:
    def __init__(self, adapter: "InMemoryPersistenceAdapter") -> None:
        self.adapter = adapter
        self._records: list[tuple[dict, str]] = []
        self._checkpoints: list[tuple[str, int]] = []
        self._committed = False

    def append(self, record: dict, *, retention_class: str = "security_event") -> None:
        if self._committed:
            raise RuntimeError("transaction_closed")
        self._records.append((copy.deepcopy(record), retention_class))

    def checkpoint(self, consumer_id: str, sequence: int) -> None:
        if self._committed:
            raise RuntimeError("transaction_closed")
        self._checkpoints.append((consumer_id, sequence))

    def commit(self, *, now: datetime | None = None) -> tuple[PersistenceRecord, ...]:
        if self._committed:
            raise RuntimeError("transaction_closed")
        self._committed = True
        return self.adapter._commit(self._records, self._checkpoints, now=_utc(now))

    def rollback(self) -> None:
        self._records.clear()
        self._checkpoints.clear()
        self._committed = True


class InMemoryPersistenceAdapter:
    """Conformance adapter. Models atomicity and boundaries, not production durability."""

    backend_name = "reference-memory"

    def __init__(self, *, encryption: EncryptionProvider | None = None) -> None:
        self.encryption = encryption or PassthroughEncryption()
        self._records: list[PersistenceRecord] = []
        self._record_ids: set[str] = set()
        self._checkpoints: dict[str, Checkpoint] = {}
        self._generation = 0
        self._backup: tuple[PersistenceRecord, ...] | None = None

    def begin(self) -> Transaction:
        return Transaction(self)

    def _validate_record(self, record: dict) -> None:
        if not record.get("record_id") or not record.get("correlation_id"):
            raise ValueError("invalid_record")
        producer = record.get("producer") or {}
        if producer.get("authoritative") is not True or not producer.get("id"):
            raise ValueError("non_authoritative_record")
        if record["record_id"] in self._record_ids:
            raise ValueError("duplicate_record_id")

    def _commit(self, records: list[tuple[dict, str]], checkpoints: list[tuple[str, int]], *, now: datetime) -> tuple[PersistenceRecord, ...]:
        staged_ids: set[str] = set()
        for record, _retention in records:
            self._validate_record(record)
            if record["record_id"] in staged_ids:
                raise ValueError("duplicate_record_id")
            staged_ids.add(record["record_id"])
        for consumer_id, sequence in checkpoints:
            if not consumer_id or sequence < 0:
                raise ValueError("invalid_checkpoint")
            current = self._checkpoints.get(consumer_id)
            if current and sequence < current.sequence:
                raise ValueError("checkpoint_regression")

        created: list[PersistenceRecord] = []
        next_sequence = len(self._records) + 1
        for offset, (record, retention_class) in enumerate(records):
            protected, key_id = self.encryption.protect(record)
            created.append(PersistenceRecord(
                sequence=next_sequence + offset,
                schema_version=SCHEMA_VERSION,
                stored_at=now.isoformat(),
                retention_class=retention_class,
                payload=protected,
                digest=sha256(_canonical(record)).hexdigest(),
                encryption_state="encrypted" if key_id else "unencrypted_reference",
                key_id=key_id,
            ))

        # Atomic mutation happens only after all validation and transformation succeed.
        self._records.extend(created)
        self._record_ids.update(staged_ids)
        self._generation += 1
        for consumer_id, sequence in checkpoints:
            self._checkpoints[consumer_id] = Checkpoint(consumer_id, sequence, now.isoformat(), self._generation)
        return tuple(created)

    def records(self) -> tuple[dict, ...]:
        output = []
        for row in self._records:
            payload = self.encryption.reveal(row.payload, row.key_id)
            if sha256(_canonical(payload)).hexdigest() != row.digest:
                raise ValueError("integrity_verification_failed")
            output.append(payload)
        return tuple(output)

    def checkpoint(self, consumer_id: str) -> Checkpoint:
        return self._checkpoints.get(consumer_id, Checkpoint(consumer_id, 0, "", 0))

    def migrate(self, target_version: int) -> None:
        if target_version < SCHEMA_VERSION:
            raise ValueError("schema_downgrade_not_supported")
        if target_version != SCHEMA_VERSION:
            raise ValueError("unsupported_schema_version")

    def create_backup(self) -> str:
        self._backup = copy.deepcopy(tuple(self._records))
        return sha256(_canonical([r.digest for r in self._backup])).hexdigest()

    def verify_backup_restore(self) -> bool:
        if self._backup is None:
            return False
        restored = copy.deepcopy(self._backup)
        for row in restored:
            payload = self.encryption.reveal(row.payload, row.key_id)
            if sha256(_canonical(payload)).hexdigest() != row.digest:
                return False
        return True

    def health_evidence(self, *, now: datetime | None = None) -> StorageHealthEvidence:
        now = _utc(now)
        degraded: list[str] = []
        try:
            self.records()
            integrity = True
        except ValueError:
            integrity = False
            degraded.append("integrity_verification_failed")
        if self.encryption.provider_id == "reference-none":
            degraded.append("encryption_at_rest_not_configured")
        backup_state = "available" if self._backup is not None else "missing"
        recovery = "verified" if self.verify_backup_restore() else "unverified"
        if backup_state == "missing":
            degraded.append("backup_missing")
        if recovery != "verified":
            degraded.append("recovery_unverified")
        return StorageHealthEvidence(
            observed_at=now.isoformat(),
            backend=self.backend_name,
            transactional_writes=True,
            integrity_verified=integrity,
            encryption_at_rest="configured" if self.encryption.provider_id != "reference-none" else "not_configured",
            retention_enforcement="adapter_contract_only",
            backup_state=backup_state,
            recovery_verification=recovery,
            degraded_reasons=tuple(sorted(set(degraded))),
        )
