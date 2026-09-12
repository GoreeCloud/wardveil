#!/usr/bin/env python3
"""Wardveil next-upgrade Protection Coverage Registry reference model.

The registry is a source-level reference for per-application and per-service
coverage state. It preserves evidence freshness, adoption state, enforcement
coverage, gaps, and remediation without converting missing evidence into a
clean or Protected result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from wardveil_security_state_v2 import (
    ADOPTION_STATES,
    CAPABILITIES,
    COVERAGE_STATES,
    EVIDENCE_STATES,
    CoverageObservation,
    summarize_coverage,
)

SUBJECT_KINDS = ("application", "service")
SCOPE_KINDS = (
    "account",
    "application",
    "service",
    "device",
    "network",
    "data",
    "control",
    "platform",
    "other",
)


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_evidence_refs(references: tuple[str, ...]) -> None:
    if len(references) > 32:
        raise ValueError("coverage evidence references must contain at most 32 entries")
    if len(set(references)) != len(references):
        raise ValueError("coverage evidence references must be unique")
    for reference in references:
        if (
            not isinstance(reference, str)
            or not reference
            or reference != reference.strip()
            or len(reference) > 256
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in reference)
        ):
            raise ValueError("coverage evidence references must be bounded canonical text")


@dataclass(frozen=True)
class CoverageRegistryRecord:
    subject_kind: str
    subject_id: str
    scope_kind: str
    scope_id: str
    capability: str
    coverage_state: str
    adoption_state: str
    evidence_status: str
    observed_at: datetime
    valid_until: datetime | None
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    required_enforcement_points: tuple[str, ...] = field(default_factory=tuple)
    implemented_enforcement_points: tuple[str, ...] = field(default_factory=tuple)
    dependencies: tuple[str, ...] = field(default_factory=tuple)
    known_gaps: tuple[str, ...] = field(default_factory=tuple)
    remediation: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.subject_kind not in SUBJECT_KINDS:
            raise ValueError(f"unsupported subject kind: {self.subject_kind}")
        if not self.subject_id:
            raise ValueError("subject_id is required")
        if self.scope_kind not in SCOPE_KINDS:
            raise ValueError(f"unsupported scope kind: {self.scope_kind}")
        if not self.scope_id:
            raise ValueError("scope_id is required")
        if self.capability not in CAPABILITIES:
            raise ValueError(f"unsupported capability: {self.capability}")
        if self.coverage_state not in COVERAGE_STATES:
            raise ValueError(f"unsupported coverage state: {self.coverage_state}")
        if self.adoption_state not in ADOPTION_STATES:
            raise ValueError(f"unsupported adoption state: {self.adoption_state}")
        if self.evidence_status not in EVIDENCE_STATES:
            raise ValueError(f"unsupported evidence status: {self.evidence_status}")
        _validate_evidence_refs(self.evidence_refs)
        _require_aware(self.observed_at, "observed_at")
        if self.valid_until is not None:
            _require_aware(self.valid_until, "valid_until")
            if self.valid_until <= self.observed_at:
                raise ValueError("valid_until must be later than observed_at")
        if len(set(self.required_enforcement_points)) != len(self.required_enforcement_points):
            raise ValueError("required enforcement points must be unique")
        if len(set(self.implemented_enforcement_points)) != len(self.implemented_enforcement_points):
            raise ValueError("implemented enforcement points must be unique")

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.subject_kind,
            self.subject_id,
            self.scope_kind,
            self.scope_id,
            self.capability,
        )

    def as_observation(self) -> CoverageObservation:
        return CoverageObservation(
            capability=self.capability,
            coverage_state=self.coverage_state,
            adoption_state=self.adoption_state,
            evidence_status=self.evidence_status,
            evidence_refs=self.evidence_refs,
            observed_at=self.observed_at,
            valid_until=self.valid_until,
        )

    def effective_coverage_state(self, now: datetime | None = None) -> str:
        now = now or _utc_now()
        _require_aware(now, "now")
        base_state = self.as_observation().effective_coverage_state(now)
        if base_state == "covered":
            required = set(self.required_enforcement_points)
            implemented = set(self.implemented_enforcement_points)
            if not required.issubset(implemented):
                return "partial"
        return base_state

    def stable_qualification_impact(self, now: datetime | None = None) -> str:
        state = self.effective_coverage_state(now)
        if state == "covered" and self.adoption_state == "production_accepted":
            return "none"
        if state == "unknown":
            return "unknown"
        return "blocks_stable"

    def as_record(self, now: datetime | None = None) -> dict:
        now = now or _utc_now()
        effective = self.effective_coverage_state(now)
        evidence_status = self.evidence_status
        if self.observed_at > now:
            evidence_status = "unverified"
        elif self.evidence_status == "current" and (
            self.valid_until is None or self.valid_until <= now
        ):
            evidence_status = "stale"
        elif (
            self.evidence_status == "current"
            and self.coverage_state == "covered"
            and self.adoption_state == "production_accepted"
            and not self.evidence_refs
        ):
            evidence_status = "unverified"

        return {
            "contract_version": "0.2.0",
            "record_type": "protection_coverage",
            "record_id": f"coverage-{uuid4()}",
            "subject": {"kind": self.subject_kind, "id": self.subject_id},
            "scope": {"kind": self.scope_kind, "id": self.scope_id},
            "capability": self.capability,
            "coverage_state": effective,
            "adoption_state": self.adoption_state,
            "enforcement": {
                "required": list(self.required_enforcement_points),
                "implemented": list(self.implemented_enforcement_points),
            },
            "evidence": {
                "status": evidence_status,
                "observed_at": self.observed_at.isoformat(),
                **({"valid_until": self.valid_until.isoformat()} if self.valid_until else {}),
                "references": list(self.evidence_refs),
            },
            "dependencies": list(self.dependencies),
            "known_gaps": list(self.known_gaps),
            "remediation": list(self.remediation),
            "stable_qualification_impact": self.stable_qualification_impact(now),
        }


class ProtectionCoverageRegistry:
    """In-memory reference registry with fail-closed freshness semantics."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str, str, str], CoverageRegistryRecord] = {}

    def upsert(self, record: CoverageRegistryRecord) -> None:
        existing = self._records.get(record.key)
        if existing is not None and record.observed_at < existing.observed_at:
            raise ValueError("older coverage evidence cannot overwrite a newer registry record")
        if (
            existing is not None
            and record.observed_at == existing.observed_at
            and record != existing
        ):
            raise ValueError("conflicting coverage evidence at the same observation time")
        self._records[record.key] = record

    def get(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        scope_kind: str,
        scope_id: str,
        capability: str,
    ) -> CoverageRegistryRecord | None:
        return self._records.get((subject_kind, subject_id, scope_kind, scope_id, capability))

    def records_for(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        scope_kind: str,
        scope_id: str,
    ) -> tuple[CoverageRegistryRecord, ...]:
        matches = [
            record
            for record in self._records.values()
            if record.subject_kind == subject_kind
            and record.subject_id == subject_id
            and record.scope_kind == scope_kind
            and record.scope_id == scope_id
        ]
        return tuple(sorted(matches, key=lambda item: item.capability))

    def summarize(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        scope_kind: str,
        scope_id: str,
        required_capabilities: Iterable[str],
        now: datetime | None = None,
    ) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        now = now or _utc_now()
        records = self.records_for(
            subject_kind=subject_kind,
            subject_id=subject_id,
            scope_kind=scope_kind,
            scope_id=scope_id,
        )
        observations = tuple(
            CoverageObservation(
                capability=record.capability,
                coverage_state=record.effective_coverage_state(now),
                adoption_state=record.adoption_state,
                evidence_status="current"
                if record.effective_coverage_state(now) not in ("stale", "unknown")
                else ("stale" if record.effective_coverage_state(now) == "stale" else "unverified"),
                evidence_refs=record.evidence_refs,
                observed_at=record.observed_at,
                valid_until=record.valid_until,
            )
            for record in records
        )
        return summarize_coverage(required_capabilities, observations, now=now)

    def export_records(self, now: datetime | None = None) -> tuple[dict, ...]:
        now = now or _utc_now()
        return tuple(
            record.as_record(now)
            for record in sorted(self._records.values(), key=lambda item: item.key)
        )