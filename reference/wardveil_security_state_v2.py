#!/usr/bin/env python3
"""Wardveil next-upgrade security-state and protection-coverage reference model.

This module is a dependency-free source reference. It defines deterministic
contract behavior for the next Wardveil upgrade, but it is not itself evidence
of runtime or production protection.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

SECURITY_STATES = (
    "protected",
    "at_risk",
    "action_required",
    "unknown",
    "not_covered",
    "degraded",
    "contained",
    "recovering",
    "reconciliation_required",
)

COVERAGE_STATES = (
    "covered",
    "partial",
    "not_covered",
    "unknown",
    "stale",
    "degraded",
)

ADOPTION_STATES = (
    "planned",
    "implemented",
    "source_validated",
    "runtime_validated",
    "production_accepted",
)

EVIDENCE_STATES = ("current", "stale", "unavailable", "unverified")
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

CAPABILITIES = (
    "authentication_protection",
    "authorization_enforcement",
    "session_protection",
    "device_trust",
    "malware_protection",
    "malicious_url_protection",
    "vulnerability_monitoring",
    "security_update_posture",
    "secret_protection",
    "network_exposure_controls",
    "runtime_integrity",
    "security_event_reporting",
    "audit_coverage",
    "recovery_security_verification",
)

# Lower index is more conservative for conflicting observations. This mirrors
# summarize_coverage()'s existing aggregate precedence while removing the prior
# order-dependent last-write-wins behavior for duplicate capabilities.
COVERAGE_PRECEDENCE = (
    "not_covered",
    "partial",
    "unknown",
    "stale",
    "degraded",
    "covered",
)

LEGACY_PRESENTATION_MAP = {
    "protected": "protected",
    "at_risk": "attention",
    "action_required": "attention",
    "unknown": "unknown",
    "not_covered": "unknown",
    "degraded": "degraded",
    "contained": "attention",
    "recovering": "degraded",
    "reconciliation_required": "degraded",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _validate_scope(scope_kind: str, scope_id: str) -> tuple[str, str]:
    if scope_kind not in SCOPE_KINDS:
        raise ValueError(f"unsupported scope kind: {scope_kind}")
    if not isinstance(scope_id, str) or not scope_id or scope_id != scope_id.strip():
        raise ValueError("scope_id must be a non-empty canonical identifier")
    if len(scope_id) > 128 or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in scope_id):
        raise ValueError("scope_id must be bounded and control-free")
    return scope_kind, scope_id


def _validate_coverage_evidence_refs(references: tuple[str, ...]) -> None:
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
class EvidenceObservation:
    evidence_id: str
    producer_id: str
    control: str
    scope_kind: str
    scope_id: str
    authoritative: bool
    status: str
    observed_at: datetime
    valid_until: datetime | None = None
    verifies_protection: bool = False

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.producer_id:
            raise ValueError("producer_id is required")
        if not self.control:
            raise ValueError("control is required")
        _validate_scope(self.scope_kind, self.scope_id)
        if self.status not in EVIDENCE_STATES:
            raise ValueError(f"unsupported evidence status: {self.status}")
        _require_aware(self.observed_at, "observed_at")
        if self.valid_until is not None:
            _require_aware(self.valid_until, "valid_until")
            if self.valid_until <= self.observed_at:
                raise ValueError("valid_until must be later than observed_at")

    def effective_status(self, now: datetime) -> str:
        _require_aware(now, "now")
        if not self.authoritative:
            return "unverified"
        if self.status != "current":
            return self.status
        if self.observed_at > now:
            return "unverified"
        if self.valid_until is None or self.valid_until <= now:
            return "stale"
        return "current"


@dataclass(frozen=True)
class CoverageObservation:
    capability: str
    coverage_state: str
    adoption_state: str
    evidence_status: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    observed_at: datetime | None = None
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.capability not in CAPABILITIES:
            raise ValueError(f"unsupported capability: {self.capability}")
        if self.coverage_state not in COVERAGE_STATES:
            raise ValueError(f"unsupported coverage state: {self.coverage_state}")
        if self.adoption_state not in ADOPTION_STATES:
            raise ValueError(f"unsupported adoption state: {self.adoption_state}")
        if self.evidence_status not in EVIDENCE_STATES:
            raise ValueError(f"unsupported evidence status: {self.evidence_status}")
        _validate_coverage_evidence_refs(self.evidence_refs)
        if self.observed_at is not None:
            _require_aware(self.observed_at, "observed_at")
        if self.valid_until is not None:
            _require_aware(self.valid_until, "valid_until")
            if self.observed_at is None:
                raise ValueError("valid_until requires observed_at")
            if self.valid_until <= self.observed_at:
                raise ValueError("valid_until must be later than observed_at")

    def current(self, now: datetime) -> bool:
        _require_aware(now, "now")
        if self.evidence_status != "current":
            return False
        if self.observed_at is None or self.valid_until is None:
            return False
        if self.coverage_state == "covered" and self.adoption_state == "production_accepted" and not self.evidence_refs:
            return False
        return self.observed_at <= now < self.valid_until

    def effective_coverage_state(self, now: datetime) -> str:
        """Return coverage without converting uncertainty into reassurance."""

        _require_aware(now, "now")
        if self.adoption_state == "planned" or self.coverage_state == "not_covered":
            return "not_covered"
        if self.evidence_status in ("unavailable", "unverified"):
            return "unknown"
        if self.evidence_status == "stale":
            return "stale"
        if self.observed_at is None or self.valid_until is None:
            return "unknown"
        if self.observed_at > now:
            return "unknown"
        if self.valid_until <= now:
            return "stale"
        if self.coverage_state in ("unknown", "stale", "degraded", "partial"):
            return self.coverage_state
        if self.adoption_state != "production_accepted":
            return "partial"
        if not self.evidence_refs:
            return "unknown"
        return "covered"


@dataclass(frozen=True)
class SecuritySignals:
    active_threat: bool = False
    action_required: bool = False
    contained: bool = False
    recovering: bool = False
    degraded: bool = False
    reconciliation_required: bool = False


@dataclass(frozen=True)
class SecurityAssessment:
    state: str
    coverage_state: str
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime | None
    protected_by_wardveil: bool
    scope_kind: str = ""
    scope_id: str = ""

    @property
    def legacy_presentation_state(self) -> str:
        return LEGACY_PRESENTATION_MAP[self.state]

    def as_record(
        self,
        *,
        scope_kind: str | None = None,
        scope_id: str | None = None,
        authority_system: str = "wardveil",
        authority_control: str = "security_state_engine",
    ) -> dict:
        bound_kind, bound_id = _validate_scope(self.scope_kind, self.scope_id)
        if scope_kind is not None or scope_id is not None:
            if scope_kind is None or scope_id is None:
                raise ValueError("scope_kind and scope_id must be supplied together")
            requested_kind, requested_id = _validate_scope(scope_kind, scope_id)
            if (requested_kind, requested_id) != (bound_kind, bound_id):
                raise ValueError("security assessment scope cannot be relabeled")
        return {
            "contract_version": "0.2.0",
            "record_type": "security_state",
            "record_id": f"security-state-{uuid4()}",
            "scope": {"kind": bound_kind, "id": bound_id},
            "authority": {
                "system": authority_system,
                "control": authority_control,
                "authoritative": True,
            },
            "state": self.state,
            "coverage": {"status": self.coverage_state},
            "evidence": {
                "status": "current" if self.protected_by_wardveil else _assessment_evidence_status(self),
                "observed_at": self.observed_at.isoformat(),
                **({"valid_until": self.valid_until.isoformat()} if self.valid_until else {}),
                "references": list(self.evidence_refs),
            },
            "claim": {"protected_by_wardveil": self.protected_by_wardveil},
            "explanation": {
                "reason_codes": list(self.reason_codes),
                "legacy_presentation_state": self.legacy_presentation_state,
            },
        }


def _assessment_evidence_status(assessment: SecurityAssessment) -> str:
    reasons = set(assessment.reason_codes)
    if "required_evidence_unavailable" in reasons:
        return "unavailable"
    if (
        "required_evidence_unverified" in reasons
        or "required_evidence_scope_mismatch" in reasons
        or "required_evidence_identity_conflict" in reasons
    ):
        return "unverified"
    if "required_evidence_stale" in reasons or "coverage_evidence_stale" in reasons:
        return "stale"
    return "current"


def _conflicting_evidence_ids(observations: Iterable[EvidenceObservation]) -> tuple[str, ...]:
    """Return evidence IDs reused for materially different observations."""

    first_by_id: dict[str, EvidenceObservation] = {}
    conflicts: list[str] = []
    for item in observations:
        previous = first_by_id.get(item.evidence_id)
        if previous is None:
            first_by_id[item.evidence_id] = item
            continue
        if previous != item and item.evidence_id not in conflicts:
            conflicts.append(item.evidence_id)
    return tuple(conflicts)


def _conservative_coverage_state(
    observations: Iterable[CoverageObservation],
    *,
    now: datetime,
) -> str:
    """Resolve duplicate capability observations deterministically and fail closed."""

    effective_states = {
        item.effective_coverage_state(now)
        for item in observations
    }
    if not effective_states:
        return "not_covered"
    return next(
        state for state in COVERAGE_PRECEDENCE
        if state in effective_states
    )


def summarize_coverage(
    required_capabilities: Iterable[str],
    coverage: Iterable[CoverageObservation],
    *,
    now: datetime | None = None,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    now = now or _utc_now()
    _require_aware(now, "now")
    required = tuple(dict.fromkeys(required_capabilities))
    for capability in required:
        if capability not in CAPABILITIES:
            raise ValueError(f"unsupported required capability: {capability}")

    by_capability: dict[str, list[CoverageObservation]] = {}
    for item in coverage:
        by_capability.setdefault(item.capability, []).append(item)

    missing: list[str] = []
    uncertain: list[str] = []
    partial: list[str] = []
    stale: list[str] = []
    degraded: list[str] = []
    covered: list[str] = []

    for capability in required:
        items = by_capability.get(capability)
        if not items:
            missing.append(capability)
            continue

        effective = _conservative_coverage_state(items, now=now)
        if effective == "not_covered":
            missing.append(capability)
        elif effective == "unknown":
            uncertain.append(capability)
        elif effective == "partial":
            partial.append(capability)
        elif effective == "stale":
            stale.append(capability)
        elif effective == "degraded":
            degraded.append(capability)
        else:
            covered.append(capability)

    if not required:
        return "unknown", (), ()
    if len(missing) == len(required):
        return "not_covered", tuple(missing), ()
    if missing or partial:
        return "partial", tuple(missing), tuple(partial + uncertain + stale + degraded)
    if uncertain:
        return "unknown", (), tuple(uncertain)
    if stale:
        return "stale", (), tuple(stale)
    if degraded:
        return "degraded", (), tuple(degraded)
    if len(covered) == len(required):
        return "covered", (), ()
    return "unknown", (), tuple(required)


def _evaluate_security_state_unscoped(
    *,
    evidence: Iterable[EvidenceObservation],
    coverage: Iterable[CoverageObservation],
    required_capabilities: Iterable[str],
    signals: SecuritySignals = SecuritySignals(),
    now: datetime | None = None,
) -> SecurityAssessment:
    now = now or _utc_now()
    _require_aware(now, "now")

    observations = tuple(evidence)
    coverage_state, missing_caps, uncertain_caps = summarize_coverage(
        required_capabilities, coverage, now=now
    )

    evidence_refs = tuple(dict.fromkeys(item.evidence_id for item in observations))
    reason_codes: list[str] = []
    valid_until_values: list[datetime] = []

    effective = [item.effective_status(now) for item in observations]
    for item in observations:
        if item.valid_until is not None and item.effective_status(now) == "current":
            valid_until_values.append(item.valid_until)

    if coverage_state == "not_covered":
        reason_codes.extend(f"capability_not_covered:{cap}" for cap in missing_caps)
        return SecurityAssessment(
            "not_covered",
            coverage_state,
            tuple(reason_codes or ("required_capability_not_covered",)),
            evidence_refs,
            now,
            None,
            False,
        )

    if not observations:
        return SecurityAssessment(
            "unknown",
            coverage_state,
            ("required_evidence_unavailable",),
            (),
            now,
            None,
            False,
        )

    if "unverified" in effective:
        reason_codes.append("required_evidence_unverified")
    if "unavailable" in effective:
        reason_codes.append("required_evidence_unavailable")
    if "stale" in effective:
        reason_codes.append("required_evidence_stale")

    if reason_codes:
        return SecurityAssessment(
            "unknown",
            coverage_state,
            tuple(dict.fromkeys(reason_codes)),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )

    if coverage_state == "unknown":
        details = tuple(
            f"capability_coverage_unverified:{cap}" for cap in uncertain_caps
        ) or ("coverage_unknown",)
        return SecurityAssessment(
            "unknown",
            coverage_state,
            details,
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if coverage_state == "stale":
        return SecurityAssessment(
            "unknown",
            coverage_state,
            ("coverage_evidence_stale",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )

    if signals.reconciliation_required:
        return SecurityAssessment(
            "reconciliation_required",
            coverage_state,
            ("execution_outcome_uncertain",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if signals.active_threat:
        return SecurityAssessment(
            "at_risk",
            coverage_state,
            ("active_security_threat",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if signals.action_required:
        return SecurityAssessment(
            "action_required",
            coverage_state,
            ("security_action_required",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if signals.contained:
        return SecurityAssessment(
            "contained",
            coverage_state,
            ("threat_contained_pending_resolution",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if signals.recovering:
        return SecurityAssessment(
            "recovering",
            coverage_state,
            ("recovery_in_progress",),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )
    if signals.degraded or coverage_state in ("partial", "degraded"):
        details = ["security_control_degraded"] if signals.degraded else []
        if coverage_state == "degraded":
            details.append("coverage_degraded")
        details.extend(f"capability_not_covered:{cap}" for cap in missing_caps)
        details.extend(f"capability_not_production_accepted:{cap}" for cap in uncertain_caps)
        return SecurityAssessment(
            "degraded",
            coverage_state,
            tuple(dict.fromkeys(details or ("coverage_partial",))),
            evidence_refs,
            now,
            min(valid_until_values) if valid_until_values else None,
            False,
        )

    protection_evidence = [item for item in observations if item.verifies_protection]
    if (
        coverage_state == "covered"
        and protection_evidence
        and all(item.authoritative and item.effective_status(now) == "current" for item in observations)
    ):
        return SecurityAssessment(
            "protected",
            coverage_state,
            ("current_authoritative_protection_evidence",),
            evidence_refs,
            now,
            min(valid_until_values),
            True,
        )

    return SecurityAssessment(
        "unknown",
        coverage_state,
        ("no_authoritative_protection_verification",),
        evidence_refs,
        now,
        min(valid_until_values) if valid_until_values else None,
        False,
    )


def evaluate_security_state(
    *,
    scope_kind: str,
    scope_id: str,
    evidence: Iterable[EvidenceObservation],
    coverage: Iterable[CoverageObservation],
    required_capabilities: Iterable[str],
    signals: SecuritySignals = SecuritySignals(),
    now: datetime | None = None,
) -> SecurityAssessment:
    """Evaluate evidence only for the exact scope represented by the assessment."""

    scope_kind, scope_id = _validate_scope(scope_kind, scope_id)
    observations = tuple(evidence)
    evidence_refs = tuple(dict.fromkeys(item.evidence_id for item in observations))
    observed_at = now or _utc_now()
    _require_aware(observed_at, "now")

    if _conflicting_evidence_ids(observations):
        coverage_state, _, _ = summarize_coverage(
            required_capabilities, coverage, now=observed_at
        )
        return SecurityAssessment(
            "unknown",
            coverage_state,
            ("required_evidence_identity_conflict",),
            evidence_refs,
            observed_at,
            None,
            False,
            scope_kind,
            scope_id,
        )

    if any(
        item.scope_kind != scope_kind or item.scope_id != scope_id
        for item in observations
    ):
        coverage_state, _, _ = summarize_coverage(
            required_capabilities, coverage, now=observed_at
        )
        return SecurityAssessment(
            "unknown",
            coverage_state,
            ("required_evidence_scope_mismatch",),
            evidence_refs,
            observed_at,
            None,
            False,
            scope_kind,
            scope_id,
        )

    assessment = _evaluate_security_state_unscoped(
        evidence=observations,
        coverage=coverage,
        required_capabilities=required_capabilities,
        signals=signals,
        now=observed_at,
    )
    return replace(assessment, scope_kind=scope_kind, scope_id=scope_id)