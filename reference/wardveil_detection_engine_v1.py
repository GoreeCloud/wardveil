#!/usr/bin/env python3
"""Wardveil Behavioral Detection Engine V1 development reference.

This module correlates authoritative behavioral security signals into an
explainable detection assessment. It does not collect telemetry, execute
containment, grant target-resource authority, or establish production
protection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

CONTRACT_VERSION = "0.1.0"

SIGNAL_CATEGORIES = (
    "privilege_escalation",
    "credential_harvesting",
    "suspicious_process_spawn",
    "mass_file_encryption",
    "persistence_attempt",
    "unauthorized_system_modification",
    "anomalous_network_activity",
    "sensitive_file_access",
    "abnormal_background_activity",
    "administrative_anomaly",
    "rapid_permission_change",
    "post_update_behavior_change",
)

SEVERITIES = ("informational", "low", "medium", "high", "critical")
DISPOSITIONS = ("unknown", "informational", "suspicious", "likely_malicious")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


def _text(value: str, field: str, max_length: int = 256) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field}_required")
    if len(normalized) > max_length:
        raise ValueError(f"{field}_too_long")
    return normalized


def _confidence(value: float) -> float:
    try:
        normalized = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("confidence_invalid") from error
    if not 0.0 <= normalized <= 1.0:
        raise ValueError("confidence_out_of_range")
    return normalized


def _refs(values: Iterable[str], *, max_items: int = 32) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
    if not normalized:
        raise ValueError("evidence_refs_required")
    if len(normalized) > max_items:
        raise ValueError("evidence_refs_too_many")
    if any(len(value) > 256 for value in normalized):
        raise ValueError("evidence_ref_too_long")
    return normalized


@dataclass(frozen=True)
class BehavioralSignal:
    signal_id: str
    category: str
    resource_type: str
    resource_id: str
    producer_id: str
    authority_domain: str
    severity: str
    confidence: float
    observed_at: datetime
    valid_until: datetime
    evidence_refs: tuple[str, ...]
    authoritative: bool = True

    def normalized(self) -> "BehavioralSignal":
        if self.category not in SIGNAL_CATEGORIES:
            raise ValueError("unsupported_signal_category")
        if self.severity not in SEVERITIES:
            raise ValueError("unsupported_signal_severity")
        observed_at = _utc(self.observed_at)
        valid_until = _utc(self.valid_until)
        if valid_until < observed_at:
            raise ValueError("signal_valid_until_before_observed_at")
        return BehavioralSignal(
            signal_id=_text(self.signal_id, "signal_id", 160),
            category=self.category,
            resource_type=_text(self.resource_type, "resource_type", 128),
            resource_id=_text(self.resource_id, "resource_id"),
            producer_id=_text(self.producer_id, "producer_id", 128),
            authority_domain=_text(self.authority_domain, "authority_domain", 128),
            severity=self.severity,
            confidence=_confidence(self.confidence),
            observed_at=observed_at,
            valid_until=valid_until,
            evidence_refs=_refs(self.evidence_refs),
            authoritative=bool(self.authoritative),
        )


@dataclass(frozen=True)
class DetectionAssessment:
    resource_type: str
    resource_id: str
    disposition: str
    severity: str
    confidence: float
    correlated: bool
    signal_categories: tuple[str, ...]
    producer_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime
    incident_candidate: bool
    execution_authority: bool = False

    def as_record(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": "detection_assessment",
            "resource": {
                "type": self.resource_type,
                "id": self.resource_id,
            },
            "disposition": self.disposition,
            "severity": self.severity,
            "confidence": self.confidence,
            "correlated": self.correlated,
            "signal_categories": list(self.signal_categories),
            "producer_ids": list(self.producer_ids),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "incident_candidate": self.incident_candidate,
            "execution_authority": False,
        }


def assess_behavioral_signals(
    signals: Iterable[BehavioralSignal],
    *,
    now: datetime | None = None,
    correlation_window: timedelta = timedelta(minutes=5),
) -> DetectionAssessment:
    current = _utc(now or datetime.now(timezone.utc))
    if correlation_window <= timedelta(0) or correlation_window > timedelta(hours=1):
        raise ValueError("correlation_window_out_of_bounds")

    normalized = tuple(signal.normalized() for signal in signals)
    if not normalized:
        return DetectionAssessment(
            resource_type="unknown",
            resource_id="unknown",
            disposition="unknown",
            severity="informational",
            confidence=0.0,
            correlated=False,
            signal_categories=(),
            producer_ids=(),
            evidence_refs=(),
            reason_codes=("missing_behavioral_evidence",),
            observed_at=current,
            valid_until=current,
            incident_candidate=False,
        )

    resources = {(signal.resource_type, signal.resource_id) for signal in normalized}
    if len(resources) != 1:
        raise ValueError("mixed_resource_signals_require_partitioning")

    seen: dict[str, BehavioralSignal] = {}
    for signal in normalized:
        previous = seen.get(signal.signal_id)
        if previous is None:
            seen[signal.signal_id] = signal
            continue
        if previous != signal:
            raise ValueError("conflicting_signal_id_reuse")

    unique = tuple(seen.values())
    fresh_authoritative = tuple(
        signal
        for signal in unique
        if signal.authoritative
        and signal.observed_at <= current
        and signal.valid_until >= current
        and current - signal.observed_at <= correlation_window
    )

    resource_type, resource_id = next(iter(resources))
    excluded_untrusted = any(not signal.authoritative for signal in unique)
    excluded_stale = any(
        signal.authoritative
        and (
            signal.observed_at > current
            or signal.valid_until < current
            or current - signal.observed_at > correlation_window
        )
        for signal in unique
    )

    if not fresh_authoritative:
        reasons = ["no_fresh_authoritative_behavioral_evidence"]
        if excluded_untrusted:
            reasons.append("untrusted_signals_excluded")
        if excluded_stale:
            reasons.append("stale_or_future_signals_excluded")
        return DetectionAssessment(
            resource_type=resource_type,
            resource_id=resource_id,
            disposition="unknown",
            severity="informational",
            confidence=0.0,
            correlated=False,
            signal_categories=(),
            producer_ids=(),
            evidence_refs=(),
            reason_codes=tuple(reasons),
            observed_at=current,
            valid_until=current,
            incident_candidate=False,
        )

    categories = tuple(dict.fromkeys(signal.category for signal in fresh_authoritative))
    producers = tuple(dict.fromkeys(signal.producer_id for signal in fresh_authoritative))
    evidence = tuple(dict.fromkeys(ref for signal in fresh_authoritative for ref in signal.evidence_refs))
    confidence = max(signal.confidence for signal in fresh_authoritative)
    severity = max(fresh_authoritative, key=lambda signal: SEVERITY_RANK[signal.severity]).severity
    correlated = len(categories) >= 2 and len(evidence) >= 2

    reasons: list[str] = []
    if correlated:
        reasons.append("multiple_authoritative_behavior_categories_correlated")
    else:
        reasons.append("single_behavior_category_requires_corroboration")
    if len(producers) >= 2:
        reasons.append("independent_producers_present")
    if excluded_untrusted:
        reasons.append("untrusted_signals_excluded")
    if excluded_stale:
        reasons.append("stale_or_future_signals_excluded")

    if correlated and SEVERITY_RANK[severity] >= SEVERITY_RANK["high"] and confidence >= 0.8:
        disposition = "likely_malicious"
    elif confidence >= 0.5 or SEVERITY_RANK[severity] >= SEVERITY_RANK["medium"]:
        disposition = "suspicious"
    else:
        disposition = "informational"

    incident_candidate = (
        disposition in {"suspicious", "likely_malicious"}
        and SEVERITY_RANK[severity] >= SEVERITY_RANK["medium"]
    )

    return DetectionAssessment(
        resource_type=resource_type,
        resource_id=resource_id,
        disposition=disposition,
        severity=severity,
        confidence=confidence,
        correlated=correlated,
        signal_categories=categories,
        producer_ids=producers,
        evidence_refs=evidence,
        reason_codes=tuple(reasons),
        observed_at=max(signal.observed_at for signal in fresh_authoritative),
        valid_until=min(signal.valid_until for signal in fresh_authoritative),
        incident_candidate=incident_candidate,
    )
