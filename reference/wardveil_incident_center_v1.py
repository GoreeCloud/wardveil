#!/usr/bin/env python3
"""Wardveil Incident Center V1 Development review-intake reference.

This module bridges Detection Engine V1 assessments into non-authorizing
incident review cases. It does not create/transition incidents, quarantine
resources, execute containment, request recovery, or establish production
protection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from math import isfinite
from typing import Iterable

from reference.wardveil_detection_engine_v1 import (
    DISPOSITIONS,
    SEVERITIES,
    SEVERITY_RANK,
    SIGNAL_CATEGORIES,
    DetectionAssessment,
)

CONTRACT_VERSION = "0.1.0"
STATUS_VALUES = ("unknown", "review_required")
PRIORITY_BY_SEVERITY = {
    "informational": "routine",
    "low": "routine",
    "medium": "attention",
    "high": "high",
    "critical": "critical",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}_must_be_string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field}_required")
    if normalized != value:
        raise ValueError(f"{field}_must_be_canonical")
    if len(normalized) > maximum:
        raise ValueError(f"{field}_too_long")
    return normalized


def _bounded_unique(values: Iterable[str], field: str, maximum_items: int, maximum_length: int) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _text(value, field, maximum_length)
        if item not in seen:
            seen.add(item)
            normalized.append(item)
    if len(normalized) > maximum_items:
        raise ValueError(f"{field}_too_many")
    return tuple(normalized)


def _case_id(
    resource_type: str,
    resource_id: str,
    evidence_refs: tuple[str, ...],
    observed_at: datetime,
    valid_until: datetime,
) -> str:
    material = json.dumps(
        {
            "resource": {"type": resource_type, "id": resource_id},
            "evidence_refs": sorted(evidence_refs),
            "observed_at": observed_at.isoformat(),
            "valid_until": valid_until.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "wicv1-" + sha256(material.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class IncidentReviewCase:
    case_id: str
    resource_type: str
    resource_id: str
    status: str
    review_priority: str
    assessment_count: int
    correlated_assessment_count: int
    dispositions: tuple[str, ...]
    signal_categories: tuple[str, ...]
    producer_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime
    incident_established: bool = False
    execution_authority: bool = False
    containment_authority: bool = False
    production_accepted: bool = False

    def as_record(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": "incident_review_case",
            "case_id": self.case_id,
            "resource": {"type": self.resource_type, "id": self.resource_id},
            "status": self.status,
            "review_priority": self.review_priority,
            "assessment_count": self.assessment_count,
            "correlated_assessment_count": self.correlated_assessment_count,
            "dispositions": list(self.dispositions),
            "signal_categories": list(self.signal_categories),
            "producer_ids": list(self.producer_ids),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "incident_established": False,
            "execution_authority": False,
            "containment_authority": False,
            "production_accepted": False,
        }


def build_incident_review_case(
    assessments: Iterable[DetectionAssessment],
    *,
    now: datetime | None = None,
    max_assessment_age: timedelta = timedelta(minutes=15),
) -> IncidentReviewCase:
    current = _utc(now or datetime.now(timezone.utc))
    if max_assessment_age <= timedelta(0) or max_assessment_age > timedelta(hours=1):
        raise ValueError("max_assessment_age_out_of_bounds")

    values = tuple(assessments)
    if len(values) > 64:
        raise ValueError("too_many_detection_assessments")
    if not values:
        return IncidentReviewCase(
            case_id=_case_id("unknown", "unknown", (), current, current),
            resource_type="unknown",
            resource_id="unknown",
            status="unknown",
            review_priority="routine",
            assessment_count=0,
            correlated_assessment_count=0,
            dispositions=(),
            signal_categories=(),
            producer_ids=(),
            evidence_refs=(),
            reason_codes=("missing_detection_assessments",),
            observed_at=current,
            valid_until=current,
        )

    normalized: list[tuple[DetectionAssessment, datetime, datetime]] = []
    resources: set[tuple[str, str]] = set()
    seen_assessments: set[DetectionAssessment] = set()
    for assessment in values:
        if not isinstance(assessment, DetectionAssessment):
            raise TypeError("incident_center_requires_detection_assessments")
        if assessment in seen_assessments:
            raise ValueError("duplicate_detection_assessment")
        seen_assessments.add(assessment)
        if assessment.execution_authority is not False:
            raise ValueError("detection_assessment_must_not_claim_execution_authority")
        try:
            confidence = float(assessment.confidence)
        except (TypeError, ValueError) as error:
            raise ValueError("detection_assessment_confidence_invalid") from error
        if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("detection_assessment_confidence_out_of_range")
        if assessment.disposition not in DISPOSITIONS:
            raise ValueError("unsupported_detection_disposition")
        if assessment.severity not in SEVERITIES:
            raise ValueError("unsupported_detection_severity")
        categories = _bounded_unique(assessment.signal_categories, "signal_category", 12, 128)
        if any(category not in SIGNAL_CATEGORIES for category in categories):
            raise ValueError("unsupported_detection_signal_category")
        producers = _bounded_unique(assessment.producer_ids, "producer_id", 64, 128)
        evidence = _bounded_unique(assessment.evidence_refs, "evidence_ref", 128, 256)
        expected_correlated = len(categories) >= 2 and len(evidence) >= 2
        if assessment.correlated is not expected_correlated:
            raise ValueError("inconsistent_detection_correlation_claim")
        expected_candidate = (
            assessment.disposition in {"suspicious", "likely_malicious"}
            and SEVERITY_RANK[assessment.severity] >= SEVERITY_RANK["medium"]
        )
        if assessment.incident_candidate is not expected_candidate:
            raise ValueError("inconsistent_detection_incident_candidate_claim")
        if assessment.incident_candidate and (not categories or not producers or not evidence):
            raise ValueError("incident_candidate_requires_detection_provenance")
        resource_type = _text(assessment.resource_type, "resource_type", 128)
        resource_id = _text(assessment.resource_id, "resource_id", 256)
        resources.add((resource_type, resource_id))
        observed_at = _utc(assessment.observed_at)
        valid_until = _utc(assessment.valid_until)
        if valid_until < observed_at:
            raise ValueError("detection_valid_until_before_observed_at")
        normalized.append((assessment, observed_at, valid_until))

    if len(resources) != 1:
        raise ValueError("mixed_resource_detection_assessments_require_partitioning")
    resource_type, resource_id = next(iter(resources))

    fresh_candidates: list[tuple[DetectionAssessment, datetime, datetime]] = []
    excluded_non_candidate = False
    excluded_stale = False
    for assessment, observed_at, valid_until in normalized:
        if not assessment.incident_candidate:
            excluded_non_candidate = True
            continue
        if not assessment.evidence_refs:
            raise ValueError("incident_candidate_requires_evidence_refs")
        if observed_at > current or valid_until < current or current - observed_at > max_assessment_age:
            excluded_stale = True
            continue
        fresh_candidates.append((assessment, observed_at, valid_until))

    if not fresh_candidates:
        reasons = ["no_fresh_incident_candidate"]
        if excluded_non_candidate:
            reasons.append("non_candidate_assessments_excluded")
        if excluded_stale:
            reasons.append("stale_or_future_detection_assessments_excluded")
        return IncidentReviewCase(
            case_id=_case_id(resource_type, resource_id, (), current, current),
            resource_type=resource_type,
            resource_id=resource_id,
            status="unknown",
            review_priority="routine",
            assessment_count=0,
            correlated_assessment_count=0,
            dispositions=(),
            signal_categories=(),
            producer_ids=(),
            evidence_refs=(),
            reason_codes=tuple(reasons),
            observed_at=current,
            valid_until=current,
        )

    assessments_only = tuple(item[0] for item in fresh_candidates)
    observed_at = max(item[1] for item in fresh_candidates)
    valid_until = min(item[2] for item in fresh_candidates)
    dispositions = _bounded_unique((a.disposition for a in assessments_only), "disposition", 4, 64)
    categories = _bounded_unique(
        (category for a in assessments_only for category in a.signal_categories),
        "signal_category",
        12,
        128,
    )
    producers = _bounded_unique(
        (producer for a in assessments_only for producer in a.producer_ids),
        "producer_id",
        64,
        128,
    )
    evidence_refs = _bounded_unique(
        (ref for a in assessments_only for ref in a.evidence_refs),
        "evidence_ref",
        128,
        256,
    )
    if not evidence_refs:
        raise ValueError("incident_review_case_requires_evidence_refs")

    highest = max(assessments_only, key=lambda a: SEVERITY_RANK[a.severity]).severity
    correlated_count = sum(1 for assessment in assessments_only if assessment.correlated)
    reasons = ["detection_candidate_requires_incident_review"]
    if correlated_count:
        reasons.append("correlated_detection_candidate_present")
    else:
        reasons.append("uncorroborated_detection_candidate_requires_review")
    if excluded_non_candidate:
        reasons.append("non_candidate_assessments_excluded")
    if excluded_stale:
        reasons.append("stale_or_future_detection_assessments_excluded")

    return IncidentReviewCase(
        case_id=_case_id(resource_type, resource_id, evidence_refs, observed_at, valid_until),
        resource_type=resource_type,
        resource_id=resource_id,
        status="review_required",
        review_priority=PRIORITY_BY_SEVERITY[highest],
        assessment_count=len(assessments_only),
        correlated_assessment_count=correlated_count,
        dispositions=dispositions,
        signal_categories=categories,
        producer_ids=producers,
        evidence_refs=evidence_refs,
        reason_codes=tuple(reasons),
        observed_at=observed_at,
        valid_until=valid_until,
    )
