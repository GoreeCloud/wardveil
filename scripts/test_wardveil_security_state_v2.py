#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade security-state engine."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_security_state_v2 import (
    CoverageObservation,
    EvidenceObservation,
    SecuritySignals,
    evaluate_security_state,
)

NOW = datetime(2026, 9, 9, 20, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def evidence(*, status="current", authoritative=True, verifies=True):
    return EvidenceObservation(
        evidence_id="ev-protect-1",
        producer_id="wardveil-protect-test",
        control="malware_protection",
        authoritative=authoritative,
        status=status,
        observed_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=4),
        verifies_protection=verifies,
    )


def coverage(*, state="covered", adoption="production_accepted", evidence_status="current"):
    return CoverageObservation(
        capability="malware_protection",
        coverage_state=state,
        adoption_state=adoption,
        evidence_status=evidence_status,
        evidence_refs=("coverage-1",),
        observed_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=9),
    )


def main() -> None:
    protected = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        now=NOW,
    )
    check(protected.state == "protected", "current authoritative production-accepted evidence should protect")
    check(protected.protected_by_wardveil is True, "protected state must permit the scoped Wardveil claim")
    check(protected.legacy_presentation_state == "protected", "legacy mapping must preserve protected")

    stale = EvidenceObservation(
        evidence_id="ev-stale",
        producer_id="wardveil-protect-test",
        control="malware_protection",
        authoritative=True,
        status="current",
        observed_at=NOW - timedelta(minutes=10),
        valid_until=NOW - timedelta(minutes=1),
        verifies_protection=True,
    )
    assessment = evaluate_security_state(
        evidence=(stale,),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        now=NOW,
    )
    check(assessment.state == "unknown", "expired evidence must fail closed to unknown")
    check("required_evidence_stale" in assessment.reason_codes, "stale evidence reason must be explainable")
    check(assessment.protected_by_wardveil is False, "stale evidence cannot authorize a protection claim")

    assessment = evaluate_security_state(
        evidence=(evidence(authoritative=False),),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        now=NOW,
    )
    check(assessment.state == "unknown", "non-authoritative evidence must fail closed")
    check("required_evidence_unverified" in assessment.reason_codes, "unverified evidence must be explicit")

    assessment = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(state="not_covered", adoption="implemented"),),
        required_capabilities=("malware_protection",),
        now=NOW,
    )
    check(assessment.state == "not_covered", "explicitly unintegrated required capability must be not covered")
    check(assessment.protected_by_wardveil is False, "not-covered state cannot authorize protection")

    assessment = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(adoption="runtime_validated"),),
        required_capabilities=("malware_protection",),
        now=NOW,
    )
    check(assessment.state == "degraded", "runtime validation without production acceptance must not be Protected")
    check(
        "capability_not_production_accepted:malware_protection" in assessment.reason_codes,
        "production-acceptance gap must be explainable",
    )

    assessment = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        signals=SecuritySignals(reconciliation_required=True),
        now=NOW,
    )
    check(assessment.state == "reconciliation_required", "uncertain side effect must require reconciliation")
    check(assessment.legacy_presentation_state == "degraded", "legacy UI must not overstate reconciliation state")

    assessment = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        signals=SecuritySignals(active_threat=True),
        now=NOW,
    )
    check(assessment.state == "at_risk", "active threat must override otherwise good evidence")
    check(assessment.protected_by_wardveil is False, "active threat must disable Protected claim")

    assessment = evaluate_security_state(
        evidence=(evidence(),),
        coverage=(coverage(),),
        required_capabilities=("malware_protection",),
        signals=SecuritySignals(contained=True),
        now=NOW,
    )
    check(assessment.state == "contained", "contained threat must remain distinct from Protected")

    record = protected.as_record(scope_kind="application", scope_id="goreecloud-test")
    check(record["contract_version"] == "0.2.0", "next-upgrade state contract must be versioned")
    check(record["claim"]["protected_by_wardveil"] is True, "record claim must match assessment")
    check(record["coverage"]["status"] == "covered", "record must preserve independent coverage state")
    check(
        record["explanation"]["legacy_presentation_state"] == "protected",
        "record must carry an explicit compatibility presentation state",
    )

    print("Wardveil next-upgrade security-state self-tests passed.")


if __name__ == "__main__":
    main()
