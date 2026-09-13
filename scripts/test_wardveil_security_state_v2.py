#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade security-state engine."""

from dataclasses import replace
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
SCOPE_KIND = "application"
SCOPE_ID = "goreecloud-test"
COVERAGE_REF = "evidence+sha256:" + "c" * 64 + ":coverage-1"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def evidence(*, status="current", authoritative=True, verifies=True, scope_kind=SCOPE_KIND, scope_id=SCOPE_ID):
    return EvidenceObservation(
        evidence_id="ev-protect-1",
        producer_id="wardveil-protect-test",
        control="malware_protection",
        scope_kind=scope_kind,
        scope_id=scope_id,
        authoritative=authoritative,
        status=status,
        observed_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=4),
        verifies_protection=verifies,
    )


def coverage(
    *,
    state="covered",
    adoption="production_accepted",
    evidence_status="current",
    evidence_refs=(COVERAGE_REF,),
    observed_at=None,
    valid_until=None,
):
    return CoverageObservation(
        capability="malware_protection",
        coverage_state=state,
        adoption_state=adoption,
        evidence_status=evidence_status,
        evidence_refs=evidence_refs,
        observed_at=observed_at or NOW - timedelta(minutes=1),
        valid_until=valid_until or NOW + timedelta(minutes=9),
    )


def assess(*, evidence_items, coverage_items=None, signals=SecuritySignals()):
    return evaluate_security_state(
        scope_kind=SCOPE_KIND,
        scope_id=SCOPE_ID,
        evidence=evidence_items,
        coverage=coverage_items if coverage_items is not None else (coverage(),),
        required_capabilities=("malware_protection",),
        signals=signals,
        now=NOW,
    )


def main() -> None:
    protected = assess(evidence_items=(evidence(),))
    check(protected.state == "protected", "current authoritative production-accepted evidence should protect")
    check(protected.protected_by_wardveil is True, "protected state must permit the scoped Wardveil claim")
    check(protected.legacy_presentation_state == "protected", "legacy mapping must preserve protected")
    check(protected.scope_kind == SCOPE_KIND and protected.scope_id == SCOPE_ID, "assessment must retain exact scope")
    check(
        protected.evidence_refs == ("ev-protect-1", COVERAGE_REF),
        "Protected assessment must expose both direct protection and required coverage evidence references",
    )
    check(
        protected.valid_until == NOW + timedelta(minutes=4),
        "Protected lifetime must use the earliest current evidence expiry",
    )

    nested_ref = "evidence+sha256:" + "a" * 64 + ":reports/coverage-1.json"
    nested_coverage = coverage(evidence_refs=(nested_ref,))
    check(
        nested_coverage.effective_coverage_state(NOW) == "covered",
        "credential-free nested logical locators must remain valid production evidence references",
    )

    short_ref = "evidence+sha256:" + "d" * 64 + ":coverage-short"
    short_coverage = coverage(
        evidence_refs=(short_ref,),
        valid_until=NOW + timedelta(minutes=2),
    )
    coverage_bounded = assess(
        evidence_items=(evidence(),),
        coverage_items=(short_coverage,),
    )
    check(coverage_bounded.state == "protected", "shorter current coverage evidence can still support Protected before expiry")
    check(
        coverage_bounded.valid_until == short_coverage.valid_until,
        "Protected state must not outlive the coverage evidence that justified covered capability state",
    )
    check(
        coverage_bounded.evidence_refs == ("ev-protect-1", short_ref),
        "Protected evidence references must retain the coverage proof that bounds the claim",
    )
    coverage_bounded_record = coverage_bounded.as_record()
    check(
        coverage_bounded_record["evidence"]["valid_until"] == short_coverage.valid_until.isoformat(),
        "serialized Protected evidence window must preserve the earliest coverage expiry",
    )
    check(
        coverage_bounded_record["evidence"]["references"] == ["ev-protect-1", short_ref],
        "serialized Protected record must expose direct and coverage evidence references",
    )

    foreign = assess(evidence_items=(evidence(scope_id="goreecloud-other"),))
    check(foreign.state == "unknown", "valid evidence for a different scope must fail closed")
    check(foreign.protected_by_wardveil is False, "foreign-scope evidence cannot authorize protection")
    check("required_evidence_scope_mismatch" in foreign.reason_codes, "scope mismatch must be explainable")

    stale = EvidenceObservation(
        evidence_id="ev-stale",
        producer_id="wardveil-protect-test",
        control="malware_protection",
        scope_kind=SCOPE_KIND,
        scope_id=SCOPE_ID,
        authoritative=True,
        status="current",
        observed_at=NOW - timedelta(minutes=10),
        valid_until=NOW - timedelta(minutes=1),
        verifies_protection=True,
    )
    assessment = assess(evidence_items=(stale,))
    check(assessment.state == "unknown", "expired evidence must fail closed to unknown")
    check("required_evidence_stale" in assessment.reason_codes, "stale evidence reason must be explainable")
    check(assessment.protected_by_wardveil is False, "stale evidence cannot authorize a protection claim")

    assessment = assess(evidence_items=(evidence(authoritative=False),))
    check(assessment.state == "unknown", "non-authoritative evidence must fail closed")
    check("required_evidence_unverified" in assessment.reason_codes, "unverified evidence must be explicit")

    duplicate = evidence()
    exact_replay = assess(evidence_items=(duplicate, duplicate))
    check(exact_replay.state == "protected", "exact duplicate evidence replay must remain idempotent")
    check(
        exact_replay.evidence_refs == (duplicate.evidence_id, COVERAGE_REF),
        "exact duplicate replay must deduplicate direct evidence while retaining required coverage evidence",
    )

    conflicting_evidence = (
        duplicate,
        replace(duplicate, authoritative=False),
    )
    identity_conflict_first = assess(evidence_items=conflicting_evidence)
    identity_conflict_reversed = assess(evidence_items=tuple(reversed(conflicting_evidence)))
    check(
        identity_conflict_first.state == "unknown" and identity_conflict_reversed.state == "unknown",
        "conflicting duplicate evidence IDs must fail closed regardless of input order",
    )
    check(
        identity_conflict_first.protected_by_wardveil is False and identity_conflict_reversed.protected_by_wardveil is False,
        "conflicting duplicate evidence IDs cannot authorize a protection claim",
    )
    check(
        identity_conflict_first.reason_codes == identity_conflict_reversed.reason_codes == ("required_evidence_identity_conflict",),
        "evidence ID conflict resolution must be deterministic and explainable",
    )
    check(
        identity_conflict_first.evidence_refs == identity_conflict_reversed.evidence_refs == (duplicate.evidence_id,),
        "evidence ID conflict must retain one bounded reference without hiding the conflict reason",
    )

    unreferenced_coverage = coverage(evidence_refs=())
    assessment = assess(evidence_items=(evidence(),), coverage_items=(unreferenced_coverage,))
    check(assessment.coverage_state == "unknown", "unreferenced production coverage must fail closed to unknown")
    check(assessment.state == "unknown", "unreferenced production coverage must never produce Protected")
    check(assessment.protected_by_wardveil is False, "unreferenced production coverage cannot authorize a protection claim")
    check(
        "capability_coverage_unverified:malware_protection" in assessment.reason_codes,
        "missing production coverage evidence must be explainable",
    )

    try:
        coverage(evidence_refs=("artifact:latest",))
    except ValueError as exc:
        check("immutable evidence+sha256" in str(exc), "mutable production coverage rejection should be explainable")
    else:
        raise AssertionError("mutable production coverage evidence references must be rejected")

    unsafe_digest = "f" * 64
    unsafe_production_refs = (
        f"evidence+sha256:{unsafe_digest}:https://evidence.example/report",
        f"evidence+sha256:{unsafe_digest}:reports/current.json?token=secret",
        f"evidence+sha256:{unsafe_digest}:user@host/report",
        f"evidence+sha256:{unsafe_digest}:reports/%2E%2E/secret",
        f"evidence+sha256:{unsafe_digest}:reports/report.json#fragment",
    )
    for unsafe_ref in unsafe_production_refs:
        try:
            coverage(evidence_refs=(unsafe_ref,))
        except ValueError as exc:
            check(
                "credential-free logical locators" in str(exc),
                "unsafe production coverage locator rejection should explain the credential-safe boundary",
            )
        else:
            raise AssertionError("production coverage evidence locators must reject transport or credential-bearing syntax")

    source_only_mutable = coverage(
        adoption="source_validated",
        evidence_refs=("source-validation:wardveil-malware",),
    )
    check(
        source_only_mutable.effective_coverage_state(NOW) == "partial",
        "non-production lifecycle evidence may remain canonical but mutable without becoming covered",
    )

    for bad_refs in (("duplicate", "duplicate"), (" bad",), ("x" * 257,)):
        try:
            coverage(evidence_refs=bad_refs)
        except ValueError as exc:
            check("coverage evidence references" in str(exc), "invalid coverage evidence reference rejection should be explainable")
        else:
            raise AssertionError("invalid coverage evidence references must be rejected")

    assessment = assess(
        evidence_items=(evidence(),),
        coverage_items=(coverage(state="not_covered", adoption="implemented", evidence_refs=("implementation-note",)),),
    )
    check(assessment.state == "not_covered", "explicitly unintegrated required capability must be not covered")
    check(assessment.protected_by_wardveil is False, "not-covered state cannot authorize protection")

    conflicting = (
        coverage(state="not_covered", adoption="implemented", evidence_refs=("implementation-note",)),
        coverage(),
    )
    coverage_conflict_first = assess(evidence_items=(evidence(),), coverage_items=conflicting)
    coverage_conflict_reversed = assess(evidence_items=(evidence(),), coverage_items=tuple(reversed(conflicting)))
    check(
        coverage_conflict_first.state == "not_covered" and coverage_conflict_reversed.state == "not_covered",
        "conflicting duplicate coverage must never become Protected regardless of input order",
    )
    check(
        coverage_conflict_first.protected_by_wardveil is False and coverage_conflict_reversed.protected_by_wardveil is False,
        "conflicting duplicate coverage cannot authorize a protection claim",
    )
    check(
        coverage_conflict_first.coverage_state == coverage_conflict_reversed.coverage_state == "not_covered",
        "duplicate coverage conflict resolution must be deterministic and conservative",
    )

    assessment = assess(
        evidence_items=(evidence(),),
        coverage_items=(coverage(adoption="runtime_validated", evidence_refs=("runtime-validation:malware",)),),
    )
    check(assessment.state == "degraded", "runtime validation without production acceptance must not be Protected")
    check(
        "capability_not_production_accepted:malware_protection" in assessment.reason_codes,
        "production-acceptance gap must be explainable",
    )

    stale_coverage = CoverageObservation(
        capability="malware_protection",
        coverage_state="covered",
        adoption_state="production_accepted",
        evidence_status="current",
        evidence_refs=("evidence+sha256:" + "e" * 64 + ":coverage-stale",),
        observed_at=NOW - timedelta(minutes=20),
        valid_until=NOW - timedelta(seconds=1),
    )
    assessment = assess(evidence_items=(evidence(),), coverage_items=(stale_coverage,))
    check(assessment.coverage_state == "stale", "expired coverage evidence must remain explicitly stale")
    check(assessment.state == "unknown", "stale coverage cannot produce a Protected security state")
    check("coverage_evidence_stale" in assessment.reason_codes, "stale coverage must have an explicit reason")

    assessment = assess(
        evidence_items=(evidence(),),
        coverage_items=(coverage(state="degraded", evidence_refs=("degraded-observation",)),),
    )
    check(assessment.coverage_state == "degraded", "degraded coverage must remain distinct")
    check(assessment.state == "degraded", "degraded required coverage must degrade security state")
    check("coverage_degraded" in assessment.reason_codes, "degraded coverage must be explainable")

    assessment = assess(
        evidence_items=(evidence(),),
        signals=SecuritySignals(reconciliation_required=True),
    )
    check(assessment.state == "reconciliation_required", "uncertain side effect must require reconciliation")
    check(assessment.legacy_presentation_state == "degraded", "legacy UI must not overstate reconciliation state")

    assessment = assess(
        evidence_items=(evidence(),),
        signals=SecuritySignals(active_threat=True),
    )
    check(assessment.state == "at_risk", "active threat must override otherwise good evidence")
    check(assessment.protected_by_wardveil is False, "active threat must disable Protected claim")

    assessment = assess(
        evidence_items=(evidence(),),
        signals=SecuritySignals(contained=True),
    )
    check(assessment.state == "contained", "contained threat must remain distinct from Protected")

    record = protected.as_record()
    check(record["contract_version"] == "0.2.0", "next-upgrade state contract must be versioned")
    check(record["scope"] == {"kind": SCOPE_KIND, "id": SCOPE_ID}, "record must use assessment-bound scope")
    check(record["claim"]["protected_by_wardveil"] is True, "record claim must match assessment")
    check(record["coverage"]["status"] == "covered", "record must preserve independent coverage state")
    check(
        record["explanation"]["legacy_presentation_state"] == "protected",
        "record must carry an explicit compatibility presentation state",
    )

    conflict_record = identity_conflict_first.as_record()
    check(conflict_record["claim"]["protected_by_wardveil"] is False, "conflicting evidence record cannot claim protection")
    check(conflict_record["evidence"]["status"] == "unverified", "conflicting evidence record must serialize as unverified")

    try:
        protected.as_record(scope_kind=SCOPE_KIND, scope_id="goreecloud-other")
    except ValueError as exc:
        check("cannot be relabeled" in str(exc), "scope relabel rejection must be explicit")
    else:
        raise AssertionError("security assessment must reject record serialization under a different scope")

    print("Wardveil next-upgrade security-state self-tests passed.")


if __name__ == "__main__":
    main()
