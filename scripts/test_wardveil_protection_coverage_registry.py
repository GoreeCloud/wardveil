#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade Protection Coverage Registry."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_protection_coverage_registry import (
    CoverageRegistryRecord,
    ProtectionCoverageRegistry,
)

NOW = datetime(2026, 9, 9, 21, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def record(
    *,
    capability="malware_protection",
    coverage_state="covered",
    adoption_state="production_accepted",
    evidence_status="current",
    observed_at=None,
    valid_until=None,
    required=("upload_gate", "download_gate"),
    implemented=("upload_gate", "download_gate"),
    subject_kind="application",
    subject_id="goreecloud-drive",
):
    return CoverageRegistryRecord(
        subject_kind=subject_kind,
        subject_id=subject_id,
        scope_kind="application",
        scope_id=subject_id,
        capability=capability,
        coverage_state=coverage_state,
        adoption_state=adoption_state,
        evidence_status=evidence_status,
        observed_at=observed_at or NOW - timedelta(minutes=2),
        valid_until=valid_until or NOW + timedelta(minutes=8),
        evidence_refs=(f"evidence:{subject_id}:{capability}",),
        required_enforcement_points=required,
        implemented_enforcement_points=implemented,
        dependencies=("wardveil-scan",),
        known_gaps=(),
        remediation=(),
    )


def main() -> None:
    registry = ProtectionCoverageRegistry()
    malware = record()
    registry.upsert(malware)

    current = registry.get(
        subject_kind="application",
        subject_id="goreecloud-drive",
        scope_kind="application",
        scope_id="goreecloud-drive",
        capability="malware_protection",
    )
    check(current == malware, "registry must return the exact current capability record")
    check(current.effective_coverage_state(NOW) == "covered", "accepted current coverage should remain covered")
    check(current.stable_qualification_impact(NOW) == "none", "fully accepted coverage should not block Stable")

    partial_enforcement = record(implemented=("upload_gate",))
    check(
        partial_enforcement.effective_coverage_state(NOW) == "partial",
        "missing an enforcement point must downgrade coverage to partial",
    )
    check(
        partial_enforcement.stable_qualification_impact(NOW) == "blocks_stable",
        "partial enforcement must block Stable qualification",
    )

    source_only = record(adoption_state="source_validated")
    check(
        source_only.effective_coverage_state(NOW) == "partial",
        "source validation alone must not become covered production protection",
    )

    stale = record(
        observed_at=NOW - timedelta(minutes=20),
        valid_until=NOW - timedelta(minutes=1),
    )
    check(stale.effective_coverage_state(NOW) == "stale", "expired coverage evidence must become stale")
    stale_record = stale.as_record(NOW)
    check(stale_record["coverage_state"] == "stale", "serialized coverage must preserve stale state")
    check(stale_record["evidence"]["status"] == "stale", "serialized evidence must expose stale freshness")

    degraded = record(coverage_state="degraded")
    check(degraded.effective_coverage_state(NOW) == "degraded", "degraded coverage must remain explicit")
    check(degraded.stable_qualification_impact(NOW) == "blocks_stable", "degraded coverage must block Stable")

    unknown = record(evidence_status="unavailable")
    check(unknown.effective_coverage_state(NOW) == "unknown", "unavailable evidence must fail closed to unknown")
    check(unknown.stable_qualification_impact(NOW) == "unknown", "unknown coverage must not imply Stable eligibility")

    registry.upsert(record(capability="audit_coverage", required=("audit_write",), implemented=("audit_write",)))
    state, missing, uncertain = registry.summarize(
        subject_kind="application",
        subject_id="goreecloud-drive",
        scope_kind="application",
        scope_id="goreecloud-drive",
        required_capabilities=("malware_protection", "audit_coverage"),
        now=NOW,
    )
    check(state == "covered", "all required accepted current capabilities should summarize as covered")
    check(not missing and not uncertain, "covered summary must not invent gaps")

    state, missing, _ = registry.summarize(
        subject_kind="application",
        subject_id="goreecloud-drive",
        scope_kind="application",
        scope_id="goreecloud-drive",
        required_capabilities=("malware_protection", "recovery_security_verification"),
        now=NOW,
    )
    check(state == "partial", "one missing required capability must produce partial coverage")
    check(
        "recovery_security_verification" in missing,
        "missing required coverage must remain visible in the summary",
    )

    try:
        registry.upsert(
            record(
                observed_at=NOW - timedelta(hours=1),
                valid_until=NOW + timedelta(minutes=1),
            )
        )
    except ValueError as exc:
        check("older coverage evidence" in str(exc), "older-record rejection should be explainable")
    else:
        raise AssertionError("older evidence must not overwrite newer coverage")

    same_time_conflict = record(
        observed_at=malware.observed_at,
        valid_until=malware.valid_until,
        implemented=("upload_gate",),
    )
    try:
        registry.upsert(same_time_conflict)
    except ValueError as exc:
        check("conflicting coverage evidence" in str(exc), "same-time conflicts must be explicit")
    else:
        raise AssertionError("conflicting same-time evidence must be rejected")

    registry.upsert(
        record(
            subject_kind="service",
            subject_id="wardveil-scan",
            capability="runtime_integrity",
            required=("service_health",),
            implemented=("service_health",),
        )
    )
    exported = registry.export_records(NOW)
    check(len(exported) == 3, "registry export must preserve independent application/service records")
    check(
        any(item["subject"] == {"kind": "service", "id": "wardveil-scan"} for item in exported),
        "registry export must identify service coverage independently",
    )

    print("Wardveil Protection Coverage Registry self-tests passed.")


if __name__ == "__main__":
    main()
