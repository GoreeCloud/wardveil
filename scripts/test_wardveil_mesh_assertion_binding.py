#!/usr/bin/env python3
"""Security regression tests for Wardveil Mesh assertion/producer binding.

These tests intentionally fail closed until every generic runtime assertion is
bound to its canonical Wardveil runtime record type. They do not execute any
security action or establish production acceptance.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_evidence import create_mesh_evidence_envelope


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Mesh assertion-binding regression failed: {message}")


def expect_value_error(callback, message: str) -> None:
    try:
        callback()
    except ValueError:
        return
    fail(message)


NOW = datetime(2026, 9, 5, 19, 30, tzinfo=timezone.utc)
REVISION = "a" * 40


def runtime_record(record_type: str, record_id: str, **fields: object) -> dict:
    record = {
        "contract_version": "0.1.0",
        "record_type": record_type,
        "record_id": record_id,
        "correlation_id": "corr-assertion-binding",
        "producer": {"id": "wardveil-binding-test", "authoritative": True},
        "scope": {
            "resource_type": "service",
            "resource_id": "goreecloud-mail",
            "operation": "attachment-ingress",
        },
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(hours=1)).isoformat(),
        "evidence_refs": ["wardveil://evidence/assertion-binding-test"],
    }
    record.update(fields)
    return record


policy = runtime_record(
    "policy_decision",
    "policy-binding-001",
    policy_decision="allow",
    reason_code="policy_satisfied",
)

# Canonical same-family binding remains valid.
canonical = create_mesh_evidence_envelope(
    policy,
    revision=REVISION,
    assertion="policy-decision",
    outcome="allow",
    observed_at=NOW,
)
if canonical.get("assertion") != "policy-decision" or canonical.get("outcome") != "allow":
    fail("canonical policy-decision evidence no longer emits its producer outcome")

# Runtime schema permits additional top-level fields. A record from one runtime
# family must therefore never become evidence for another assertion merely
# because an extra field happens to carry an allowed outcome value.
scan_with_policy_field = runtime_record(
    "scan_finding",
    "scan-binding-001",
    scan_result="clean",
    policy_decision="allow",
)
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        scan_with_policy_field,
        revision=REVISION,
        assertion="policy-decision",
        outcome="allow",
        observed_at=NOW,
    ),
    "scan_finding was relabeled as policy-decision evidence",
)

policy_with_scan_field = copy.deepcopy(policy)
policy_with_scan_field["scan_result"] = "clean"
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        policy_with_scan_field,
        revision=REVISION,
        assertion="scan-finding",
        outcome="clean",
        observed_at=NOW,
    ),
    "policy_decision was relabeled as scan-finding evidence",
)

# These assertion families do not yet have a canonical runtime record-type and
# producer-outcome binding in this adapter. They must fail closed rather than
# accept caller-defined outcomes from an otherwise valid runtime record.
for assertion, outcome in (
    ("runtime-acceptance", "accepted"),
    ("response-state", "contained"),
):
    expect_value_error(
        lambda assertion=assertion, outcome=outcome: create_mesh_evidence_envelope(
            policy,
            revision=REVISION,
            assertion=assertion,
            outcome=outcome,
            observed_at=NOW,
        ),
        f"unbound assertion {assertion} accepted caller-defined runtime evidence",
    )

print("Wardveil Mesh assertion-to-producer record-type binding regressions: OK")
