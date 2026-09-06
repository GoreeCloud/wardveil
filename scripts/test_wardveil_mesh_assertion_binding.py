#!/usr/bin/env python3
"""Security regression tests for Wardveil Mesh assertion/producer binding.

Every publishable generic assertion must be bound to its canonical Wardveil
runtime record type and producer outcome. Runtime subproducer identity must be
preserved through the producer-controlled source reference without being treated
as delivery authentication. Profile-permitted but unbound families remain fail
closed. These tests do not execute security actions or establish production
acceptance.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from urllib.parse import quote

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
PROFILE = json.loads((ROOT / "contracts/wardveil.mesh-evidence-profile.json").read_text(encoding="utf-8"))


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


def expected_runtime_source(record: dict) -> str:
    return (
        f"wardveil://producers/{quote(str(record['producer']['id']), safe='')}"
        f"/records/{quote(str(record['record_id']), safe='')}"
    )


CASES = {
    "trust-evaluation": ("trust_decision", "trust_state", "normal", {}),
    "policy-decision": ("policy_decision", "policy_decision", "allow", {"reason_code": "policy_satisfied"}),
    "protection-result": ("protection_action", "execution_status", "succeeded", {"policy_decision": "allow", "executor": "test-executor", "idempotency_key": "idem-001"}),
    "detection-finding": ("detection_finding", "detection_disposition", "suspicious", {"severity": "medium", "confidence": 0.8}),
    "scan-finding": ("scan_finding", "scan_result", "clean", {}),
    "quarantine-state": ("quarantine_record", "review_state", "pending", {}),
    "incident-state": ("incident_record", "incident_status", "open", {"severity": "high"}),
    "security-audit-state": ("audit_event", "outcome", "success", {"event_type": "test"}),
}

# The profile must describe exactly the same producer bindings the adapter accepts.
bindings = PROFILE.get("producer_bindings") or {}
if PROFILE.get("schema_version") != "1.1.3":
    fail("producer-binding profile version drifted")
if set(bindings) != set(PROFILE.get("permitted_assertion_families") or []):
    fail("every permitted assertion family must have an explicit producer-binding status")
if bindings.get("security-status", {}).get("status") != "bound":
    fail("security-status lost its dedicated bound producer status")

for assertion, (record_type, outcome_field, outcome, extras) in CASES.items():
    binding = bindings.get(assertion) or {}
    if binding.get("status") != "bound" or binding.get("contract") != "contracts/wardveil.runtime.schema.json":
        fail(f"profile runtime binding missing for {assertion}")
    if binding.get("record_type") != record_type or binding.get("outcome_field") != outcome_field or binding.get("validity_field") != "valid_until":
        fail(f"profile runtime binding drifted for {assertion}")

    record = runtime_record(record_type, f"{record_type}-binding-001", **{outcome_field: outcome}, **extras)
    envelope = create_mesh_evidence_envelope(
        record,
        revision=REVISION,
        assertion=assertion,
        outcome=outcome,
        observed_at=NOW,
    )
    if envelope.get("assertion") != assertion or envelope.get("outcome") != outcome:
        fail(f"canonical {assertion} evidence no longer emits its producer outcome")
    if envelope.get("producer", {}).get("system") != "wardveil-security":
        fail(f"{assertion} changed the Mesh transport producer identity")
    if envelope.get("source") != expected_runtime_source(record):
        fail(f"{assertion} no longer preserves the validated runtime producer identity")

# Reserved URI characters must be encoded rather than being interpreted as part
# of the opaque producer-controlled reference structure.
reserved = runtime_record("scan_finding", "scan/finding?record=1#fragment", scan_result="clean")
reserved["producer"]["id"] = "wardveil/scan?tenant=example#fragment"
reserved_envelope = create_mesh_evidence_envelope(
    reserved,
    revision=REVISION,
    assertion="scan-finding",
    outcome="clean",
    observed_at=NOW,
)
if reserved_envelope.get("source") != expected_runtime_source(reserved):
    fail("reserved runtime producer/record identity was not preserved with safe URI encoding")
if "wardveil/scan?tenant=example#fragment" in str(reserved_envelope.get("source")):
    fail("runtime producer identity escaped opaque-source encoding")

# Producer identity preservation never bypasses the producer-authoritative gate.
non_authoritative = runtime_record("scan_finding", "scan-nonauthoritative-001", scan_result="clean")
non_authoritative["producer"]["authoritative"] = False
expect_value_error(
    lambda: create_mesh_evidence_envelope(non_authoritative, revision=REVISION, assertion="scan-finding", outcome="clean", observed_at=NOW),
    "non-authoritative runtime producer emitted Mesh evidence",
)

# Runtime schema permits additional top-level fields. A record from one family
# must never become evidence for another assertion because an extra field looks compatible.
scan_with_policy_field = runtime_record("scan_finding", "scan-binding-001", scan_result="clean", policy_decision="allow")
expect_value_error(
    lambda: create_mesh_evidence_envelope(scan_with_policy_field, revision=REVISION, assertion="policy-decision", outcome="allow", observed_at=NOW),
    "scan_finding was relabeled as policy-decision evidence",
)
policy = runtime_record("policy_decision", "policy-binding-001", policy_decision="allow", reason_code="policy_satisfied")
policy_with_scan_field = copy.deepcopy(policy)
policy_with_scan_field["scan_result"] = "clean"
expect_value_error(
    lambda: create_mesh_evidence_envelope(policy_with_scan_field, revision=REVISION, assertion="scan-finding", outcome="clean", observed_at=NOW),
    "policy_decision was relabeled as scan-finding evidence",
)

# Profile-permitted does not mean producer-bound. Runtime acceptance currently
# lacks a canonical producer-declared Mesh validity window; response-state lacks
# a canonical Response producer record/outcome/validity binding. Both must stay closed.
expected_unbound = {
    "runtime-acceptance": "producer-validity-window-not-established",
    "response-state": "canonical-response-producer-record-not-established",
}
for assertion, reason_code in expected_unbound.items():
    binding = bindings.get(assertion) or {}
    if binding.get("status") != "unbound" or binding.get("mode") != "fail-closed" or binding.get("reason_code") != reason_code:
        fail(f"profile no longer records {assertion} as explicitly fail-closed")
    if binding.get("contract") is not None or binding.get("record_type") is not None or binding.get("outcome_field") is not None or binding.get("validity_field") is not None:
        fail(f"unbound assertion {assertion} gained partial producer authority")
    expect_value_error(
        lambda assertion=assertion: create_mesh_evidence_envelope(policy, revision=REVISION, assertion=assertion, outcome="accepted", observed_at=NOW),
        f"unbound assertion {assertion} accepted caller-defined runtime evidence",
    )

print("Wardveil Mesh assertion-to-producer binding and identity-preservation regressions: OK")
