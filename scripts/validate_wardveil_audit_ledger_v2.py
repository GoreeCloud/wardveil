#!/usr/bin/env python3
"""Validate Wardveil next-upgrade Audit and Evidence Ledger invariants."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.audit-event.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_audit_ledger_v2.py"
TEST = ROOT / "scripts" / "test_wardveil_audit_ledger_v2.py"
DOC = ROOT / "AUDIT-EVIDENCE-LEDGER-V2.md"

EXPECTED_CATEGORIES = {
    "security_decision",
    "execution",
    "reconciliation",
    "recovery_verification",
    "security_observation",
}
EXPECTED_OUTCOMES = {
    "requested",
    "succeeded",
    "failed",
    "denied",
    "blocked",
    "partial",
    "unknown",
    "reconciled",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def main() -> None:
    for path in (SCHEMA, REFERENCE, TEST, DOC):
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")

    try:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid audit schema JSON: {exc}")

    if schema.get("$id") != "urn:goreecloud:wardveil:audit-event:0.1.0":
        fail("unexpected audit contract id")
    if schema.get("additionalProperties") is not False:
        fail("audit contract must reject unbounded extra fields")

    props = schema.get("properties", {})
    if set(props["event_category"]["enum"]) != EXPECTED_CATEGORIES:
        fail("audit event category vocabulary is incomplete")
    if set(props["outcome"]["enum"]) != EXPECTED_OUTCOMES:
        fail("audit outcome vocabulary is incomplete")

    required = set(schema.get("required", []))
    for field in (
        "audit_event_id",
        "correlation_id",
        "producer",
        "target",
        "requested_action",
        "outcome",
        "evidence_refs",
        "source_record_refs",
        "reconciliation_state",
        "reason_code",
        "summary",
        "retention",
        "event_hash",
    ):
        if field not in required:
            fail(f"audit contract missing required provenance field: {field}")

    retention = props["retention"]
    if retention.get("additionalProperties") is not False:
        fail("audit retention metadata must remain bounded")
    if retention["properties"]["class"].get("const") != "audit_evidence":
        fail("audit retention class must be explicit")
    if retention["properties"]["may_leave_origin"].get("const") is not False:
        fail("audit evidence must default to origin-local retention")

    reference = REFERENCE.read_text(encoding="utf-8")
    for token in (
        "successful_execution_requires_verification_evidence",
        "execution_audit_requires_authorization_and_executor",
        "uncertain_execution_requires_reconciliation",
        "reconciliation_does_not_match_open_uncertainty",
        "unknown_reconciliation_must_remain_required",
        "audit_event_requires_acting_identity",
        "contains_prohibited_sensitive_material",
        "verify_chain",
        "evidence_freshness",
        "security_provenance",
        "may_leave_origin",
    ):
        if token not in reference:
            fail(f"audit reference missing invariant token: {token}")

    tests = TEST.read_text(encoding="utf-8")
    for token in (
        "authorization or acknowledgement alone must not prove successful execution",
        "reconciliation must not clear unrelated uncertainty",
        "expired evidence may remain historical but must not present as current",
        "audit summaries must reject obvious reusable secret material",
        "hash-linked ledger must detect event mutation",
    ):
        if token not in tests:
            fail(f"audit tests missing negative invariant: {token}")

    doc = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Authorization is not execution success.",
        "Expired evidence may remain historical",
        "Privacy Shield remains the privacy and minimization authority.",
        "Production durable storage remains unaccepted.",
    ):
        if phrase not in doc:
            fail(f"audit documentation missing governing boundary: {phrase}")

    print("Wardveil next-upgrade Audit and Evidence Ledger contract validated.")


if __name__ == "__main__":
    main()
