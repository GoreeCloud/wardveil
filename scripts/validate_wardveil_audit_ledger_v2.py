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
EXPECTED_REFERENCE_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9._+-]*"
    r"(?::[A-Za-z0-9][A-Za-z0-9._+-]*)*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._+-]*"
    r"(?::[A-Za-z0-9][A-Za-z0-9._+-]*)*)*$"
)


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

    reference_def = schema.get("$defs", {}).get("credentialSafeLogicalReference", {})
    if reference_def.get("pattern") != EXPECTED_REFERENCE_PATTERN:
        fail("audit credential-safe logical-reference schema pattern drifted")
    if reference_def.get("maxLength") != 256:
        fail("audit logical references must remain bounded to 256 characters")

    reference_ref = "#/$defs/credentialSafeLogicalReference"
    for field in ("evidence_refs", "verification_evidence_refs", "source_record_refs"):
        if props[field].get("items", {}).get("$ref") != reference_ref:
            fail(f"audit {field} must use the credential-safe logical-reference contract")
    for field in ("incident_ref", "quarantine_object_ref"):
        if props[field].get("$ref") != reference_ref:
            fail(f"audit {field} must use the credential-safe logical-reference contract")

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
        "must_be_credential_safe_logical_reference",
        "REFERENCE_PATTERN",
        "_optional_reference",
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
        "audit references must reject credential-bearing transport syntax",
        "incident references must use the same credential-safe logical grammar",
        "evidence+sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:reports/protect-receipt-2.json",
        "hash-linked ledger must detect event mutation",
    ):
        if token not in tests:
            fail(f"audit tests missing negative or compatibility invariant: {token}")

    doc = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Authorization is not execution success.",
        "Expired evidence may remain historical",
        "Privacy Shield remains the privacy and minimization authority.",
        "Audit reference fields are logical identifiers, not transport URLs.",
        "Retrieval credentials, signed URLs, bearer material, and similar access secrets must remain outside durable audit records.",
        "Production durable storage remains unaccepted.",
    ):
        if phrase not in doc:
            fail(f"audit documentation missing governing boundary: {phrase}")

    print("Wardveil next-upgrade Audit and Evidence Ledger contract validated.")


if __name__ == "__main__":
    main()
