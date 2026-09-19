#!/usr/bin/env python3
"""Validate Wardveil next-upgrade Incident Plane invariants."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.incident.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_incident_v2.py"
TEST = ROOT / "scripts" / "test_wardveil_incident_v2.py"

EXPECTED_STATES = {
    "open",
    "investigating",
    "containment_pending",
    "contained",
    "recovery_pending",
    "recovering",
    "verification_pending",
    "resolved",
    "archived",
}

EXPECTED_EVENTS = {
    "finding",
    "threat_detection",
    "trust_change",
    "policy_decision",
    "execution_authorization",
    "protection_action",
    "quarantine",
    "reconciliation",
    "recovery_action",
    "everkeep_recovery_evidence",
    "wardveil_recovery_verification",
    "resolution",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def main() -> None:
    for path in (SCHEMA, REFERENCE, TEST):
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")

    try:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid incident schema JSON: {exc}")

    if schema.get("$id") != "urn:goreecloud:wardveil:incident:0.1.0":
        fail("unexpected incident contract id")
    if set(schema["properties"]["state"]["enum"]) != EXPECTED_STATES:
        fail("incident state vocabulary is incomplete")
    event_enum = schema["properties"]["timeline"]["items"]["properties"]["event_type"]["enum"]
    if set(event_enum) != EXPECTED_EVENTS:
        fail("incident timeline event vocabulary is incomplete")
    if "open_reconciliation_refs" not in schema.get("required", []):
        fail("incident contract must expose unresolved execution identities")

    resolution_rule = schema["allOf"][0]
    if "resolution" not in resolution_rule["then"]["required"]:
        fail("resolved or archived incident must require resolution evidence")
    resolution_timeline = resolution_rule["then"]["properties"]["timeline"]
    if resolution_timeline.get("minContains") != 1:
        fail("resolved or archived incident must retain a normalized resolution event")

    contained_rule = schema["allOf"][1]
    contained_timeline = contained_rule["then"]["properties"]["timeline"]
    if contained_timeline.get("minContains") != 1:
        fail("contained state must require a verified containment timeline event")

    open_reconciliation_rule = schema["allOf"][2]
    if open_reconciliation_rule["then"]["properties"]["open_reconciliation_refs"].get("minItems") != 1:
        fail("open reconciliation must expose at least one unresolved execution identity")

    closed_reconciliation_rule = schema["allOf"][3]
    if closed_reconciliation_rule["then"]["properties"]["open_reconciliation_refs"].get("maxItems") != 0:
        fail("closed reconciliation must not retain unresolved execution identities")

    reference = REFERENCE.read_text(encoding="utf-8")
    for token in (
        "incident_reconciliation_must_complete_before_state_upgrade",
        "contained_incident_requires_verified_containment",
        "uncertain_execution_requires_source_record",
        "reconciliation_does_not_match_open_uncertainty",
        "resolved_incident_requires_resolution_evidence",
        "recovery_linked_incident_requires_everkeep_evidence",
        "recovery_linked_incident_requires_wardveil_verification",
        "security_action_event_requires_execution_state",
        "archived_incident_timeline_is_immutable",
        "open_reconciliation_refs",
        "ALLOWED_TRANSITIONS",
    ):
        if token not in reference:
            fail(f"incident reference missing invariant token: {token}")

    test = TEST.read_text(encoding="utf-8")
    for token in (
        "one reconciliation must not clear unrelated uncertainty",
        "reconciliation alone must not fabricate a verified containment effect",
        "resolution must be represented in the normalized timeline",
    ):
        if token not in test:
            fail(f"incident tests missing negative invariant: {token}")

    print("Wardveil next-upgrade Incident Plane contract validated.")


if __name__ == "__main__":
    main()
