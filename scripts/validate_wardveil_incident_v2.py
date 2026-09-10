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

    resolution_rule = schema["allOf"][0]
    if "resolution" not in resolution_rule["then"]["required"]:
        fail("resolved or archived incident must require resolution evidence")

    reference = REFERENCE.read_text(encoding="utf-8")
    for token in (
        "incident_reconciliation_must_complete_before_state_upgrade",
        "resolved_incident_requires_resolution_evidence",
        "recovery_linked_incident_requires_everkeep_evidence",
        "recovery_linked_incident_requires_wardveil_verification",
        "security_action_event_requires_execution_state",
        "archived_incident_timeline_is_immutable",
        "ALLOWED_TRANSITIONS",
    ):
        if token not in reference:
            fail(f"incident reference missing invariant token: {token}")

    print("Wardveil next-upgrade Incident Plane contract validated.")


if __name__ == "__main__":
    main()
