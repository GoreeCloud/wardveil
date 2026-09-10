#!/usr/bin/env python3
"""Validate Wardveil next-upgrade Quarantine object invariants."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.quarantine-object.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_quarantine_object_v2.py"
TEST = ROOT / "scripts" / "test_wardveil_quarantine_object_v2.py"

EXPECTED_STATES = {
    "quarantine_pending",
    "isolation_requested",
    "isolation_executing",
    "verified_quarantined",
    "reconciliation_required",
    "release_pending",
    "released",
    "restore_pending",
    "restored",
    "rescan_pending",
    "escalated",
    "removal_pending",
    "removed",
    "failed",
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
        fail(f"invalid quarantine schema JSON: {exc}")

    if schema.get("$id") != "urn:goreecloud:wardveil:quarantine-object:0.1.0":
        fail("unexpected quarantine contract id")
    if set(schema["properties"]["state"]["enum"]) != EXPECTED_STATES:
        fail("quarantine state vocabulary is incomplete")

    reconciliation = schema["properties"]["reconciliation"]["properties"]
    if reconciliation["original_authorization_reusable"].get("const") is not False:
        fail("quarantine reconciliation must permanently prevent original authorization reuse")

    verified_rule = schema["allOf"][0]["then"]["required"]
    for required in (
        "authorization_ref",
        "executor_id",
        "idempotency_key",
        "target_state_ref",
        "verified_resulting_state",
    ):
        if required not in verified_rule:
            fail(f"verified quarantine missing required binding: {required}")

    reference = REFERENCE.read_text(encoding="utf-8")
    for token in (
        "destructive_delete_requires_separate_executor_contract",
        "reconciliation_must_complete_before_new_action",
        "successful_reconciliation_requires_target_state_verification",
        '"original_authorization_reusable": False',
        "target_state_verification_evidence_required",
        "PENDING_STATE_BY_ACTION",
        "SUCCESS_STATE_BY_ACTION",
    ):
        if token not in reference:
            fail(f"quarantine reference missing invariant token: {token}")

    print("Wardveil next-upgrade Quarantine object contract validated.")


if __name__ == "__main__":
    main()
