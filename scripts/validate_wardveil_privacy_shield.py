#!/usr/bin/env python3
"""Validate the Wardveil read-only Privacy Shield presentation contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "contracts" / "wardveil.privacy-shield.vectors.json"
DOC = ROOT / "PRIVACY-SHIELD.md"

ALLOWED_SOURCE_STATES = {"protected", "partial", "attention", "unavailable", "development"}
ALLOWED_WARDVEIL_STATES = {"protected", "attention", "unknown"}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def map_state(*, state: str, production_approved: bool, privacy_safe: bool, runtime_acceptance_required: bool) -> tuple[str, bool]:
    """Return conservative Wardveil presentation state and claim eligibility."""
    if not privacy_safe or not runtime_acceptance_required:
        return "unknown", False
    if state == "protected":
        return ("protected" if production_approved else "unknown"), False
    if state in {"partial", "attention"}:
        return "attention", False
    if state in {"unavailable", "development"}:
        return "unknown", False
    return "unknown", False


def main() -> None:
    if not DOC.is_file():
        fail("missing PRIVACY-SHIELD.md")
    text = DOC.read_text(encoding="utf-8").lower()
    for phrase in (
        "platform-wide goreecloud privacy",
        "separate platform-wide security",
        "raw_private_activity_included",
        "contains_credentials",
        "contains_identifiers",
        "runtime_acceptance_required",
        "claim.protected_by_wardveil=true",
        "excluded from wardveil's primary required-control protection aggregation by default",
        "presentation interoperability contract only",
    ):
        if phrase not in text:
            fail(f"Privacy Shield consumer contract missing invariant: {phrase}")

    try:
        payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid Privacy Shield conformance vectors: {exc}")

    if payload.get("contract_version") != 1:
        fail("unsupported Privacy Shield bridge contract version")
    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        fail("Privacy Shield conformance vectors must be a non-empty list")

    names: set[str] = set()
    covered_source_states: set[str] = set()
    unsafe_case = False
    acceptance_case = False
    for vector in vectors:
        if not isinstance(vector, dict):
            fail("each Privacy Shield conformance vector must be an object")
        name = vector.get("name")
        if not isinstance(name, str) or not name or name in names:
            fail("Privacy Shield vector names must be unique non-empty strings")
        names.add(name)

        state = vector.get("privacy_shield_state")
        if state not in ALLOWED_SOURCE_STATES:
            fail(f"{name}: unsupported Privacy Shield state {state!r}")
        covered_source_states.add(state)

        production_approved = vector.get("production_approved")
        privacy_safe = vector.get("privacy_safe")
        runtime_acceptance_required = vector.get("runtime_acceptance_required")
        if not all(isinstance(value, bool) for value in (production_approved, privacy_safe, runtime_acceptance_required)):
            fail(f"{name}: approval/privacy/acceptance inputs must be boolean")

        expected_state = vector.get("expected_wardveil_state")
        expected_claim = vector.get("expected_protected_by_wardveil")
        if expected_state not in ALLOWED_WARDVEIL_STATES:
            fail(f"{name}: unsupported Wardveil state {expected_state!r}")
        if expected_claim is not False:
            fail(f"{name}: Privacy Shield presentation must never produce Protected by Wardveil")

        actual_state, actual_claim = map_state(
            state=state,
            production_approved=production_approved,
            privacy_safe=privacy_safe,
            runtime_acceptance_required=runtime_acceptance_required,
        )
        if (actual_state, actual_claim) != (expected_state, expected_claim):
            fail(f"{name}: expected {(expected_state, expected_claim)!r}, got {(actual_state, actual_claim)!r}")

        if not privacy_safe:
            unsafe_case = actual_state == "unknown" and actual_claim is False
        if not runtime_acceptance_required:
            acceptance_case = actual_state == "unknown" and actual_claim is False

    if covered_source_states != ALLOWED_SOURCE_STATES:
        fail(f"conformance vectors do not cover all Privacy Shield states: {sorted(ALLOWED_SOURCE_STATES - covered_source_states)}")
    if not unsafe_case:
        fail("missing fail-closed unsafe-privacy vector")
    if not acceptance_case:
        fail("missing fail-closed runtime-acceptance vector")

    print(f"Wardveil Privacy Shield consumer validation passed; {len(vectors)} vectors verified.")


if __name__ == "__main__":
    main()
