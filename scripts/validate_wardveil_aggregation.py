#!/usr/bin/env python3
"""Validate Wardveil deterministic aggregation semantics using the standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "contracts/wardveil.aggregation.vectors.json"
ALLOWED = {"protected", "attention", "degraded", "unknown", "not_applicable"}
PRECEDENCE = ("degraded", "attention", "unknown", "protected", "not_applicable")


class AggregationError(ValueError):
    pass


def aggregate(states: list[str]) -> tuple[str, bool]:
    if not states:
        raise AggregationError("empty-required-set")
    if any(state not in ALLOWED for state in states):
        raise AggregationError("invalid-state")

    applicable = [state for state in states if state != "not_applicable"]
    if not applicable:
        return "not_applicable", False

    for candidate in PRECEDENCE:
        if candidate == "not_applicable":
            continue
        if candidate in applicable:
            return candidate, candidate == "protected" and all(
                state in {"protected", "not_applicable"} for state in states
            )

    raise AggregationError("unreachable-state")


def main() -> None:
    payload = json.loads(VECTORS.read_text(encoding="utf-8"))
    if payload.get("contract_version") != "0.1.0":
        raise SystemExit("ERROR: unexpected aggregation contract version")
    if payload.get("precedence") != list(PRECEDENCE):
        raise SystemExit("ERROR: aggregation precedence drift")

    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise SystemExit("ERROR: aggregation vectors missing")

    seen: set[str] = set()
    for vector in vectors:
        name = vector.get("name")
        if not isinstance(name, str) or not name or name in seen:
            raise SystemExit("ERROR: invalid or duplicate aggregation vector name")
        seen.add(name)
        states = vector.get("states")
        if not isinstance(states, list) or not all(isinstance(v, str) for v in states):
            raise SystemExit(f"ERROR: {name}: states must be a string list")

        expected_error = vector.get("expected_error")
        try:
            state, claim = aggregate(states)
        except AggregationError as exc:
            if expected_error != str(exc):
                raise SystemExit(f"ERROR: {name}: unexpected error {exc!s}")
            continue

        if expected_error is not None:
            raise SystemExit(f"ERROR: {name}: expected error {expected_error!r}")
        if state != vector.get("expected_state"):
            raise SystemExit(f"ERROR: {name}: expected state {vector.get('expected_state')!r}, got {state!r}")
        if claim is not vector.get("expected_claim"):
            raise SystemExit(f"ERROR: {name}: protection claim mismatch")
        if claim and state != "protected":
            raise SystemExit(f"ERROR: {name}: non-protected aggregate asserted protection")

    print(f"Wardveil aggregation conformance passed ({len(vectors)} vectors).")


if __name__ == "__main__":
    main()
