#!/usr/bin/env python3
"""Fail-closed validation for Wardveil evidence-validity contracts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.status.schema.json"
EXAMPLES = (
    ROOT / "examples" / "wardveil.status.example.json",
    ROOT / "examples" / "wardveil.status.unknown.example.json",
)


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil evidence-validity validation failed: {message}")


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path.relative_to(ROOT)} is unreadable or invalid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a date-time string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{label} is not a valid ISO-8601 date-time")


def main() -> None:
    schema = load(SCHEMA)
    evidence = schema.get("properties", {}).get("evidence", {}).get("properties", {})
    if evidence.get("valid_until", {}).get("format") != "date-time":
        fail("status schema must define evidence.valid_until as date-time")
    serialized = json.dumps(schema, sort_keys=True)
    if serialized.count('"valid_until"') < 3:
        fail("status schema must require valid_until for protected state and Wardveil protection claims")

    for path in EXAMPLES:
        record = load(path)
        evidence_record = record.get("evidence")
        if not isinstance(evidence_record, dict):
            fail(f"{path.name} is missing evidence")
        protected = record.get("state") == "protected" or record.get("claim", {}).get("protected_by_wardveil") is True
        valid_until = evidence_record.get("valid_until")
        if protected and valid_until is None:
            fail(f"{path.name} protected evidence is missing valid_until")
        if valid_until is not None:
            observed = instant(evidence_record.get("observed_at"), f"{path.name} evidence.observed_at")
            deadline = instant(valid_until, f"{path.name} evidence.valid_until")
            if deadline <= observed:
                fail(f"{path.name} validity deadline must be later than observed_at")

    print("Wardveil evidence-validity contract validation passed.")


if __name__ == "__main__":
    main()
