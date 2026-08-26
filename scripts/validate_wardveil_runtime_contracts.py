#!/usr/bin/env python3
"""Validate Wardveil runtime contract invariants using only the Python standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "wardveil.runtime.schema.json"
DOC_PATH = ROOT / "RUNTIME-CONTRACTS.md"
EXPECTED_ID = "urn:goreecloud:wardveil:runtime:0.1.0"
EXPECTED_RECORD_TYPES = {
    "trust_decision",
    "policy_decision",
    "detection_finding",
    "scan_finding",
    "protection_action",
    "quarantine_record",
    "incident_record",
    "audit_event",
}
FORBIDDEN_KEYS = {
    "password", "passphrase", "private_key", "api_key", "access_token",
    "refresh_token", "recovery_code", "mfa_seed", "session_token",
    "client_secret", "authorization", "cookie",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> None:
    if not SCHEMA_PATH.is_file():
        fail("missing runtime schema")
    if not DOC_PATH.is_file():
        fail("missing runtime contract documentation")

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema.get("$id") != EXPECTED_ID:
        fail("unexpected runtime schema id")

    record_type = schema.get("properties", {}).get("record_type", {})
    values = set(record_type.get("enum", []))
    if values != EXPECTED_RECORD_TYPES:
        fail("runtime record type set is incomplete or contains unknown values")

    keys = set(walk_keys(schema))
    leaked = sorted(keys & FORBIDDEN_KEYS)
    if leaked:
        fail(f"runtime schema contains forbidden secret-bearing field names: {', '.join(leaked)}")

    text = DOC_PATH.read_text(encoding="utf-8").lower()
    required_phrases = (
        "trust is not authorization",
        "unknown and `unsupported` must never be interpreted as clean",
        "explicit executor authority",
        "quarantine is not deletion",
        "does not transfer authority",
        "presentation itself is not proof",
        "fail closed",
    )
    for phrase in required_phrases:
        if phrase.lower() not in text:
            fail(f"runtime documentation missing required boundary: {phrase}")

    properties = schema.get("properties", {})
    scan_values = set(properties.get("scan_result", {}).get("enum", []))
    if not {"unknown", "unsupported"}.issubset(scan_values):
        fail("scan contract must preserve unknown and unsupported results")

    trust_values = set(properties.get("trust_state", {}).get("enum", []))
    if trust_values != {"trusted", "normal", "elevated_risk", "restricted", "blocked"}:
        fail("trust states do not match canonical Wardveil model")

    policy_values = set(properties.get("policy_decision", {}).get("enum", []))
    required_policy = {"allow", "allow_and_log", "warn", "step_up", "restrict", "quarantine", "revoke", "block", "isolate", "escalate"}
    if policy_values != required_policy:
        fail("policy decisions do not match canonical Wardveil model")

    print("Wardveil runtime contract validation passed.")


if __name__ == "__main__":
    main()
