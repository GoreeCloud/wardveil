#!/usr/bin/env python3
"""Source validator for Wardveil operation-scoped Trust, Session, and Device Posture."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.trust-posture.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_trust_posture_v2.py"
DOC = ROOT / "TRUST-SESSION-DEVICE-POSTURE-V2.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    reference = REFERENCE.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")

    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "unexpected JSON Schema dialect")
    require(schema.get("additionalProperties") is False, "top-level trust contract must reject unknown fields")
    required = set(schema.get("required", []))
    for field in ("subject_id", "device_id", "session_id", "runtime_id", "application_id", "action", "impact", "inputs"):
        require(field in required, f"trust contract missing exact operation scope field {field}")

    input_states = set(schema["properties"]["inputs"]["items"]["properties"]["state"]["enum"])
    require(input_states == {"present", "missing", "stale", "conflicting", "invalid"}, "trust input states drifted")

    for literal in (
        '"authorization_effect": False',
        '"execution_authorization": False',
        '"target_authority": False',
        '"global_trust": False',
        "HIGH_IMPACT_MAX_AGE_SECONDS = 300",
        "session_revoked",
        "credential_compromised",
        "runtime_integrity_failed",
        "material_posture_changed",
        "material_security_incident",
        "proposed_trusted_state_not_supported",
    ):
        require(literal in reference, f"reference model missing invariant: {literal}")

    for literal in (
        "Trust is not authorization.",
        "No global trust state",
        "Trusted",
        "Restricted",
        "Unknown",
        "Untrusted",
        "Reauthentication Required",
        "high-impact",
        "source-level Development candidate",
        "does not establish production trust acceptance",
    ):
        require(literal in documentation, f"documentation missing trust boundary: {literal}")

    print("validated Wardveil Trust, Session, and Device Posture source contract")


if __name__ == "__main__":
    main()
