#!/usr/bin/env python3
"""Source validator for Wardveil Work Package G Identity/key lifecycle artifacts."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.identity-key-lifecycle.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_identity_key_lifecycle_v1.py"
DOC = ROOT / "docs/IDENTITY-KEY-LIFECYCLE-V1.md"

EXPECTED_IDENTITY_REVISION = "4ce7d193ff251ce3e7c39b8a19712317dd013c5d"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    reference = REFERENCE.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")

    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "unexpected JSON Schema dialect")
    require(schema.get("additionalProperties") is False, "top-level contract must reject unknown fields")
    require(schema["properties"]["identity_authority"].get("const") == "goreecloud-identity", "Identity authority must be fixed")
    require("direct_wardveil_execution" in schema["properties"]["usage"]["enum"], "direct Wardveil usage boundary missing")
    require("claim_authority" in schema["properties"]["acceptance"]["required"], "claim authority must be explicit")

    required_reference_literals = [
        EXPECTED_IDENTITY_REVISION,
        'MESH_PROFILE = "goreecloud-identity.mesh-service-token.v1"',
        'MESH_AUDIENCE = "goreecloud-mesh"',
        'MESH_ALGORITHM = "RS256"',
        "MESH_MAX_LIFETIME_SECONDS = 900",
        "MESH_CLOCK_SKEW_SECONDS = 60",
        "MIN_RSA_BITS = 2048",
        "mesh_credential_not_direct_wardveil_authority",
        "direct_wardveil_identity_profile_not_approved",
        '"claim_authority": production_accepted',
    ]
    for literal in required_reference_literals:
        require(literal in reference, f"reference model missing required invariant: {literal}")

    required_doc_literals = [
        "GoreeCloud Identity remains the identity, credential, service-identity, and signing-key authority",
        EXPECTED_IDENTITY_REVISION,
        "goreecloud-identity.mesh-service-token.v1",
        "A Mesh service token is **not** direct Wardveil execution authorization.",
        "durable protected private-signing-key custody",
        "tested key rotation",
        "tested credential revocation",
        "tested replay protection",
        "tested expiration enforcement",
        "tested emergency key/credential revocation procedures",
        "The current Work Package G implementation is source-level development work only.",
        "private signing keys",
        "bearer credentials",
    ]
    for literal in required_doc_literals:
        require(literal in documentation, f"documentation missing required boundary: {literal}")

    forbidden_claims = [
        "Work Package G is production accepted",
        "GoreeCloud Identity is production accepted for Wardveil",
        "production_acceptance: true",
    ]
    for claim in forbidden_claims:
        require(claim not in documentation, f"documentation contains unsupported production claim: {claim}")

    print("validated Wardveil Identity/key lifecycle source contract")


if __name__ == "__main__":
    main()
