#!/usr/bin/env python3
"""Validate Wardveil Security foundation contracts using only the Python standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_VERSION = "0.2.0"
STATUS_CONTRACT_VERSION = "0.1.0"

REQUIRED_FILES = (
    ".gitignore",
    "README.md",
    "IDENTITY.md",
    "ICON.md",
    "INTEGRATION.md",
    "STATUS.md",
    "CONFORMANCE.md",
    "SECURITY.md",
    "VERSION",
    "contracts/wardveil.identity.json",
    "contracts/wardveil.status.schema.json",
    "examples/wardveil.status.example.json",
)

APPROVED_NAMES = (
    "Wardveil Security by GoreeCloud",
    "Wardveil Security",
    "Wardveil",
    "Protected by Wardveil",
)

RESERVED_NAMES = (
    "Wardveil Access",
    "Wardveil Network",
    "Wardveil Integrity",
    "Wardveil Threats",
    "Wardveil Verify",
    "Wardveil Watch",
    "Wardveil Security Center",
)

ALLOWED_STATES = {
    "protected",
    "attention",
    "degraded",
    "unknown",
    "not_applicable",
}

ALLOWED_EVIDENCE_STATUS = {"current", "stale", "unavailable", "unverified"}
CANONICAL_ICON_PATH = "branding/wardveil-security-icon.svg"

FORBIDDEN_EXAMPLE_KEYS = {
    "password",
    "passphrase",
    "private_key",
    "api_key",
    "access_token",
    "refresh_token",
    "setup_key",
    "recovery_code",
    "mfa_seed",
    "session_token",
    "client_secret",
    "cookie",
}

FORBIDDEN_STRING_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "Bearer ",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(relative_path: str) -> Any:
    path = ROOT / relative_path
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {relative_path}: {exc}")


def walk_json(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_EXAMPLE_KEYS:
                fail(f"status example contains forbidden secret-bearing key: {key}")
            walk_json(child)
    elif isinstance(value, list):
        for child in value:
            walk_json(child)
    elif isinstance(value, str):
        for marker in FORBIDDEN_STRING_MARKERS:
            if marker in value:
                fail("status example contains secret-like material")


def validate_identity_contract() -> None:
    contract = load_json("contracts/wardveil.identity.json")

    if contract.get("foundation_version") != FOUNDATION_VERSION:
        fail("identity contract foundation_version must match VERSION")

    identity = contract.get("identity")
    if not isinstance(identity, dict):
        fail("identity contract must contain an identity object")

    expected = {
        "full_presentation": APPROVED_NAMES[0],
        "primary_name": APPROVED_NAMES[1],
        "short_name": APPROVED_NAMES[2],
        "protection_phrase": APPROVED_NAMES[3],
    }
    if identity != expected:
        fail("machine-readable approved identity does not match the canonical naming contract")

    if contract.get("technical_authority") is not False:
        fail("Wardveil must not be marked as the underlying technical authority")

    reserved = contract.get("reserved_unapproved_component_names")
    if reserved != list(RESERVED_NAMES):
        fail("reserved Wardveil component-name list changed without a foundation update")

    status_contract = contract.get("status_contract")
    if not isinstance(status_contract, dict):
        fail("identity contract must declare the Wardveil status contract")
    if status_contract.get("document") != "STATUS.md":
        fail("STATUS.md must remain the canonical status semantics document")
    if status_contract.get("schema") != "contracts/wardveil.status.schema.json":
        fail("Wardveil status schema path changed without a foundation update")
    if status_contract.get("contract_version") != STATUS_CONTRACT_VERSION:
        fail("unexpected Wardveil status contract version")
    if set(status_contract.get("normalized_states") or []) != ALLOWED_STATES:
        fail("identity contract normalized state vocabulary changed unexpectedly")
    if status_contract.get("missing_evidence_fails_closed") is not True:
        fail("missing evidence must fail closed")
    if status_contract.get("protected_claim_requires_current_authoritative_evidence") is not True:
        fail("Protected by Wardveil must require current authoritative evidence")

    if contract.get("legal_status") != (
        "internal-naming-approved-external-name-conflict-and-legal-clearance-pending"
    ):
        fail("legal status must remain explicit and fail closed while external clearance is pending")

    visual = contract.get("visual_identity")
    if not isinstance(visual, dict):
        fail("identity contract must contain visual_identity metadata")

    if visual.get("description_document") != "ICON.md":
        fail("ICON.md must remain the canonical Wardveil icon-description contract")

    if visual.get("canonical_asset_path") != CANONICAL_ICON_PATH:
        fail("canonical Wardveil icon path changed without a foundation update")

    visual_status = visual.get("canonical_visual_identity_status")
    showcase_status = visual.get("showcase_status")
    icon_exists = (ROOT / CANONICAL_ICON_PATH).is_file()

    if visual_status == "pending-canonical-icon":
        if showcase_status != "blocked-pending-canonical-icon":
            fail("showcase must remain blocked while the canonical Wardveil icon is pending")
        if icon_exists:
            fail(
                "canonical icon asset exists but visual identity is still marked pending; "
                "approve and reconcile status explicitly"
            )
    elif visual_status == "approved":
        if showcase_status != "approved":
            fail("approved canonical icon requires an explicitly approved showcase status")
        if not icon_exists:
            fail(f"approved visual identity requires {CANONICAL_ICON_PATH}")
    else:
        fail(f"unsupported canonical visual identity status: {visual_status!r}")

    if visual.get("temporary_icon_substitution_allowed") is not False:
        fail("temporary icon substitution must remain disallowed")


def validate_status_contract() -> None:
    schema = load_json("contracts/wardveil.status.schema.json")
    example = load_json("examples/wardveil.status.example.json")

    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        fail("status schema must remain a closed top-level object")

    schema_states = (
        schema.get("properties", {}).get("state", {}).get("enum")
        if isinstance(schema.get("properties"), dict)
        else None
    )
    if set(schema_states or []) != ALLOWED_STATES:
        fail("status schema normalized state vocabulary changed unexpectedly")

    contract_version_schema = schema.get("properties", {}).get("contract_version", {}).get("const")
    if contract_version_schema != STATUS_CONTRACT_VERSION:
        fail("status schema contract version changed unexpectedly")

    if example.get("contract_version") != STATUS_CONTRACT_VERSION:
        fail(f"status example must use contract version {STATUS_CONTRACT_VERSION}")

    state = example.get("state")
    if state not in ALLOWED_STATES:
        fail(f"invalid normalized Wardveil state in example: {state!r}")

    scope = example.get("scope")
    if not isinstance(scope, dict) or not scope.get("kind") or not scope.get("id"):
        fail("status example must identify a bounded scope")

    authority = example.get("authority")
    if not isinstance(authority, dict):
        fail("status example must identify the authoritative source")
    if not authority.get("system") or not authority.get("control"):
        fail("status example requires non-empty authority system and control identifiers")

    evidence = example.get("evidence")
    if not isinstance(evidence, dict):
        fail("status example must contain evidence metadata")
    if evidence.get("status") not in ALLOWED_EVIDENCE_STATUS:
        fail("status example contains an unsupported evidence status")
    if not evidence.get("observed_at"):
        fail("status example requires an evidence observation timestamp")

    claim = example.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("protected_by_wardveil"), bool):
        fail("status example requires an explicit Protected by Wardveil boolean")

    protected_claim = claim["protected_by_wardveil"]
    claim_allowed = (
        state == "protected"
        and authority.get("authoritative") is True
        and evidence.get("status") == "current"
        and bool(authority.get("system"))
        and bool(authority.get("control"))
    )
    if protected_claim and not claim_allowed:
        fail("Protected by Wardveil claim violates fail-closed evidence rules")

    privacy = example.get("privacy")
    if not isinstance(privacy, dict):
        fail("status example must contain privacy metadata")
    if not isinstance(privacy.get("details_withheld"), bool):
        fail("status example must explicitly state whether details are withheld")
    if not isinstance(privacy.get("redactions"), list):
        fail("status example privacy.redactions must be an array")

    walk_json(example)


def validate_repository_security() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required_pattern in (".env", "secrets/", "*.key", "*.pem", "credentials.json", "token.json"):
        if required_pattern not in ignore:
            fail(f".gitignore is missing sensitive-information exclusion: {required_pattern}")

    security_doc = (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
    if "reusable secrets" not in security_doc:
        fail("SECURITY.md must preserve the reusable-secret boundary")
    if "private" not in security_doc or "report" not in security_doc:
        fail("SECURITY.md must preserve private security-reporting guidance")


def validate_documentation() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    identity_doc = (ROOT / "IDENTITY.md").read_text(encoding="utf-8")
    icon_doc = (ROOT / "ICON.md").read_text(encoding="utf-8")
    integration = (ROOT / "INTEGRATION.md").read_text(encoding="utf-8")
    status_doc = (ROOT / "STATUS.md").read_text(encoding="utf-8")
    conformance = (ROOT / "CONFORMANCE.md").read_text(encoding="utf-8")

    for name in APPROVED_NAMES:
        if name not in readme and name not in identity_doc:
            fail(f"approved identity term is missing from canonical documentation: {name}")

    if "external name-conflict" not in readme.lower():
        fail("README must preserve the external name-conflict clearance boundary")

    if "technical authority" not in conformance.lower():
        fail("CONFORMANCE.md must preserve the technical-authority boundary")

    if "two softly curved, layered veil panels" not in icon_doc:
        fail("ICON.md must preserve the canonical Wardveil icon concept")

    if "not visually showcase-ready" not in icon_doc.lower():
        fail("ICON.md must preserve the fail-closed showcase gate")

    if "contracts/wardveil.status.schema.json" not in status_doc:
        fail("STATUS.md must identify the machine-readable status schema")

    if "missing evidence" not in integration.lower():
        fail("INTEGRATION.md must preserve fail-closed missing-evidence behavior")


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if version != FOUNDATION_VERSION:
        fail(f"unexpected foundation version: {version!r}")

    validate_identity_contract()
    validate_status_contract()
    validate_repository_security()
    validate_documentation()

    print("Wardveil Security foundation validation passed.")


if __name__ == "__main__":
    main()
