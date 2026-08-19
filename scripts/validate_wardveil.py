#!/usr/bin/env python3
"""Validate Wardveil Security foundation contracts using only the Python standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_VERSION = "0.5.0"
STATUS_CONTRACT_VERSION = "0.1.0"
STATUS_SCHEMA_ID = "urn:goreecloud:wardveil:status:0.1.0"
LEGAL_STATUS = (
    "original-goreecloud-identity-no-known-conflict-formal-clearance-optional-future-due-diligence"
)

REQUIRED_FILES = (
    ".gitignore",
    "CHANGELOG.md",
    "README.md",
    "IDENTITY.md",
    "ICON.md",
    "INTEGRATION.md",
    "STATUS.md",
    "CONFORMANCE.md",
    "SECURITY.md",
    "THREAT-MODEL.md",
    "ADOPTION.md",
    "AGGREGATION.md",
    "VERSION",
    "contracts/wardveil.identity.json",
    "contracts/wardveil.status.schema.json",
    "contracts/wardveil.aggregation.vectors.json",
    "examples/wardveil.status.example.json",
    "examples/wardveil.status.unknown.example.json",
    "scripts/validate_wardveil_aggregation.py",
)

STATUS_EXAMPLES = (
    "examples/wardveil.status.example.json",
    "examples/wardveil.status.unknown.example.json",
)

APPROVED_NAMES = (
    "Wardveil Security by GoreeCloud",
    "Wardveil Security",
    "Wardveil",
    "Protected by Wardveil",
)

ALLOWED_STATES = {"protected", "attention", "degraded", "unknown", "not_applicable"}
ALLOWED_EVIDENCE_STATUS = {"current", "stale", "unavailable", "unverified"}
CANONICAL_ICON_PATH = "branding/wardveil-security-icon.svg"
FORBIDDEN_EXAMPLE_KEYS = {"password", "passphrase", "private_key", "api_key", "access_token", "refresh_token", "setup_key", "recovery_code", "mfa_seed", "session_token", "client_secret", "authorization", "cookie"}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        fail(f"required file missing: {path}")
    return target.read_text(encoding="utf-8")


def read_json(path: str) -> Any:
    try:
        return json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(str(key).lower())
            keys.extend(walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(walk_keys(child))
    return keys


def validate_status_example(path: str, example: Any) -> None:
    if not isinstance(example, dict):
        fail(f"{path} must contain a JSON object")
    keys = set(walk_keys(example))
    leaked = sorted(keys & FORBIDDEN_EXAMPLE_KEYS)
    if leaked:
        fail(f"{path} contains forbidden sensitive key(s): {', '.join(leaked)}")

    state = example.get("state")
    evidence = example.get("evidence")
    claim = example.get("claim")
    authority = example.get("authority")
    if state not in ALLOWED_STATES:
        fail(f"{path} contains invalid normalized state: {state!r}")
    if not isinstance(evidence, dict) or evidence.get("status") not in ALLOWED_EVIDENCE_STATUS:
        fail(f"{path} contains invalid or missing evidence status")
    if not isinstance(claim, dict) or not isinstance(claim.get("protected_by_wardveil"), bool):
        fail(f"{path} must contain a boolean claim.protected_by_wardveil")
    if not isinstance(authority, dict) or authority.get("authoritative") is not True:
        fail(f"{path} must identify an authoritative producer")

    protected_claim = claim["protected_by_wardveil"]
    evidence_status = evidence["status"]
    if state == "protected":
        if evidence_status != "current":
            fail(f"{path} asserts protected state without current evidence")
        if protected_claim is not True:
            fail(f"{path} asserts protected state without an eligible Wardveil protection claim")
    elif protected_claim:
        fail(f"{path} asserts a Wardveil protection claim for non-protected state {state!r}")


def main() -> None:
    for path in REQUIRED_FILES:
        read_text(path)

    version = read_text("VERSION").strip()
    if version != FOUNDATION_VERSION:
        fail(f"unexpected foundation version: {version!r}")

    combined = "\n".join(read_text(path) for path in ("README.md", "IDENTITY.md", "INTEGRATION.md", "CONFORMANCE.md"))
    for name in APPROVED_NAMES:
        if name not in combined:
            fail(f"approved Wardveil name missing from canonical documentation: {name}")

    identity = read_json("contracts/wardveil.identity.json")
    serialized_identity = json.dumps(identity, sort_keys=True)
    if LEGAL_STATUS not in serialized_identity:
        fail("identity contract does not preserve the approved originality/legal-status boundary")
    if CANONICAL_ICON_PATH not in serialized_identity:
        fail("identity contract does not preserve the canonical icon path")

    threat_model = read_text("THREAT-MODEL.md")
    adoption = read_text("ADOPTION.md")
    aggregation = read_text("AGGREGATION.md")
    for phrase in ("authoritative producer", "fail closed", "Aggregation rule", "read-only"):
        if phrase.lower() not in threat_model.lower():
            fail(f"threat model missing required security concept: {phrase}")
    for phrase in ("authoritative producer", "stale or missing evidence", "accessible", "exact-revision"):
        if phrase.lower() not in adoption.lower():
            fail(f"adoption contract missing required integration concept: {phrase}")
    for phrase in ("deterministic precedence", "degraded", "attention", "unknown", "not_applicable", "fail closed", "read-only"):
        if phrase.lower() not in aggregation.lower():
            fail(f"aggregation contract missing required concept: {phrase}")

    schema = read_json("contracts/wardveil.status.schema.json")
    if schema.get("$id") != STATUS_SCHEMA_ID:
        fail("unexpected Wardveil status schema id")
    schema_text = json.dumps(schema, sort_keys=True)
    for state in ALLOWED_STATES:
        if state not in schema_text:
            fail(f"status schema missing normalized state: {state}")
    for evidence_state in ALLOWED_EVIDENCE_STATUS:
        if evidence_state not in schema_text:
            fail(f"status schema missing evidence state: {evidence_state}")

    vectors = read_json("contracts/wardveil.aggregation.vectors.json")
    if vectors.get("contract_version") != "0.1.0" or not isinstance(vectors.get("vectors"), list):
        fail("aggregation conformance vectors are invalid")

    for path in STATUS_EXAMPLES:
        validate_status_example(path, read_json(path))

    icon = ROOT / CANONICAL_ICON_PATH
    if not icon.exists():
        if "pending-canonical-icon" not in serialized_identity or "blocked-pending-canonical-icon" not in serialized_identity:
            fail("canonical icon is absent but identity/showcase state is not fail-closed")

    print(f"Wardveil Security foundation {FOUNDATION_VERSION} validation passed.")


if __name__ == "__main__":
    main()
