#!/usr/bin/env python3
"""Validate Wardveil Security foundation contracts using only the Python standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION_VERSION = "0.9.0"
STATUS_CONTRACT_VERSION = "0.1.0"
AGGREGATION_CONTRACT_VERSION = "0.1.0"
PRIVACY_SHIELD_PRESENTATION_CONTRACT_VERSION = "0.1.0"
CAPABILITIES_CONTRACT_VERSION = "0.1.0"
RUNTIME_AUTHORIZATION_CONTRACT_VERSION = "0.1.0"
EXECUTION_STATE_CONTRACT_VERSION = "0.1.0"
STATUS_SCHEMA_ID = "urn:goreecloud:wardveil:status:0.1.0"
LEGAL_STATUS = "original-goreecloud-identity-no-known-conflict-formal-clearance-optional-future-due-diligence"

REQUIRED_FILES = (
    ".gitignore", "docs/CHANGELOG.md", "README.md", "docs/ARCHITECTURE.md", "docs/IDENTITY.md", "docs/ICON.md",
    "docs/INTEGRATION.md", "docs/STATUS.md", "docs/CONFORMANCE.md", "docs/COMPATIBILITY.md", "docs/SECURITY.md",
    "docs/THREAT-MODEL.md", "docs/ADOPTION.md", "docs/AGGREGATION.md", "docs/PRIVACY-SHIELD.md", "docs/RUNTIME-AUTHORIZATION.md",
    "docs/EXECUTION-STATE.md", "VERSION",
    "contracts/wardveil.identity.json", "contracts/wardveil.capabilities.json",
    "contracts/wardveil.runtime-authorization.json", "contracts/wardveil.execution-state.json",
    "contracts/wardveil.status.schema.json", "contracts/wardveil.aggregation.vectors.json",
    "contracts/wardveil.privacy-shield.vectors.json", "examples/wardveil.status.example.json",
    "examples/wardveil.status.unknown.example.json", "scripts/validate_wardveil_capabilities.py",
    "scripts/validate_wardveil_runtime_authorization.py", "scripts/validate_wardveil_execution_state.py",
    "scripts/validate_wardveil_aggregation.py", "scripts/validate_wardveil_privacy_shield.py",
)
STATUS_EXAMPLES = ("examples/wardveil.status.example.json", "examples/wardveil.status.unknown.example.json")
APPROVED_NAMES = ("Wardveil Security by GoreeCloud", "Wardveil Security", "Wardveil", "Protected by Wardveil")
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
    state, evidence, claim, authority = example.get("state"), example.get("evidence"), example.get("claim"), example.get("authority")
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
        if evidence_status != "current": fail(f"{path} asserts protected state without current evidence")
        if protected_claim is not True: fail(f"{path} asserts protected state without an eligible Wardveil protection claim")
    elif protected_claim:
        fail(f"{path} asserts a Wardveil protection claim for non-protected state {state!r}")


def main() -> None:
    for path in REQUIRED_FILES: read_text(path)
    version = read_text("VERSION").strip()
    if version != FOUNDATION_VERSION: fail(f"unexpected foundation version: {version!r}")

    combined = "\n".join(read_text(path) for path in ("README.md", "docs/ARCHITECTURE.md", "docs/IDENTITY.md", "docs/INTEGRATION.md", "docs/CONFORMANCE.md", "docs/RUNTIME-AUTHORIZATION.md", "docs/EXECUTION-STATE.md"))
    for name in APPROVED_NAMES:
        if name not in combined: fail(f"approved Wardveil name missing from canonical documentation: {name}")

    identity = read_json("contracts/wardveil.identity.json")
    serialized_identity = json.dumps(identity, sort_keys=True)
    if identity.get("foundation_version") != version: fail("identity contract foundation_version does not match VERSION")
    if identity.get("technical_authority") is not True: fail("Wardveil 0.9 must advertise scoped first-party technical authority")
    if LEGAL_STATUS not in serialized_identity: fail("identity contract does not preserve the approved originality/legal-status boundary")
    if CANONICAL_ICON_PATH not in serialized_identity: fail("identity contract does not preserve the canonical icon path")

    relationships = identity.get("relationships")
    if not isinstance(relationships, dict) or relationships.get("privacy_identity") != "GoreeCloud Privacy Shield": fail("identity contract does not preserve the canonical platform-wide Privacy Shield relationship")
    if relationships.get("resilience_system") != "Everkeep" or relationships.get("coordination_plane") != "GoreeCloud Mesh": fail("identity contract is missing required platform relationships")

    architecture = identity.get("architecture")
    if not isinstance(architecture, dict) or architecture.get("capabilities_contract_version") != CAPABILITIES_CONTRACT_VERSION: fail("identity contract capability architecture metadata is inconsistent")
    approved_caps = set(identity.get("approved_first_party_capabilities") or [])
    required_caps = {"Wardveil Trust", "Wardveil Protect", "Wardveil Detect", "Wardveil Scan", "Wardveil Policy", "Wardveil Quarantine", "Wardveil Audit", "Wardveil Response", "Wardveil Security Center"}
    if approved_caps != required_caps: fail("identity contract does not contain the canonical first-party capability set")

    runtime_auth = identity.get("runtime_authorization_contract")
    if not isinstance(runtime_auth, dict): fail("identity contract runtime authorization metadata is missing")
    if runtime_auth.get("contract_version") != RUNTIME_AUTHORIZATION_CONTRACT_VERSION: fail("identity runtime authorization contract version is inconsistent")
    if runtime_auth.get("high_impact_cross_service_execution_requires_authorization") is not True: fail("identity must require bound authorization for high-impact cross-service execution")
    if runtime_auth.get("policy_decision_alone_is_execution_authority") is not False: fail("identity must separate policy decisions from execution authority")
    if runtime_auth.get("underlying_resource_authority_transferred") is not False: fail("runtime authorization must not transfer target authority")
    if runtime_auth.get("production_runtime_status") != "unaccepted": fail("runtime authorization source metadata must not claim production acceptance")

    execution_state = identity.get("execution_state_contract")
    if not isinstance(execution_state, dict): fail("identity contract execution-state metadata is missing")
    if execution_state.get("contract_version") != EXECUTION_STATE_CONTRACT_VERSION: fail("identity execution-state contract version is inconsistent")
    if execution_state.get("durable_claim_before_high_impact_side_effect") is not True: fail("identity must require a durable claim before high-impact side effects")
    if execution_state.get("pending_claim_requires_reconciliation") is not True: fail("identity must preserve uncertain-outcome reconciliation")
    if execution_state.get("blind_reexecution_after_uncertain_outcome_allowed") is not False: fail("identity must prohibit blind uncertain-outcome re-execution")
    if execution_state.get("durable_receipt_required") is not True: fail("identity must require a durable execution receipt")
    if execution_state.get("persistence_grants_executor_authority") is not False: fail("execution-state persistence must not grant executor authority")
    if execution_state.get("production_runtime_status") != "unaccepted": fail("execution-state source metadata must not claim production acceptance")

    status_metadata = identity.get("status_contract")
    if not isinstance(status_metadata, dict) or status_metadata.get("contract_version") != STATUS_CONTRACT_VERSION: fail("identity contract status-contract version is inconsistent")
    aggregation_metadata = identity.get("aggregation_contract")
    if not isinstance(aggregation_metadata, dict) or aggregation_metadata.get("contract_version") != AGGREGATION_CONTRACT_VERSION: fail("identity contract aggregation-contract version is inconsistent")
    privacy_metadata = identity.get("privacy_shield_presentation_contract")
    if not isinstance(privacy_metadata, dict): fail("identity contract Privacy Shield presentation metadata is missing")
    if privacy_metadata.get("contract_version") != PRIVACY_SHIELD_PRESENTATION_CONTRACT_VERSION: fail("identity contract Privacy Shield presentation version is inconsistent")
    if privacy_metadata.get("read_only") is not True or privacy_metadata.get("raw_private_activity_allowed") is not False or privacy_metadata.get("privacy_authority_transferred") is not False or privacy_metadata.get("included_in_primary_required_control_aggregation_by_default") is not False: fail("Privacy Shield presentation authority boundary is invalid")

    compatibility_metadata = identity.get("compatibility")
    if not isinstance(compatibility_metadata, dict): fail("identity contract compatibility metadata is missing")
    if compatibility_metadata.get("foundation_version_must_match_version_file") is not True: fail("identity contract does not require foundation/version consistency")
    if compatibility_metadata.get("status_contract_version") != STATUS_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong status contract version")
    if compatibility_metadata.get("aggregation_contract_version") != AGGREGATION_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong aggregation contract version")
    if compatibility_metadata.get("privacy_shield_presentation_contract_version") != PRIVACY_SHIELD_PRESENTATION_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong Privacy Shield presentation contract version")
    if compatibility_metadata.get("capabilities_contract_version") != CAPABILITIES_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong capability contract version")
    if compatibility_metadata.get("runtime_authorization_contract_version") != RUNTIME_AUTHORIZATION_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong runtime authorization version")
    if compatibility_metadata.get("execution_state_contract_version") != EXECUTION_STATE_CONTRACT_VERSION: fail("identity compatibility metadata advertises the wrong execution-state version")

    threat_model, adoption, aggregation, compatibility, privacy_shield, architecture_doc, runtime_doc, execution_doc = (read_text(p) for p in ("docs/THREAT-MODEL.md", "docs/ADOPTION.md", "docs/AGGREGATION.md", "docs/COMPATIBILITY.md", "docs/PRIVACY-SHIELD.md", "docs/ARCHITECTURE.md", "docs/RUNTIME-AUTHORIZATION.md", "docs/EXECUTION-STATE.md"))
    for phrase in ("authoritative producer", "fail closed", "Aggregation rule", "read-only"):
        if phrase.lower() not in threat_model.lower(): fail(f"threat model missing required security concept: {phrase}")
    for phrase in ("authoritative producer", "stale or missing evidence", "accessible", "exact-revision"):
        if phrase.lower() not in adoption.lower(): fail(f"adoption contract missing required integration concept: {phrase}")
    for phrase in ("deterministic precedence", "degraded", "attention", "unknown", "not_applicable", "fail closed", "read-only"):
        if phrase.lower() not in aggregation.lower(): fail(f"aggregation contract missing required concept: {phrase}")
    for phrase in ("version domains", "fail-closed metadata consistency", "foundation_version", "unsupported versions", "runtime authorization"):
        if phrase.lower() not in compatibility.lower(): fail(f"compatibility contract missing required concept: {phrase}")
    for phrase in ("platform-wide goreecloud privacy", "separate platform-wide security", "read-only presenter", "primary required-control protection aggregation by default"):
        if phrase.lower() not in privacy_shield.lower(): fail(f"Privacy Shield consumer contract missing required boundary: {phrase}")
    for phrase in ("Wardveil Trust", "Wardveil Policy", "Wardveil Protect", "Wardveil Detect", "Wardveil Scan", "Wardveil Quarantine", "Wardveil Response", "Wardveil Audit", "Wardveil Security Center", "Evidence before reassurance", "runtime execution authorization"):
        if phrase.lower() not in architecture_doc.lower(): fail(f"architecture missing required capability or invariant: {phrase}")
    for phrase in ("policy decision is not", "idempotency", "replay", "production acceptance", "durable execution"):
        if phrase.lower() not in runtime_doc.lower(): fail(f"runtime authorization documentation missing required concept: {phrase}")
    for phrase in ("durable claim", "execution_reconciliation_required", "blind re-execution", "execution receipts", "production acceptance"):
        if phrase.lower() not in execution_doc.lower(): fail(f"execution-state documentation missing required concept: {phrase}")

    runtime_contract = read_json("contracts/wardveil.runtime-authorization.json")
    if runtime_contract.get("contract_version") != RUNTIME_AUTHORIZATION_CONTRACT_VERSION: fail("runtime authorization contract version is inconsistent")
    if runtime_contract.get("foundation_version") != FOUNDATION_VERSION: fail("runtime authorization contract foundation version is inconsistent")
    if (runtime_contract.get("production_acceptance") or {}).get("status") != "unaccepted": fail("runtime authorization contract must preserve unaccepted production state")

    execution_contract = read_json("contracts/wardveil.execution-state.json")
    if execution_contract.get("contract_version") != EXECUTION_STATE_CONTRACT_VERSION: fail("execution-state contract version is inconsistent")
    if execution_contract.get("foundation_version") != FOUNDATION_VERSION: fail("execution-state contract foundation version is inconsistent")
    if execution_contract.get("production_runtime_status") != "unaccepted": fail("execution-state contract must preserve unaccepted production state")
    if (execution_contract.get("claim") or {}).get("blind_reexecution_after_uncertain_outcome_allowed") is not False: fail("execution-state contract must prohibit blind uncertain-outcome re-execution")

    schema = read_json("contracts/wardveil.status.schema.json")
    if schema.get("$id") != STATUS_SCHEMA_ID: fail("unexpected Wardveil status schema id")
    schema_text = json.dumps(schema, sort_keys=True)
    if STATUS_CONTRACT_VERSION not in schema_text: fail("status schema does not preserve the expected contract version")
    for state in ALLOWED_STATES:
        if state not in schema_text: fail(f"status schema missing normalized state: {state}")
    for evidence_state in ALLOWED_EVIDENCE_STATUS:
        if evidence_state not in schema_text: fail(f"status schema missing evidence state: {evidence_state}")

    vectors = read_json("contracts/wardveil.aggregation.vectors.json")
    if vectors.get("contract_version") != AGGREGATION_CONTRACT_VERSION or not isinstance(vectors.get("vectors"), list): fail("aggregation conformance vectors are invalid")
    privacy_vectors = read_json("contracts/wardveil.privacy-shield.vectors.json")
    if privacy_vectors.get("contract_version") != 1 or not isinstance(privacy_vectors.get("vectors"), list): fail("Privacy Shield consumer conformance vectors are invalid")
    for path in STATUS_EXAMPLES: validate_status_example(path, read_json(path))
    icon = ROOT / CANONICAL_ICON_PATH
    if not icon.exists() and ("pending-canonical-icon" not in serialized_identity or "blocked-pending-canonical-icon" not in serialized_identity): fail("canonical icon is absent but identity/showcase state is not fail-closed")
    print(f"Wardveil Security foundation {FOUNDATION_VERSION} validation passed.")


if __name__ == "__main__":
    main()