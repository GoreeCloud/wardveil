#!/usr/bin/env python3
"""Validate Wardveil Privacy Shield runtime-acceptance governance and records."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.privacy-shield.runtime-acceptance.json"
SCHEMA = ROOT / "contracts" / "wardveil.privacy-shield.runtime-acceptance.schema.json"
RECORDS = ROOT / "acceptance" / "privacy-shield"

CONTRACT_ID = "goreecloud.wardveil.privacy-shield.runtime-acceptance.v1"
PRIVACY_SHIELD_REPO = "GoreeCloud/goreecloud-privacy-shield"
WARDVEIL_REPO = "GoreeCloud/goreecloud-wardveil"
IDENTITY_AUTHORITY = "GoreeCloud/goreecloud-identity"
REVIEWED_PRIVACY_REVISION = "536099d16f114bde4d32d1e0865b1c9bf55a00d7"
REVIEWED_PRIVACY_TREE = "2a9e2cfe9adce463899d9647768f37c803a308ec"
REVIEWED_PRIVACY_RUN = 35472816139
REVIEWED_PRIVACY_RUN_NUMBER = 486
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
REPO = re.compile(r"^GoreeCloud/[A-Za-z0-9._-]+$")
EVIDENCE = re.compile(r"^evidence\+sha256:([0-9a-f]{64}):\S+$")
REQUIRED_EVIDENCE = {
    "producer-runtime",
    "producer-provider-acceptance",
    "authenticated-transport",
    "target-environment",
    "privacy-minimization",
    "wardveil-consumer",
}


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Privacy Shield runtime acceptance validation failed: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{label} is unreadable or invalid: {exc}")
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and value and value == value.strip(), f"{label} must be canonical text")
    require(re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value) is not None, f"{label} must be timezone-qualified")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        fail(f"{label} must be a valid date-time: {exc}")
    require(parsed.tzinfo is not None, f"{label} must be timezone-qualified")
    return parsed.astimezone(timezone.utc)


def evidence_ref(value: Any, label: str, expected_digest: str | None = None) -> str:
    require(isinstance(value, str) and value == value.strip(), f"{label} must be canonical text")
    match = EVIDENCE.fullmatch(value)
    require(match is not None, f"{label} must be content-addressed evidence+sha256")
    if expected_digest is not None:
        require(match.group(1) == expected_digest, f"{label} digest does not match bound record digest")
    return value


def validate_contract() -> None:
    contract = load_json(CONTRACT, "runtime acceptance contract")
    require(contract.get("schema_version") == 1, "contract schema_version drifted")
    require(contract.get("contract_id") == CONTRACT_ID, "contract identity drifted")
    reviewed = contract.get("reviewed_privacy_shield_source")
    require(isinstance(reviewed, dict), "reviewed Privacy Shield source missing")
    require(reviewed.get("repository") == PRIVACY_SHIELD_REPO, "reviewed producer repository drifted")
    require(reviewed.get("revision") == REVIEWED_PRIVACY_REVISION, "reviewed producer revision drifted")
    require(reviewed.get("source_tree_sha") == REVIEWED_PRIVACY_TREE, "reviewed producer tree drifted")
    require(reviewed.get("validation_run_id") == REVIEWED_PRIVACY_RUN, "reviewed producer validation run drifted")
    require(reviewed.get("validation_run_number") == REVIEWED_PRIVACY_RUN_NUMBER, "reviewed producer validation run number drifted")
    require(contract.get("acceptance_schema") == "contracts/wardveil.privacy-shield.runtime-acceptance.schema.json", "acceptance schema path drifted")
    require(contract.get("acceptance_records") == "acceptance/privacy-shield/*.json", "acceptance record path drifted")
    require(set(contract.get("required_acceptance_evidence") or []) == REQUIRED_EVIDENCE, "required evidence vocabulary drifted")
    transport = contract.get("required_transport") or {}
    require(transport == {
        "authenticated": True,
        "encrypted": True,
        "producer_service_identity": "privacy-shield",
        "identity_authority": IDENTITY_AUTHORITY,
    }, "required transport boundary drifted")
    require(contract.get("privacy") == {
        "raw_private_activity_included": False,
        "contains_credentials": False,
        "contains_identifiers": False,
    }, "privacy minimization boundary drifted")
    authority = contract.get("authority_boundary") or {}
    for key in (
        "source_validation_is_runtime_acceptance",
        "producer_runtime_acceptance_transfers_authority",
        "shared_interaction_acceptance_authorizes_target_execution",
        "shared_interaction_acceptance_authorizes_protected_by_wardveil",
        "shared_interaction_acceptance_is_wardveil_production_acceptance",
    ):
        require(authority.get(key) is False, f"authority boundary weakened: {key}")
    require(contract.get("production_runtime_status") == "unaccepted", "source contract must remain unaccepted")


def validate_schema() -> None:
    schema = load_json(SCHEMA, "runtime acceptance schema")
    require(schema.get("additionalProperties") is False, "runtime acceptance schema must remain closed")
    props = schema.get("properties") or {}
    require(props.get("contract_id", {}).get("const") == CONTRACT_ID, "schema contract identity drifted")
    require(props.get("privacy_shield", {}).get("properties", {}).get("producer_repository", {}).get("const") == PRIVACY_SHIELD_REPO, "schema producer repository drifted")
    require(props.get("wardveil", {}).get("properties", {}).get("consumer_repository", {}).get("const") == WARDVEIL_REPO, "schema Wardveil repository drifted")
    tprops = props.get("transport", {}).get("properties", {})
    require(tprops.get("authenticated", {}).get("const") is True, "authenticated transport must remain mandatory")
    require(tprops.get("encrypted", {}).get("const") is True, "encrypted transport must remain mandatory")
    require(tprops.get("identity_authority", {}).get("const") == IDENTITY_AUTHORITY, "Identity authority drifted")
    aprops = props.get("acceptance", {}).get("properties", {})
    require(aprops.get("producer_runtime_status", {}).get("const") == "passed", "producer runtime acceptance must be passed")
    require(aprops.get("producer_production_approved", {}).get("const") is True, "producer production approval must be explicit")
    require(aprops.get("wardveil_consumer_status", {}).get("const") == "passed", "Wardveil consumer acceptance must be passed")
    require(aprops.get("shared_interaction_status", {}).get("const") == "passed", "shared interaction acceptance must be passed")
    require(aprops.get("production_approved", {}).get("const") is False, "shared interaction record must not self-approve Wardveil production")
    require(aprops.get("authorization_effect", {}).get("const") is False, "shared interaction record must not authorize")
    require(aprops.get("authority_transfer", {}).get("const") is False, "shared interaction record must not transfer authority")
    require(aprops.get("protected_by_wardveil", {}).get("const") is False, "shared interaction record must not grant Protected by Wardveil")


def validate_record(record: dict[str, Any], *, now: datetime | None = None, label: str = "runtime acceptance record") -> None:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expected = {"schema_version","contract_id","record_id","privacy_shield","wardveil","transport","privacy","acceptance","evidence","limitations"}
    require(set(record) == expected, f"{label}: top-level fields drifted")
    require(record["schema_version"] == 1 and record["contract_id"] == CONTRACT_ID, f"{label}: schema identity mismatch")
    require(isinstance(record["record_id"], str) and SLUG.fullmatch(record["record_id"]) is not None, f"{label}: invalid record_id")

    producer = record["privacy_shield"]
    producer_fields = {"producer_repository","producer_revision","producer_source_tree_sha","adapter_id","runtime_authority","status_schema_version","status_record_sha256","status_record_reference"}
    require(isinstance(producer, dict) and set(producer) == producer_fields, f"{label}: privacy_shield fields drifted")
    require(producer["producer_repository"] == PRIVACY_SHIELD_REPO, f"{label}: producer repository mismatch")
    require(isinstance(producer["producer_revision"], str) and SHA40.fullmatch(producer["producer_revision"]) is not None, f"{label}: invalid producer revision")
    require(isinstance(producer["producer_source_tree_sha"], str) and SHA40.fullmatch(producer["producer_source_tree_sha"]) is not None, f"{label}: invalid producer tree")
    require(isinstance(producer["adapter_id"], str) and SLUG.fullmatch(producer["adapter_id"]) is not None, f"{label}: invalid adapter_id")
    require(isinstance(producer["runtime_authority"], str) and REPO.fullmatch(producer["runtime_authority"]) is not None, f"{label}: invalid runtime_authority")
    require(producer["status_schema_version"] == 1, f"{label}: unsupported status schema version")
    require(isinstance(producer["status_record_sha256"], str) and SHA256.fullmatch(producer["status_record_sha256"]) is not None, f"{label}: invalid status record digest")
    evidence_ref(producer["status_record_reference"], f"{label}.privacy_shield.status_record_reference", producer["status_record_sha256"])

    consumer = record["wardveil"]
    require(isinstance(consumer, dict) and set(consumer) == {"consumer_repository","consumer_revision","consumer_source_tree_sha"}, f"{label}: Wardveil fields drifted")
    require(consumer["consumer_repository"] == WARDVEIL_REPO, f"{label}: Wardveil repository mismatch")
    require(isinstance(consumer["consumer_revision"], str) and SHA40.fullmatch(consumer["consumer_revision"]) is not None, f"{label}: invalid Wardveil revision")
    require(isinstance(consumer["consumer_source_tree_sha"], str) and SHA40.fullmatch(consumer["consumer_source_tree_sha"]) is not None, f"{label}: invalid Wardveil tree")

    transport = record["transport"]
    require(isinstance(transport, dict) and set(transport) == {"authenticated","encrypted","producer_service_identity","identity_authority","evidence_reference"}, f"{label}: transport fields drifted")
    require(transport["authenticated"] is True and transport["encrypted"] is True, f"{label}: transport must be authenticated and encrypted")
    require(transport["producer_service_identity"] == "privacy-shield", f"{label}: producer service identity mismatch")
    require(transport["identity_authority"] == IDENTITY_AUTHORITY, f"{label}: Identity authority mismatch")
    evidence_ref(transport["evidence_reference"], f"{label}.transport.evidence_reference")

    privacy = record["privacy"]
    require(isinstance(privacy, dict) and privacy == {"raw_private_activity_included":False,"contains_credentials":False,"contains_identifiers":False}, f"{label}: privacy minimization boundary violated")

    acceptance = record["acceptance"]
    acceptance_fields = {"producer_runtime_status","producer_production_approved","wardveil_consumer_status","shared_interaction_status","observed_at","reviewed_at","valid_until","production_approved","authorization_effect","authority_transfer","protected_by_wardveil"}
    require(isinstance(acceptance, dict) and set(acceptance) == acceptance_fields, f"{label}: acceptance fields drifted")
    require(acceptance["producer_runtime_status"] == "passed", f"{label}: producer runtime is not accepted")
    require(acceptance["producer_production_approved"] is True, f"{label}: producer production approval is required")
    require(acceptance["wardveil_consumer_status"] == "passed", f"{label}: Wardveil consumer runtime is not accepted")
    require(acceptance["shared_interaction_status"] == "passed", f"{label}: shared interaction is not accepted")
    require(acceptance["production_approved"] is False, f"{label}: shared interaction cannot self-approve Wardveil production")
    require(acceptance["authorization_effect"] is False and acceptance["authority_transfer"] is False and acceptance["protected_by_wardveil"] is False, f"{label}: authority/protection boundary violated")
    observed = parse_time(acceptance["observed_at"], f"{label}.acceptance.observed_at")
    reviewed = parse_time(acceptance["reviewed_at"], f"{label}.acceptance.reviewed_at")
    valid_until = parse_time(acceptance["valid_until"], f"{label}.acceptance.valid_until")
    require(observed <= reviewed <= now, f"{label}: review chronology is invalid or future-dated")
    require(valid_until > reviewed and valid_until > now, f"{label}: acceptance is expired or has invalid validity")

    evidence = record["evidence"]
    require(isinstance(evidence, list) and 6 <= len(evidence) <= 30, f"{label}: evidence count invalid")
    ids: set[str] = set()
    categories: set[str] = set()
    for index, item in enumerate(evidence):
        require(isinstance(item, dict) and set(item) == {"id","category","result","reference"}, f"{label}: evidence[{index}] fields drifted")
        require(isinstance(item["id"], str) and SLUG.fullmatch(item["id"]) is not None and item["id"] not in ids, f"{label}: invalid or duplicate evidence id")
        ids.add(item["id"])
        require(item["category"] in REQUIRED_EVIDENCE, f"{label}: unsupported evidence category")
        require(item["result"] == "passed", f"{label}: every required evidence result must pass")
        evidence_ref(item["reference"], f"{label}.evidence[{index}].reference")
        categories.add(item["category"])
    require(categories == REQUIRED_EVIDENCE, f"{label}: required evidence coverage is incomplete")

    limitations = record["limitations"]
    require(isinstance(limitations, list) and len(limitations) <= 30 and len(limitations) == len(set(limitations)), f"{label}: limitations invalid")
    require(all(isinstance(item, str) and item.strip() for item in limitations), f"{label}: limitations must be non-empty strings")


def validate_repository() -> int:
    validate_contract()
    validate_schema()
    count = 0
    if RECORDS.exists():
        for path in sorted(RECORDS.glob("*.json")):
            validate_record(load_json(path, f"runtime acceptance record {path}"), label=str(path))
            count += 1
    return count


def main() -> None:
    count = validate_repository()
    print(
        "Wardveil Privacy Shield runtime acceptance boundary passed "
        f"(accepted_record_files={count}, production_runtime_status=unaccepted, "
        "authorization_effect=false, protected_by_wardveil=false)."
    )


if __name__ == "__main__":
    main()
