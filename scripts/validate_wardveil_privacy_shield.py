#!/usr/bin/env python3
"""Validate the Wardveil read-only Privacy Shield presentation contract."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "contracts" / "wardveil.privacy-shield.vectors.json"
DOC = ROOT / "PRIVACY-SHIELD.md"

ALLOWED_SOURCE_STATES = {"protected", "partial", "attention", "unavailable", "development"}
ALLOWED_CAPABILITY_STATES = {"active", "inactive", "pending-acceptance", "unavailable"}
ALLOWED_WARDVEIL_STATES = {"protected", "attention", "unknown"}
TOP_LEVEL_KEYS = {
    "schema_version",
    "producer",
    "generated_at",
    "valid_until",
    "state",
    "capabilities",
    "privacy",
    "acceptance",
}
PRODUCER_KEYS = {"adapter_id", "product", "runtime_authority", "adapter_contract_version"}
CAPABILITY_KEYS = {"id", "state"}
PRIVACY_KEYS = {"raw_private_activity_included", "contains_credentials", "contains_identifiers"}
ACCEPTANCE_KEYS = {"runtime_acceptance_required", "production_approved"}
ADAPTER_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
RUNTIME_AUTHORITY_RE = re.compile(r"^GoreeCloud/[A-Za-z0-9._-]+$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def exact_keys(value: Any, *, allowed: set[str], required: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    unexpected = set(value) - allowed
    if unexpected:
        raise ValueError(f"{label} contains unsupported properties: {sorted(unexpected)}")
    missing = required - set(value)
    if missing:
        raise ValueError(f"{label} is missing required properties: {sorted(missing)}")


def parse_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty date-time without surrounding whitespace")
    if not RFC3339_RE.fullmatch(value):
        raise ValueError(f"{label} must be an offset-qualified RFC 3339 date-time")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid date-time") from exc


def validate_status_record(record: Any, *, observed_at: str) -> dict[str, Any]:
    exact_keys(
        record,
        allowed=TOP_LEVEL_KEYS,
        required={"schema_version", "producer", "generated_at", "state", "capabilities", "privacy", "acceptance"},
        label="status record",
    )
    if record["schema_version"] != 1:
        raise ValueError("unsupported Privacy Shield status schema_version")

    producer = record["producer"]
    exact_keys(producer, allowed=PRODUCER_KEYS, required=PRODUCER_KEYS, label="producer")
    if not isinstance(producer["adapter_id"], str) or not ADAPTER_RE.fullmatch(producer["adapter_id"]):
        raise ValueError("producer.adapter_id is invalid")
    if not isinstance(producer["product"], str) or not producer["product"]:
        raise ValueError("producer.product must be a non-empty string")
    if (
        not isinstance(producer["runtime_authority"], str)
        or not RUNTIME_AUTHORITY_RE.fullmatch(producer["runtime_authority"])
    ):
        raise ValueError("producer.runtime_authority is invalid")
    if (
        isinstance(producer["adapter_contract_version"], bool)
        or not isinstance(producer["adapter_contract_version"], int)
        or producer["adapter_contract_version"] < 1
    ):
        raise ValueError("producer.adapter_contract_version must be an integer >= 1")

    generated_at = parse_datetime(record["generated_at"], "generated_at")
    observed = parse_datetime(observed_at, "observed_at")
    valid_until = None
    if "valid_until" in record:
        valid_until = parse_datetime(record["valid_until"], "valid_until")
        if valid_until <= generated_at:
            raise ValueError("valid_until must be later than generated_at")

    state = record["state"]
    if state not in ALLOWED_SOURCE_STATES:
        raise ValueError(f"unsupported Privacy Shield state {state!r}")

    capabilities = record["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise ValueError("capabilities must be a non-empty list")
    capability_ids: set[str] = set()
    for index, capability in enumerate(capabilities):
        exact_keys(
            capability,
            allowed=CAPABILITY_KEYS,
            required=CAPABILITY_KEYS,
            label=f"capabilities[{index}]",
        )
        capability_id = capability["id"]
        if not isinstance(capability_id, str) or not capability_id:
            raise ValueError(f"capabilities[{index}].id must be non-empty")
        if capability_id in capability_ids:
            raise ValueError(f"duplicate capability id: {capability_id}")
        capability_ids.add(capability_id)
        if capability["state"] not in ALLOWED_CAPABILITY_STATES:
            raise ValueError(f"capabilities[{index}].state is unsupported")

    privacy = record["privacy"]
    exact_keys(privacy, allowed=PRIVACY_KEYS, required=PRIVACY_KEYS, label="privacy")
    if privacy["raw_private_activity_included"] is not False:
        raise ValueError("raw private activity must not be included")
    if privacy["contains_credentials"] is not False:
        raise ValueError("credentials must not be included")
    if privacy["contains_identifiers"] is not False:
        raise ValueError("identifiers must not be included")

    acceptance = record["acceptance"]
    exact_keys(acceptance, allowed=ACCEPTANCE_KEYS, required=ACCEPTANCE_KEYS, label="acceptance")
    if acceptance["runtime_acceptance_required"] is not True:
        raise ValueError("runtime acceptance boundary must remain required")
    if not isinstance(acceptance["production_approved"], bool):
        raise ValueError("production_approved must be boolean")

    if (state == "protected" or acceptance["production_approved"] is True) and valid_until is None:
        raise ValueError("protected or production-approved status requires valid_until")

    return {
        "state": state,
        "production_approved": acceptance["production_approved"],
        "expired": valid_until is not None and observed > valid_until,
        "generated_in_future": generated_at > observed,
    }


def map_record(record: Any, *, observed_at: str) -> tuple[str, bool]:
    """Return conservative Wardveil presentation state and claim eligibility."""
    try:
        validated = validate_status_record(record, observed_at=observed_at)
    except ValueError:
        return "unknown", False

    if validated["expired"] or validated["generated_in_future"]:
        return "unknown", False

    state = validated["state"]
    if state == "protected":
        return ("protected" if validated["production_approved"] else "unknown"), False
    if state in {"partial", "attention"}:
        return "attention", False
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
        "full-record validation",
        "expired",
        "future-dated",
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
    protected_success = False
    expired_case = False
    future_case = False
    malformed_case = False
    for vector in vectors:
        if not isinstance(vector, dict):
            fail("each Privacy Shield conformance vector must be an object")
        name = vector.get("name")
        if not isinstance(name, str) or not name or name in names:
            fail("Privacy Shield vector names must be unique non-empty strings")
        names.add(name)

        record = vector.get("status_record")
        observed_at = vector.get("observed_at")
        if not isinstance(observed_at, str):
            fail(f"{name}: observed_at must be a date-time string")

        if isinstance(record, dict) and record.get("state") in ALLOWED_SOURCE_STATES:
            covered_source_states.add(record["state"])

        expected_state = vector.get("expected_wardveil_state")
        expected_claim = vector.get("expected_protected_by_wardveil")
        if expected_state not in ALLOWED_WARDVEIL_STATES:
            fail(f"{name}: unsupported Wardveil state {expected_state!r}")
        if expected_claim is not False:
            fail(f"{name}: Privacy Shield presentation must never produce Protected by Wardveil")

        actual_state, actual_claim = map_record(record, observed_at=observed_at)
        if (actual_state, actual_claim) != (expected_state, expected_claim):
            fail(f"{name}: expected {(expected_state, expected_claim)!r}, got {(actual_state, actual_claim)!r}")

        protected_success = protected_success or actual_state == "protected"
        expired_case = expired_case or ("expired" in name and actual_state == "unknown")
        future_case = future_case or ("future" in name and actual_state == "unknown")
        malformed_case = malformed_case or (
            any(token in name for token in ("unsafe", "malformed", "duplicate", "extra", "acceptance"))
            and actual_state == "unknown"
        )

    if covered_source_states != ALLOWED_SOURCE_STATES:
        fail(f"conformance vectors do not cover all Privacy Shield states: {sorted(ALLOWED_SOURCE_STATES - covered_source_states)}")
    if not protected_success:
        fail("missing accepted protected Privacy Shield vector")
    if not expired_case:
        fail("missing fail-closed expired Privacy Shield vector")
    if not future_case:
        fail("missing fail-closed future-dated Privacy Shield vector")
    if not malformed_case:
        fail("missing fail-closed malformed Privacy Shield vectors")

    print(f"Wardveil Privacy Shield full-record consumer validation passed; {len(vectors)} vectors verified.")


if __name__ == "__main__":
    main()
