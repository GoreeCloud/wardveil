#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.privacy-shield.consumer-source-evidence.json"
DOC = ROOT / "PRIVACY-SHIELD.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(
            f"Wardveil Privacy Shield public-source evidence validation failed: {message}"
        )


def main() -> None:
    require(EVIDENCE.is_file(), "missing public producer-source evidence record")
    require(DOC.is_file(), "missing PRIVACY-SHIELD.md")

    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    expected_top_level = {
        "schema_version",
        "producer",
        "integration",
        "source_integration_status",
        "runtime_acceptance_status",
        "provider_production_acceptance_status",
        "public_interoperability_contract",
        "evidence",
        "runtime_acceptance_requirements_remaining",
        "source_evidence_is_runtime_acceptance",
        "source_evidence_is_production_acceptance",
        "source_evidence_authorizes_protected_by_wardveil",
    }
    require(set(record) == expected_top_level, "unexpected top-level public evidence fields")

    require(record["schema_version"] == 2, "unexpected evidence schema version")
    require(record["producer"] == "GoreeCloud Privacy Shield", "unexpected producer")
    require(
        record["integration"] == "Wardveil read-only Privacy Shield status consumer",
        "unexpected integration",
    )
    require(record["source_integration_status"] == "implemented", "source integration must remain implemented")
    require(record["runtime_acceptance_status"] == "unaccepted", "runtime acceptance must remain unaccepted")
    require(
        record["provider_production_acceptance_status"] == "unaccepted",
        "provider production acceptance must remain unaccepted",
    )

    public_contract = record["public_interoperability_contract"]
    require(
        set(public_contract)
        == {
            "status_schema_version",
            "scope",
            "producer_source_provenance_published",
            "private_repository_inventory_included",
            "restricted_operational_detail_included",
        },
        "unexpected public interoperability fields",
    )
    require(public_contract["status_schema_version"] == 1, "unexpected status schema version")
    require(
        public_contract["scope"] == "minimized read-only privacy status presentation",
        "unexpected public contract scope",
    )
    require(public_contract["producer_source_provenance_published"] is False, "producer provenance must remain unpublished")
    require(public_contract["private_repository_inventory_included"] is False, "private repository inventory must remain excluded")
    require(public_contract["restricted_operational_detail_included"] is False, "restricted operational detail must remain excluded")

    details = record["evidence"]
    expected_details = {
        "full_record_status_validation_required",
        "malformed_status_fails_closed",
        "expired_status_fails_closed",
        "future_dated_status_fails_closed",
        "unsafe_privacy_status_fails_closed",
        "runtime_acceptance_required",
        "producer_authority_preserved",
        "public_record_contains_credentials",
        "public_record_contains_private_repository_inventory",
        "public_record_contains_restricted_operational_evidence",
    }
    require(set(details) == expected_details, "unexpected public evidence detail fields")
    for key in (
        "full_record_status_validation_required",
        "malformed_status_fails_closed",
        "expired_status_fails_closed",
        "future_dated_status_fails_closed",
        "unsafe_privacy_status_fails_closed",
        "runtime_acceptance_required",
        "producer_authority_preserved",
    ):
        require(details[key] is True, f"missing required public invariant: {key}")

    for key in (
        "public_record_contains_credentials",
        "public_record_contains_private_repository_inventory",
        "public_record_contains_restricted_operational_evidence",
    ):
        require(details[key] is False, f"{key} must remain false")

    required_remaining = {
        "real_privacy_shield_runtime_acceptance",
        "producer_production_acceptance",
        "deployed_identity_and_authenticated_transport_acceptance",
        "shared_interaction_target_environment_acceptance",
        "independent_wardveil_runtime_acceptance",
    }
    require(
        required_remaining.issubset(
            set(record["runtime_acceptance_requirements_remaining"])
        ),
        "runtime acceptance remainder is incomplete",
    )

    require(record["source_evidence_is_runtime_acceptance"] is False, "source evidence must not equal runtime acceptance")
    require(record["source_evidence_is_production_acceptance"] is False, "source evidence must not equal production acceptance")
    require(
        record["source_evidence_authorizes_protected_by_wardveil"] is False,
        "public source evidence must not authorize Protected by Wardveil",
    )

    doc = DOC.read_text(encoding="utf-8").lower()
    for phrase in (
        "public producer-source evidence",
        "source evidence does not establish runtime acceptance",
        "provider production acceptance remains unaccepted",
        "shared interaction",
        "protected by wardveil",
    ):
        require(phrase in doc, f"Privacy Shield documentation missing public boundary: {phrase}")

    print(
        "Wardveil Privacy Shield public-source evidence validation passed; "
        "public interoperability data is minimized and runtime/provider "
        "production acceptance remains unaccepted."
    )


if __name__ == "__main__":
    main()
