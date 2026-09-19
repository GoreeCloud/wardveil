from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_privacy_shield_runtime_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_privacy_shield_runtime_acceptance", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

NOW = datetime(2026, 9, 19, 22, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def ref(name: str, digest: str | None = None) -> str:
    return f"evidence+sha256:{digest or ('b' * 64)}:artifact:{name}"


def record() -> dict:
    return {
        "schema_version": 1,
        "contract_id": validator.CONTRACT_ID,
        "record_id": "privacy-shield-runtime-test",
        "privacy_shield": {
            "producer_repository": validator.PRIVACY_SHIELD_REPO,
            "producer_revision": "1" * 40,
            "producer_source_tree_sha": "2" * 40,
            "adapter_id": "browser",
            "runtime_authority": "GoreeCloud/goreecloud-browser",
            "status_schema_version": 1,
            "status_record_sha256": DIGEST,
            "status_record_reference": ref("status", DIGEST),
        },
        "wardveil": {
            "consumer_repository": validator.WARDVEIL_REPO,
            "consumer_revision": "3" * 40,
            "consumer_source_tree_sha": "4" * 40,
        },
        "transport": {
            "authenticated": True,
            "encrypted": True,
            "producer_service_identity": "privacy-shield",
            "identity_authority": validator.IDENTITY_AUTHORITY,
            "evidence_reference": ref("transport"),
        },
        "privacy": {
            "raw_private_activity_included": False,
            "contains_credentials": False,
            "contains_identifiers": False,
        },
        "acceptance": {
            "producer_runtime_status": "passed",
            "producer_production_approved": True,
            "wardveil_consumer_status": "passed",
            "shared_interaction_status": "passed",
            "observed_at": "2026-09-19T21:00:00Z",
            "reviewed_at": "2026-09-19T21:30:00Z",
            "valid_until": "2026-09-20T21:00:00Z",
            "production_approved": False,
            "authorization_effect": False,
            "authority_transfer": False,
            "protected_by_wardveil": False,
        },
        "evidence": [
            {"id": category.replace("_", "-"), "category": category, "result": "passed", "reference": ref(category)}
            for category in sorted(validator.REQUIRED_EVIDENCE)
        ],
        "limitations": ["Synthetic test-only record."],
    }


def expect_failure(mutator) -> None:
    candidate = record()
    mutator(candidate)
    try:
        validator.validate_record(candidate, now=NOW)
    except SystemExit:
        return
    raise AssertionError("expected validation failure")


def main() -> None:
    validator.validate_contract()
    validator.validate_schema()
    validator.validate_record(record(), now=NOW)

    expect_failure(lambda r: r["acceptance"].__setitem__("protected_by_wardveil", True))
    expect_failure(lambda r: r["acceptance"].__setitem__("production_approved", True))
    expect_failure(lambda r: r["privacy"].__setitem__("contains_identifiers", True))
    expect_failure(lambda r: r["transport"].__setitem__("authenticated", False))
    expect_failure(lambda r: r["privacy_shield"].__setitem__("status_record_reference", ref("wrong")))
    expect_failure(lambda r: r["acceptance"].__setitem__("valid_until", "2026-09-19T21:45:00Z"))
    expect_failure(lambda r: r["evidence"].pop())

    print("Wardveil Privacy Shield runtime acceptance conformance tests passed.")


if __name__ == "__main__":
    main()
