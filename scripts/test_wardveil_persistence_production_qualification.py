#!/usr/bin/env python3
"""Tests for the Wardveil production persistence qualification boundary."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_wardveil_persistence_production_qualification.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_wardveil_persistence_production_qualification",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

NOW = datetime(2026, 9, 20, 2, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
REF = f"evidence+sha256:{DIGEST}:artifact:wardveil-persistence-qualification/test"


def record(status: str = "complete") -> dict:
    controls = {
        name: {"result": "passed", "evidence_refs": [REF]}
        for name in validator.CONTROLS
    }
    if status == "draft":
        controls["operational_monitoring"] = {"result": "pending", "evidence_refs": []}
    if status == "failed":
        controls["access_control_isolation"] = {"result": "failed", "evidence_refs": [REF]}
    return {
        "schema_version": 1,
        "contract_id": validator.CONTRACT_ID,
        "qualification_id": "persistence-production-test",
        "candidate": {
            "repository": "GoreeCloud/wardveil",
            "exact_source_revision": "1" * 40,
            "source_tree_sha": "2" * 40,
            "persistence_implementation": "reference/wardveil_sqlite_execution_state.py",
            "backend": "SQLite",
            "backend_version": "test",
            "deployment": {
                "environment": "production",
                "boundary_id": "wardveil-security-state-production-a",
                "topology": "single-host qualification fixture",
            },
        },
        "controls": controls,
        "governance": {
            "status": status,
            "authorizing": False,
            "production_acceptance_authorized": False,
            "protected_claim_authorized": False,
            "covered_claim_authorized": False,
            "assessed_at": "2026-09-20T01:00:00Z",
            "valid_until": "2026-10-20T01:00:00Z",
        },
        "privacy": {
            "reusable_credentials_in_record": False,
            "secret_material_in_record": False,
            "raw_private_content_in_record": False,
            "full_authentication_tokens_in_record": False,
            "raw_database_dumps_in_record": False,
        },
        "limitations": [],
    }


def expect_failure(fn) -> None:
    try:
        fn()
    except SystemExit:
        return
    raise AssertionError("expected fail-closed validation")


def main() -> None:
    value = record()
    validator.validate_record(value, label="test", now=NOW)

    stale = record()
    stale["governance"]["valid_until"] = "2026-09-20T01:30:00Z"
    expect_failure(lambda: validator.validate_record(stale, label="stale", now=NOW))

    future = record()
    future["governance"]["assessed_at"] = "2026-09-20T02:01:00Z"
    future["governance"]["valid_until"] = "2026-10-20T02:01:00Z"
    expect_failure(lambda: validator.validate_record(future, label="future", now=NOW))

    promoted = record()
    promoted["governance"]["production_acceptance_authorized"] = True
    expect_failure(lambda: validator.validate_record(promoted, label="promoted", now=NOW))

    protected = record()
    protected["governance"]["protected_claim_authorized"] = True
    expect_failure(lambda: validator.validate_record(protected, label="protected", now=NOW))

    missing_evidence = record()
    missing_evidence["controls"]["backup_creation"]["evidence_refs"] = []
    expect_failure(lambda: validator.validate_record(missing_evidence, label="missing-evidence", now=NOW))

    wrong_repo = record()
    wrong_repo["candidate"]["repository"] = "GoreeCloud/other"
    expect_failure(lambda: validator.validate_record(wrong_repo, label="wrong-repo", now=NOW))

    seen_ids: set[str] = set()
    identity = record()
    path = Path(f"{identity['qualification_id']}.json")
    validator.validate_record_identity(identity, path=path, seen_ids=seen_ids)
    expect_failure(lambda: validator.validate_record_identity(identity, path=path, seen_ids=seen_ids))
    expect_failure(
        lambda: validator.validate_record_identity(
            record(),
            path=Path("different-qualification-id.json"),
            seen_ids=set(),
        )
    )

    failed = record("failed")
    validator.validate_record(failed, label="failed", now=NOW)

    draft = record("draft")
    validator.validate_record(draft, label="draft", now=NOW)

    print("Wardveil persistence production qualification tests passed.")


if __name__ == "__main__":
    main()
