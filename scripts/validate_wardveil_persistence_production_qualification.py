#!/usr/bin/env python3
"""Validate Wardveil production persistence qualification records."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.persistence-production-qualification.schema.json"
QUALIFICATION_DIR = ROOT / "qualification" / "persistence-production"
README = QUALIFICATION_DIR / "README.md"
EXECUTION_STATE = ROOT / "contracts" / "wardveil.execution-state.json"
PERSISTENCE_DOC = ROOT / "PERSISTENCE.md"

CONTRACT_ID = "goreecloud.wardveil.persistence-production-qualification.v1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]*$")
EVIDENCE = re.compile(
    r"^evidence\+sha256:[0-9a-f]{64}:(?:https://|github://|gdrive://|qualification-run:|artifact:)\S+$"
)
CONTROLS = {
    "durable_restart_recovery",
    "transactional_atomicity",
    "concurrent_writer_integrity",
    "encryption_at_rest",
    "credential_and_key_custody",
    "retention_enforcement",
    "backup_creation",
    "restore_verification",
    "migration_and_rollback",
    "tamper_and_integrity_detection",
    "storage_failure_behavior",
    "access_control_isolation",
    "privacy_safe_observability",
    "operational_monitoring",
    "everkeep_recovery_boundary",
}
PRIVACY_FIELDS = {
    "reusable_credentials_in_record",
    "secret_material_in_record",
    "raw_private_content_in_record",
    "full_authentication_tokens_in_record",
    "raw_database_dumps_in_record",
}


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil persistence production qualification validation failed: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{label} is unreadable or invalid JSON: {exc}")
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def parse_time(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and value == value.strip(), f"{label} must be canonical text")
    require(bool(re.search(r"(?:Z|[+-]\d{2}:\d{2})$", value)), f"{label} must be timezone-qualified")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        fail(f"{label} must be a valid date-time: {exc}")
    require(parsed.tzinfo is not None, f"{label} must be timezone-qualified")
    return parsed.astimezone(timezone.utc)


def validate_record_identity(record: dict[str, Any], *, path: Path, seen_ids: set[str]) -> None:
    qualification_id = record.get("qualification_id")
    require(
        isinstance(qualification_id, str) and SLUG.fullmatch(qualification_id) is not None,
        f"{path}: invalid qualification_id",
    )
    require(path.stem == qualification_id, f"{path}: filename must match qualification_id")
    require(qualification_id not in seen_ids, f"{path}: duplicate qualification_id: {qualification_id}")
    seen_ids.add(qualification_id)


def validate_record(record: dict[str, Any], *, label: str, now: datetime | None = None) -> None:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expected = {
        "schema_version",
        "contract_id",
        "qualification_id",
        "candidate",
        "controls",
        "governance",
        "privacy",
        "limitations",
    }
    require(set(record) == expected, f"{label}: top-level fields drifted")
    require(record["schema_version"] == 1, f"{label}: schema_version drifted")
    require(record["contract_id"] == CONTRACT_ID, f"{label}: contract_id drifted")
    require(
        isinstance(record["qualification_id"], str)
        and SLUG.fullmatch(record["qualification_id"]) is not None,
        f"{label}: invalid qualification_id",
    )

    candidate = record["candidate"]
    candidate_fields = {
        "repository",
        "exact_source_revision",
        "source_tree_sha",
        "persistence_implementation",
        "backend",
        "backend_version",
        "deployment",
    }
    require(isinstance(candidate, dict) and set(candidate) == candidate_fields, f"{label}: candidate fields drifted")
    require(candidate["repository"] == "GoreeCloud/wardveil", f"{label}: candidate repository drifted")
    require(
        isinstance(candidate["exact_source_revision"], str)
        and SHA40.fullmatch(candidate["exact_source_revision"]) is not None,
        f"{label}: exact_source_revision must be immutable",
    )
    require(
        isinstance(candidate["source_tree_sha"], str)
        and SHA40.fullmatch(candidate["source_tree_sha"]) is not None,
        f"{label}: source_tree_sha must be immutable",
    )
    for field in ("persistence_implementation", "backend", "backend_version"):
        require(
            isinstance(candidate[field], str) and candidate[field].strip(),
            f"{label}: candidate.{field} required",
        )

    deployment = candidate["deployment"]
    require(
        isinstance(deployment, dict)
        and set(deployment) == {"environment", "boundary_id", "topology"},
        f"{label}: deployment fields drifted",
    )
    require(
        isinstance(deployment["environment"], str)
        and SLUG.fullmatch(deployment["environment"]) is not None,
        f"{label}: deployment.environment invalid",
    )
    require(
        isinstance(deployment["boundary_id"], str) and deployment["boundary_id"].strip(),
        f"{label}: deployment.boundary_id required",
    )
    require(
        isinstance(deployment["topology"], str) and deployment["topology"].strip(),
        f"{label}: deployment.topology required",
    )

    controls = record["controls"]
    require(isinstance(controls, dict) and set(controls) == CONTROLS, f"{label}: control vocabulary drifted")
    failed = 0
    for name, criterion in controls.items():
        require(
            isinstance(criterion, dict) and set(criterion) == {"result", "evidence_refs"},
            f"{label}: {name} fields drifted",
        )
        result = criterion["result"]
        refs = criterion["evidence_refs"]
        require(result in {"pending", "passed", "failed"}, f"{label}: invalid result for {name}")
        require(
            isinstance(refs, list) and len(refs) == len(set(refs)),
            f"{label}: {name} evidence_refs must be a unique list",
        )
        require(
            all(isinstance(ref, str) and EVIDENCE.fullmatch(ref) is not None for ref in refs),
            f"{label}: {name} has invalid evidence reference",
        )
        if result != "pending":
            require(bool(refs), f"{label}: resolved control {name} requires evidence")
        if result == "failed":
            failed += 1

    governance = record["governance"]
    governance_fields = {
        "status",
        "authorizing",
        "production_acceptance_authorized",
        "protected_claim_authorized",
        "covered_claim_authorized",
        "assessed_at",
        "valid_until",
    }
    require(
        isinstance(governance, dict) and set(governance) == governance_fields,
        f"{label}: governance fields drifted",
    )
    status = governance["status"]
    require(status in {"draft", "complete", "failed", "superseded"}, f"{label}: invalid governance.status")
    for field in (
        "authorizing",
        "production_acceptance_authorized",
        "protected_claim_authorized",
        "covered_claim_authorized",
    ):
        require(governance[field] is False, f"{label}: {field} must remain false")

    assessed_at = parse_time(governance["assessed_at"], f"{label}.governance.assessed_at")
    valid_until = parse_time(governance["valid_until"], f"{label}.governance.valid_until")
    require(assessed_at <= now, f"{label}: assessed_at cannot be future-dated")
    require(valid_until > assessed_at, f"{label}: valid_until must be after assessed_at")

    if status == "complete":
        require(
            all(item["result"] == "passed" for item in controls.values()),
            f"{label}: complete qualification requires all controls passed",
        )
        require(valid_until > now, f"{label}: complete qualification is stale")
    elif status == "failed":
        require(failed > 0, f"{label}: failed qualification requires at least one failed control")
    elif status == "draft":
        require(
            not all(item["result"] == "passed" for item in controls.values()),
            f"{label}: fully passed qualification must be complete, not draft",
        )

    privacy = record["privacy"]
    require(
        isinstance(privacy, dict) and set(privacy) == PRIVACY_FIELDS,
        f"{label}: privacy fields drifted",
    )
    require(
        all(privacy[field] is False for field in PRIVACY_FIELDS),
        f"{label}: qualification privacy boundary violated",
    )

    limitations = record["limitations"]
    require(
        isinstance(limitations, list) and len(limitations) == len(set(limitations)),
        f"{label}: limitations must be a unique list",
    )
    require(
        all(isinstance(item, str) and item.strip() for item in limitations),
        f"{label}: limitations must contain non-empty strings",
    )


def validate_schema() -> None:
    schema = load_json(SCHEMA, "persistence production qualification schema")
    require(schema.get("additionalProperties") is False, "schema must remain closed")
    require(
        schema.get("properties", {}).get("contract_id", {}).get("const") == CONTRACT_ID,
        "schema contract id drifted",
    )
    control_props = schema.get("properties", {}).get("controls", {}).get("properties", {})
    require(set(control_props) == CONTROLS, "schema control vocabulary drifted")
    require(
        set(schema.get("properties", {}).get("controls", {}).get("required", [])) == CONTROLS,
        "schema required controls drifted",
    )
    privacy_props = schema.get("properties", {}).get("privacy", {}).get("properties", {})
    require(set(privacy_props) == PRIVACY_FIELDS, "schema privacy vocabulary drifted")
    require(
        all(privacy_props[field].get("const") is False for field in PRIVACY_FIELDS),
        "schema privacy boundary weakened",
    )


def validate_source_boundaries() -> None:
    execution_state = load_json(EXECUTION_STATE, "execution-state contract")
    require(
        execution_state.get("production_runtime_status") == "unaccepted",
        "qualification boundary must not silently promote execution-state production status",
    )
    persistence_text = PERSISTENCE_DOC.read_text(encoding="utf-8").lower()
    for marker in (
        "production qualification",
        "non-authorizing",
        "not production acceptance",
        "everkeep",
    ):
        require(marker in persistence_text, f"PERSISTENCE.md missing qualification boundary marker: {marker}")


def main() -> None:
    validate_schema()
    validate_source_boundaries()

    count = 0
    seen_ids: set[str] = set()
    if QUALIFICATION_DIR.exists():
        for path in sorted(QUALIFICATION_DIR.glob("*.json")):
            record = load_json(path, str(path))
            validate_record_identity(record, path=path, seen_ids=seen_ids)
            validate_record(record, label=str(path))
            count += 1

    readme = README.read_text(encoding="utf-8").lower().replace("**", "")
    for marker in (
        "not production acceptance",
        "non-authorizing",
        "no production persistence qualification records",
        "protected by wardveil",
        "covered",
    ):
        require(marker in readme, f"qualification README missing boundary marker: {marker}")

    print(
        "Wardveil production persistence qualification boundary is consistent; "
        f"records={count}. Qualification evidence remains exact-candidate/deployment-bound, "
        "privacy-minimized, non-authorizing, and unable to create production acceptance, "
        "Protected by Wardveil, Covered, release, or Stable state."
    )


if __name__ == "__main__":
    main()
