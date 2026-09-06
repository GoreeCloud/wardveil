#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json"
SCHEMA = ROOT / "contracts" / "wardveil.cloudflare.acceptance-evidence.schema.json"
TEMPLATE = ROOT / "evidence" / "wardveil.cloudflare.production.template.json"
DOC = ROOT / "RUNTIME-ACCEPTANCE-EVIDENCE.md"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise SystemExit(message)


def parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"{field} must be RFC3339/ISO8601") from exc
    if parsed.tzinfo is None:
        fail(f"{field} must include timezone")
    return parsed.astimezone(timezone.utc)


def main() -> None:
    runtime = load(RUNTIME)
    schema = load(SCHEMA)
    template = load(TEMPLATE)
    doc = DOC.read_text(encoding="utf-8")

    required = runtime.get("required_acceptance_evidence")
    if not isinstance(required, list) or not required:
        fail("runtime acceptance contract must define required_acceptance_evidence")
    if runtime.get("evidence_validity_seconds") != 3600:
        fail("runtime acceptance producer validity policy must remain exactly one hour")

    schema_required = schema.get("required") or []
    if "valid_until" not in schema_required:
        fail("runtime acceptance evidence schema must require producer valid_until")
    valid_until_schema = (schema.get("properties") or {}).get("valid_until") or {}
    if valid_until_schema.get("type") != "string" or valid_until_schema.get("format") != "date-time":
        fail("runtime acceptance valid_until schema must remain a date-time string")

    checks_schema = schema.get("properties", {}).get("checks", {})
    checks_required = checks_schema.get("required")
    schema_properties = checks_schema.get("properties", {})
    if checks_required != required:
        fail("acceptance-evidence schema required checks must exactly match runtime acceptance contract order")
    if set(schema_properties) != set(required):
        fail("acceptance-evidence schema properties must exactly match required evidence checks")

    checks = template.get("checks")
    if list(checks or {}) != required:
        fail("production evidence template checks must exactly match runtime acceptance contract order")
    if template.get("acceptance_status") != "unaccepted":
        fail("source-controlled production evidence template must remain unaccepted")
    if template.get("deployed_revision") != "0" * 40:
        fail("source-controlled evidence template must not claim a deployed revision")
    if template.get("storage_health_is_protection_claim") is not False:
        fail("storage health must not become a protection claim")
    if template.get("everkeep_recovery_authority_preserved") is not True:
        fail("Everkeep recovery authority must remain preserved")

    collected_at = parse_timestamp(template.get("collected_at"), "template collected_at")
    valid_until = parse_timestamp(template.get("valid_until"), "template valid_until")
    if collected_at != datetime(1970, 1, 1, tzinfo=timezone.utc):
        fail("source-controlled evidence template must retain sentinel collection time")
    if valid_until - collected_at != timedelta(seconds=runtime["evidence_validity_seconds"]):
        fail("source-controlled template must demonstrate the canonical producer validity window")
    if valid_until >= datetime(2000, 1, 1, tzinfo=timezone.utc):
        fail("source-controlled runtime acceptance template must remain unmistakably expired")

    for name in required:
        check = checks[name]
        if check.get("status") != "pending":
            fail(f"template check {name} must remain pending until live evidence exists")
        if check.get("observed_at") is not None or check.get("source") is not None:
            fail(f"template check {name} must not contain invented live evidence")
        if not check.get("summary"):
            fail(f"template check {name} requires a bounded summary")

    invariants = [
        "Deployment success is not runtime acceptance",
        "Storage health is not a Wardveil protection claim",
        "Acceptance is revision-bound",
        "must not create a generic public record-mutation endpoint",
        "PITR availability proves that the storage platform exposes recovery capability. It is not a successful recovery exercise",
        "Everkeep's resilience and recovery authority",
        "valid_until",
        "one hour",
        "Consumers may reject expired evidence but may not extend its validity",
    ]
    for invariant in invariants:
        if invariant not in doc:
            fail(f"runtime acceptance evidence documentation missing invariant: {invariant}")

    print("Wardveil Cloudflare runtime acceptance evidence contract and producer validity policy are valid")


if __name__ == "__main__":
    main()
