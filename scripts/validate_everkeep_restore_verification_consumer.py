#!/usr/bin/env python3
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.everkeep.restore-verification.json"
DOC = ROOT / "docs/EVERKEEP-RESTORE-VERIFICATION.md"
RUNTIME = ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str):
    if not condition:
        raise SystemExit(message)


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def accepts(record: dict, deployed_revision: str, now: datetime | None = None) -> bool:
    target = record.get("target", {})
    exercise = record.get("exercise", {})
    if record.get("schemaVersion") != "1.1":
        return False
    if record.get("environment") != "production":
        return False
    if record.get("status") != "pass" or record.get("authoritative") is not True:
        return False
    if record.get("securityStateAuthorityTransferred") is not False:
        return False
    if not isinstance(deployed_revision, str) or REVISION_RE.fullmatch(deployed_revision) is None:
        return False
    target_revision = target.get("deployedRevision")
    if not isinstance(target_revision, str) or REVISION_RE.fullmatch(target_revision) is None:
        return False
    if target.get("system") != "Wardveil Security":
        return False
    if target.get("component") != "Cloudflare persistence runtime":
        return False
    if target.get("resourceId") != "goreecloud-wardveil-persistence":
        return False
    if target_revision != deployed_revision:
        return False
    if exercise.get("isolatedVerification") is not True:
        return False
    if exercise.get("integrityVerified") is not True:
        return False
    if exercise.get("restoredStateVerified") is not True:
        return False
    if not record.get("evidenceRefs"):
        return False

    started = parse_timestamp(exercise.get("startedAt"))
    completed = parse_timestamp(exercise.get("completedAt"))
    captured = parse_timestamp(record.get("capturedAt"))
    fresh_until = parse_timestamp(record.get("freshUntil"))
    if None in (started, completed, captured, fresh_until):
        return False

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        return False
    current = current.astimezone(timezone.utc)

    # Everkeep owns the freshness deadline. Wardveil may require a stricter
    # deadline in future policy, but it must never extend this producer-owned
    # bound. At the deadline itself the evidence is expired and fails closed.
    return started < completed <= captured <= current < fresh_until and captured < fresh_until


def main():
    contract = json.loads(CONTRACT.read_text())
    runtime = json.loads(RUNTIME.read_text())
    doc = DOC.read_text()

    expected = {
        "schema_version": 1,
        "consumer": "Wardveil Security",
        "provider": "Everkeep",
        "provider_repository": "GoreeCloud/everkeep",
        "provider_contract_current_verified_revision": "f69e369e4d8627280fac728b7f7bcb02c43b5edd",
        "provider_contract_blob_sha": "158f2afe001be211d91ebfaa3e33c475849d53f9",
        "provider_contract_id": "https://goreecloud.dev/everkeep/contracts/everkeep.restore-verification.v1.1.schema.json",
        "provider_contract_version": "1.1",
        "provider_contract_introduced_in_revision": "4de9a3425215bbee5595eb929c1eb94d94d6f7b2",
        "accepted_environment": "production",
        "satisfies_only": "restore_verification_exercise",
        "pitr_availability_is_restore_verification": False,
        "everkeep_recovery_authority_preserved": True,
        "security_state_authority_transferred": False,
        "protection_claim_authority_transferred": False,
        "accepted_restore_evidence_creates_protected_by_wardveil_claim": False,
    }
    for key, value in expected.items():
        require(contract.get(key) == value, f"Everkeep restore consumer contract mismatch: {key}")

    target = contract.get("target", {})
    require(target == {
        "system": "Wardveil Security",
        "component": "Cloudflare persistence runtime",
        "resource_id": "goreecloud-wardveil-persistence",
        "deployed_revision_must_match_exactly": True,
    }, "restore consumer target binding drifted")

    provider = contract.get("required_provider_evidence", {})
    require(provider == {
        "schema_version": "1.1",
        "status": "pass",
        "authoritative": True,
        "isolated_verification": True,
        "integrity_verified": True,
        "restored_state_verified": True,
        "evidence_refs_required": True,
        "security_state_authority_transferred": False,
        "timezone_qualified_timestamps_required": True,
        "fresh_until_required": True,
        "freshness_deadline_must_be_current": True,
        "consumer_may_shorten_but_not_extend_provider_freshness": True,
    }, "restore consumer provider evidence requirements drifted")

    require("restore_verification_exercise" in runtime.get("required_acceptance_evidence", []), "runtime acceptance must require restore verification")
    require(runtime.get("pitr_availability_is_restore_verification") is False, "PITR must remain distinct from restore verification")
    require(runtime.get("everkeep_recovery_authority_preserved") is True, "Everkeep recovery authority must remain preserved")

    revision = "a" * 40
    fixed_now = datetime(2026, 9, 8, 14, 0, tzinfo=timezone.utc)
    good = {
        "schemaVersion": "1.1",
        "verificationId": "wardveil-restore-test",
        "environment": "production",
        "capturedAt": "2026-09-08T13:30:00Z",
        "freshUntil": "2026-09-08T15:00:00Z",
        "everkeepSourceRevision": "4de9a3425215bbee5595eb929c1eb94d94d6f7b2",
        "target": {
            "system": "Wardveil Security",
            "component": "Cloudflare persistence runtime",
            "resourceId": "goreecloud-wardveil-persistence",
            "deployedRevision": revision,
        },
        "status": "pass",
        "authoritative": True,
        "exercise": {
            "recoveryPointId": "recovery-point-test",
            "startedAt": "2026-09-08T13:00:00Z",
            "completedAt": "2026-09-08T13:20:00Z",
            "isolatedVerification": True,
            "integrityVerified": True,
            "restoredStateVerified": True,
            "promotionToProductionPerformed": False,
        },
        "evidenceRefs": ["everkeep:restore:test"],
        "securityStateAuthorityTransferred": False,
    }
    require(accepts(good, revision, fixed_now), "valid fresh Everkeep restore verification must satisfy Wardveil consumer")

    bad = json.loads(json.dumps(good))
    bad["target"]["deployedRevision"] = "b" * 40
    require(not accepts(bad, revision, fixed_now), "revision-mismatched recovery evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["authoritative"] = False
    require(not accepts(bad, revision, fixed_now), "non-authoritative recovery evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["exercise"]["integrityVerified"] = False
    require(not accepts(bad, revision, fixed_now), "integrity-unverified restore evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["schemaVersion"] = "1.0"
    require(not accepts(bad, revision, fixed_now), "older provider schema version must fail closed after deliberate v1.1 adoption")
    bad = json.loads(json.dumps(good))
    bad["securityStateAuthorityTransferred"] = True
    require(not accepts(bad, revision, fixed_now), "security-authority transfer claim must fail closed")
    bad = json.loads(json.dumps(good))
    bad["capturedAt"] = "2026-09-08T13:30:00"
    require(not accepts(bad, revision, fixed_now), "timezone-less restore evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad.pop("freshUntil")
    require(not accepts(bad, revision, fixed_now), "missing freshness deadline must fail closed")
    bad = json.loads(json.dumps(good))
    bad["freshUntil"] = "2026-09-08T14:00:00Z"
    require(not accepts(bad, revision, fixed_now), "evidence at its freshness deadline must fail closed")
    bad = json.loads(json.dumps(good))
    bad["freshUntil"] = "2026-09-08T13:00:00Z"
    require(not accepts(bad, revision, fixed_now), "freshness deadline before capture must fail closed")
    bad = json.loads(json.dumps(good))
    bad["freshUntil"] = "2026-09-08T15:00:00"
    require(not accepts(bad, revision, fixed_now), "timezone-less freshness deadline must fail closed")
    bad = json.loads(json.dumps(good))
    bad["capturedAt"] = "2026-09-08T14:30:00Z"
    require(not accepts(bad, revision, fixed_now), "future-captured evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["target"]["deployedRevision"] = "not-a-revision"
    require(not accepts(bad, "not-a-revision", fixed_now), "malformed matching revisions must fail closed")

    for phrase in [
        "Everkeep is GoreeCloud's resilience and recovery authority",
        "PITR availability is not restore verification",
        "can satisfy only the recovery-verification requirement",
        "cannot create, extend, reinterpret, or upgrade a `Protected by Wardveil` claim",
        "schemaVersion=1.1",
        "freshUntil",
        "may shorten",
        "must not extend",
        "securityStateAuthorityTransferred=false",
        "timezone-qualified",
    ]:
        require(phrase in doc, f"Everkeep restore handoff documentation missing: {phrase}")

    print("Wardveil Everkeep restore verification v1.1 consumer validation passed")


if __name__ == "__main__":
    main()
