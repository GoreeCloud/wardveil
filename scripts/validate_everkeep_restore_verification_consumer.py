#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.everkeep.restore-verification.json"
DOC = ROOT / "EVERKEEP-RESTORE-VERIFICATION.md"
RUNTIME = ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json"


def require(condition: bool, message: str):
    if not condition:
        raise SystemExit(message)


def accepts(record: dict, deployed_revision: str) -> bool:
    target = record.get("target", {})
    exercise = record.get("exercise", {})
    if record.get("environment") != "production":
        return False
    if record.get("status") != "pass" or record.get("authoritative") is not True:
        return False
    if target.get("system") != "Wardveil Security":
        return False
    if target.get("component") != "Cloudflare persistence runtime":
        return False
    if target.get("resourceId") != "goreecloud-wardveil-persistence":
        return False
    if target.get("deployedRevision") != deployed_revision:
        return False
    if exercise.get("isolatedVerification") is not True:
        return False
    if exercise.get("integrityVerified") is not True:
        return False
    if exercise.get("restoredStateVerified") is not True:
        return False
    if not record.get("evidenceRefs"):
        return False
    try:
        started = datetime.fromisoformat(exercise["startedAt"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(exercise["completedAt"].replace("Z", "+00:00"))
        captured = datetime.fromisoformat(record["capturedAt"].replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError):
        return False
    return started < completed <= captured <= datetime.now(timezone.utc)


def main():
    contract = json.loads(CONTRACT.read_text())
    runtime = json.loads(RUNTIME.read_text())
    doc = DOC.read_text()

    expected = {
        "schema_version": 1,
        "consumer": "Wardveil Security",
        "provider": "Everkeep",
        "provider_repository": "GoreeCloud/goreecloud-everkeep",
        "provider_contract_id": "https://goreecloud.dev/everkeep/contracts/everkeep.restore-verification.schema.json",
        "provider_contract_version": "1.0",
        "provider_contract_introduced_in_revision": "33c5c6e85cbe6057225199811891644c4c65cac5",
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
        "status": "pass",
        "authoritative": True,
        "isolated_verification": True,
        "integrity_verified": True,
        "restored_state_verified": True,
        "evidence_refs_required": True,
    }, "restore consumer provider evidence requirements drifted")

    require("restore_verification_exercise" in runtime.get("required_acceptance_evidence", []), "runtime acceptance must require restore verification")
    require(runtime.get("pitr_availability_is_restore_verification") is False, "PITR must remain distinct from restore verification")
    require(runtime.get("everkeep_recovery_authority_preserved") is True, "Everkeep recovery authority must remain preserved")

    revision = "a" * 40
    good = {
        "schemaVersion": "1.0",
        "verificationId": "wardveil-restore-test",
        "environment": "production",
        "capturedAt": "2026-08-26T21:30:00Z",
        "everkeepSourceRevision": "33c5c6e85cbe6057225199811891644c4c65cac5",
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
            "startedAt": "2026-08-26T21:00:00Z",
            "completedAt": "2026-08-26T21:20:00Z",
            "isolatedVerification": True,
            "integrityVerified": True,
            "restoredStateVerified": True,
            "promotionToProductionPerformed": False,
        },
        "evidenceRefs": ["everkeep:restore:test"],
        "securityStateAuthorityTransferred": False,
    }
    require(accepts(good, revision), "valid Everkeep restore verification must satisfy Wardveil consumer")

    bad = json.loads(json.dumps(good))
    bad["target"]["deployedRevision"] = "b" * 40
    require(not accepts(bad, revision), "revision-mismatched recovery evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["authoritative"] = False
    require(not accepts(bad, revision), "non-authoritative recovery evidence must fail closed")
    bad = json.loads(json.dumps(good))
    bad["exercise"]["integrityVerified"] = False
    require(not accepts(bad, revision), "integrity-unverified restore evidence must fail closed")

    for phrase in [
        "Everkeep is GoreeCloud's resilience and recovery authority",
        "PITR availability is not restore verification",
        "can satisfy only the recovery-verification requirement",
        "cannot create, extend, reinterpret, or upgrade a `Protected by Wardveil` claim",
    ]:
        require(phrase in doc, f"Everkeep restore handoff documentation missing: {phrase}")

    print("Wardveil Everkeep restore verification consumer validation passed")


if __name__ == "__main__":
    main()
