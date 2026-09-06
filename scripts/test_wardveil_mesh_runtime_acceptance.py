#!/usr/bin/env python3
"""Regression tests for Wardveil runtime-acceptance Mesh evidence binding."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_runtime_acceptance import (
    RUNTIME_ACCEPTANCE_VALIDITY_SECONDS,
    WARDVEIL_RUNTIME_ACCEPTANCE_CONTRACT,
    create_runtime_acceptance_mesh_evidence,
    validate_runtime_acceptance_manifest,
)
from reference.wardveil_mesh_evidence import create_mesh_evidence_envelope

NOW = datetime(2026, 9, 6, 1, 30, tzinfo=timezone.utc)
COLLECTED = NOW - timedelta(minutes=5)
VALID_UNTIL = COLLECTED + timedelta(seconds=RUNTIME_ACCEPTANCE_VALIDITY_SECONDS)
SOURCE_REVISION = "a" * 40
DEPLOYED_REVISION = "b" * 40
CHECKS = (
    "deployed_revision_match",
    "health_endpoint",
    "authorized_append_read",
    "duplicate_record_rejection",
    "checkpoint_non_regression",
    "retention_alarm_evidence",
    "payload_digest_verification",
    "pitr_availability",
    "restore_verification_exercise",
    "observability_failure_evidence",
    "public_mutation_surface_absent",
)


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil runtime-acceptance Mesh regression failed: {message}")


def expect_value_error(callback, message: str) -> None:
    try:
        callback()
    except ValueError:
        return
    fail(message)


def manifest(status: str = "accepted") -> dict:
    checks = {
        name: {
            "status": "passed",
            "observed_at": (COLLECTED - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
            "source": f"wardveil://acceptance-check/{name}",
            "summary": f"Synthetic bounded {name} acceptance evidence.",
        }
        for name in CHECKS
    }
    return {
        "schema_version": 1,
        "component": "Wardveil Cloudflare persistence runtime",
        "environment": "production",
        "deployed_revision": DEPLOYED_REVISION,
        "collected_at": COLLECTED.isoformat().replace("+00:00", "Z"),
        "valid_until": VALID_UNTIL.isoformat().replace("+00:00", "Z"),
        "acceptance_status": status,
        "checks": checks,
        "storage_health_is_protection_claim": False,
        "everkeep_recovery_authority_preserved": True,
    }


accepted = manifest()
validated = validate_runtime_acceptance_manifest(accepted, now=NOW)
if validated["acceptance_status"] != "accepted" or validated["deployed_revision"] != DEPLOYED_REVISION:
    fail("canonical accepted manifest was not preserved by validation")

envelope = create_runtime_acceptance_mesh_evidence(accepted, revision=SOURCE_REVISION, now=NOW)
if envelope.get("assertion") != "runtime-acceptance" or envelope.get("outcome") != "accepted":
    fail("runtime acceptance producer outcome was not derived into the Mesh envelope")
producer = envelope.get("producer") or {}
if producer.get("system") != "wardveil-security" or producer.get("contract") != WARDVEIL_RUNTIME_ACCEPTANCE_CONTRACT:
    fail("runtime acceptance producer identity or contract drifted")
if envelope.get("valid_until") != accepted["valid_until"] or envelope.get("observed_at") != accepted["collected_at"]:
    fail("runtime acceptance producer validity was not preserved")
if envelope.get("subject") != {"kind": "runtime", "id": "goreecloud-wardveil-persistence", "scope": "production"}:
    fail("runtime acceptance subject binding drifted")
if envelope.get("contains_user_content") is not False or envelope.get("contains_secret_material") is not False:
    fail("runtime acceptance minimization flags weakened")

# The generic runtime-record adapter must continue refusing this family. The
# dedicated acceptance adapter is the only approved source binding.
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        {
            "contract_version": "0.1.0",
            "record_type": "policy_decision",
            "record_id": "policy-runtime-acceptance-confusion",
            "correlation_id": "corr-runtime-acceptance-confusion",
            "producer": {"id": "wardveil-policy", "authoritative": True},
            "scope": {"resource_type": "service", "resource_id": "goreecloud-wardveil-persistence"},
            "observed_at": COLLECTED.isoformat(),
            "valid_until": VALID_UNTIL.isoformat(),
            "evidence_refs": [],
            "policy_decision": "allow",
        },
        revision=SOURCE_REVISION,
        assertion="runtime-acceptance",
        outcome="accepted",
        observed_at=NOW,
    ),
    "generic runtime record was relabeled as runtime-acceptance evidence",
)

wrong_window = manifest()
wrong_window["valid_until"] = (VALID_UNTIL + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
expect_value_error(lambda: validate_runtime_acceptance_manifest(wrong_window, now=NOW), "non-canonical validity window was accepted")

expired = manifest()
expired["collected_at"] = (NOW - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
expired["valid_until"] = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
for check in expired["checks"].values():
    check["observed_at"] = (NOW - timedelta(hours=2, seconds=10)).isoformat().replace("+00:00", "Z")
expect_value_error(lambda: validate_runtime_acceptance_manifest(expired, now=NOW), "expired runtime acceptance emitted as current")

future = manifest()
future["collected_at"] = (NOW + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
future["valid_until"] = (NOW + timedelta(minutes=61)).isoformat().replace("+00:00", "Z")
expect_value_error(lambda: validate_runtime_acceptance_manifest(future, now=NOW), "future runtime acceptance evidence was accepted")

placeholder = manifest()
placeholder["deployed_revision"] = "0" * 40
expect_value_error(lambda: validate_runtime_acceptance_manifest(placeholder, now=NOW), "placeholder deployment revision was accepted")

incomplete_positive = manifest()
incomplete_positive["checks"]["restore_verification_exercise"] = {
    "status": "pending",
    "observed_at": None,
    "source": None,
    "summary": "Restore verification still pending.",
}
expect_value_error(lambda: validate_runtime_acceptance_manifest(incomplete_positive, now=NOW), "accepted status survived an incomplete required check")

degraded = copy.deepcopy(incomplete_positive)
degraded["acceptance_status"] = "degraded"
validate_runtime_acceptance_manifest(degraded, now=NOW)
degraded_envelope = create_runtime_acceptance_mesh_evidence(degraded, revision=SOURCE_REVISION, now=NOW)
if degraded_envelope.get("outcome") != "degraded":
    fail("degraded producer state was upgraded during Mesh emission")

claim_upgrade = manifest()
claim_upgrade["storage_health_is_protection_claim"] = True
expect_value_error(lambda: validate_runtime_acceptance_manifest(claim_upgrade, now=NOW), "storage health became a protection claim")

authority_transfer = manifest()
authority_transfer["everkeep_recovery_authority_preserved"] = False
expect_value_error(lambda: validate_runtime_acceptance_manifest(authority_transfer, now=NOW), "Everkeep recovery authority was not preserved")

print("Wardveil dedicated runtime-acceptance Mesh producer binding regressions: OK")
