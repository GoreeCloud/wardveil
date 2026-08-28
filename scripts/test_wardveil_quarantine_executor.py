#!/usr/bin/env python3
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_execution_state import InMemoryExecutionStateStore  # noqa: E402
from reference.wardveil_protect import ExecutorAuthority  # noqa: E402
from reference.wardveil_quarantine_executor import (  # noqa: E402
    InMemoryQuarantineTarget,
    QuarantineExecutor,
    TargetQuarantineResult,
)
from reference.wardveil_security_center import build_snapshot  # noqa: E402
from reference.wardveil_service_identity import (  # noqa: E402
    EXECUTOR_CAPABILITY,
    ISSUER_CAPABILITY,
    ReferenceSigningKeyring,
    ServiceIdentity,
    ServiceIdentityRegistry,
    create_identity_bound_execution_authorization,
)

NOW = datetime(2026, 8, 28, 11, 45, tzinfo=timezone.utc)
ISSUER = "wardveil-policy-runtime"
EXECUTOR = "wardveil-quarantine-executor-runtime"
KEY_ID = "wardveil-auth-current"
SECRET = b"reference-quarantine-executor-key"
RESOURCE_TYPE = "drive_file"


def identity(service_id: str, *capabilities: str) -> ServiceIdentity:
    return ServiceIdentity(
        service_id=service_id,
        status="active",
        capabilities=frozenset(capabilities),
        created_at=(NOW - timedelta(days=1)).isoformat(),
        not_before=(NOW - timedelta(minutes=5)).isoformat(),
        valid_until=(NOW + timedelta(days=30)).isoformat(),
    )


def policy(*, action: str = "quarantine", resource_id: str = "drive:space-1:file:file-1") -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": f"policy-{resource_id.rsplit(':', 1)[-1]}",
        "correlation_id": f"corr-{resource_id.rsplit(':', 1)[-1]}",
        "producer": {"id": ISSUER, "authoritative": True},
        "scope": {"resource_type": RESOURCE_TYPE, "resource_id": resource_id},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["scan:malicious:sha256:example"],
        "policy_decision": action,
    }


def setup(*, action: str = "quarantine", resource_id: str = "drive:space-1:file:file-1"):
    identities = ServiceIdentityRegistry([
        identity(ISSUER, ISSUER_CAPABILITY),
        identity(EXECUTOR, EXECUTOR_CAPABILITY),
    ])
    keyring = ReferenceSigningKeyring(identities)
    keyring.add_key(
        key_id=KEY_ID,
        issuer_id=ISSUER,
        key_material=SECRET,
        not_before=NOW - timedelta(minutes=5),
        not_after=NOW + timedelta(hours=1),
        now=NOW,
    )
    record = policy(action=action, resource_id=resource_id)
    auth = create_identity_bound_execution_authorization(
        record,
        identities=identities,
        keyring=keyring,
        executor_id=EXECUTOR,
        idempotency_key=f"idem-{resource_id.rsplit(':', 1)[-1]}",
        nonce=f"nonce-{resource_id.rsplit(':', 1)[-1]}",
        key_id=KEY_ID,
        now=NOW,
    )
    authority = ExecutorAuthority(EXECUTOR, frozenset({"quarantine"}), frozenset({RESOURCE_TYPE}))
    executor = QuarantineExecutor(identities=identities, keyring=keyring)
    target = InMemoryQuarantineTarget(frozenset({RESOURCE_TYPE}))
    return identities, keyring, record, auth, authority, executor, target


class UnknownTarget:
    def __init__(self) -> None:
        self.apply_calls = 0

    def apply_quarantine(self, *, scope, operation_id, correlation_id):
        self.apply_calls += 1
        return TargetQuarantineResult("unknown", operation_id, "", "target:timeout", "target_timeout")

    def read_quarantine(self, *, scope):
        return None


class ReadbackMismatchTarget(InMemoryQuarantineTarget):
    def read_quarantine(self, *, scope):
        state = super().read_quarantine(scope=scope)
        if state is None:
            return None
        return replace(state, operation_id="different-operation")


class FailingFinalizeStore(InMemoryExecutionStateStore):
    def finalize(self, authorization, protection_record, *, now=None):
        raise RuntimeError("simulated persistence failure")


def test_successful_quarantine_requires_target_readback():
    _, _, record, auth, authority, executor, target = setup()
    result = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    assert result.accepted and result.reason == "quarantine_execution_finalized"
    assert result.protection_record["execution_status"] == "succeeded"
    assert result.quarantine_record["review_state"] == "pending"
    assert result.quarantine_record["destructive_action"] is False
    assert result.audit_record["authorization_provenance"]["signing_key_id"] == KEY_ID
    assert "signature" not in result.audit_record["authorization_provenance"]


def test_security_center_surfaces_nonsecret_execution_provenance():
    _, _, record, auth, authority, executor, target = setup(resource_id="drive:space-1:file:file-2")
    result = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    snapshot = build_snapshot(
        [result.protection_record, result.quarantine_record, result.audit_record],
        now=NOW,
    )
    assert snapshot.quarantined_items == 1
    assert snapshot.execution_provenance == ({
        "authorization_id": auth.authorization_id,
        "executor_id": EXECUTOR,
        "issuer_id": ISSUER,
        "signature_algorithm": auth.signature_algorithm,
        "signing_key_id": KEY_ID,
    },)


def test_exact_retry_does_not_reinvoke_target():
    _, _, record, auth, authority, executor, target = setup(resource_id="drive:space-1:file:file-3")
    first = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    second = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    assert first.accepted and second.accepted and second.idempotent_replay
    assert target.apply_calls == 1
    assert second.receipt.receipt_id == first.receipt.receipt_id


def test_unknown_target_outcome_requires_reconciliation_and_blocks_retry():
    _, _, record, auth, authority, executor, _ = setup(resource_id="drive:space-1:file:file-4")
    target = UnknownTarget()
    first = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    second = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    assert not first.accepted and first.reconciliation_required
    assert not second.accepted and second.reason == "execution_reconciliation_required"
    assert target.apply_calls == 1


def test_readback_mismatch_requires_reconciliation():
    identities, keyring, record, auth, authority, _, _ = setup(resource_id="drive:space-1:file:file-5")
    executor = QuarantineExecutor(identities=identities, keyring=keyring)
    target = ReadbackMismatchTarget(frozenset({RESOURCE_TYPE}))
    result = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    assert not result.accepted and result.reason == "target_quarantine_readback_unverified"
    assert result.reconciliation_required


def test_known_target_failure_is_finalized_as_failure():
    _, _, record, auth, authority, executor, _ = setup(resource_id="drive:space-1:file:file-6")
    unsupported = InMemoryQuarantineTarget(frozenset({"mail_attachment"}))
    result = executor.execute(record, auth, authority, target=unsupported, reason="confirmed malware", now=NOW)
    assert not result.accepted and result.reason == "target_quarantine_failed"
    assert result.protection_record["execution_status"] == "failed"
    assert result.receipt.outcome == "failed"
    assert result.audit_record["outcome"] == "failure"


def test_wrong_action_and_wrong_executor_fail_before_target():
    identities, keyring, record, auth, authority, executor, target = setup(resource_id="drive:space-1:file:file-7")
    wrong_record = dict(record)
    wrong_record["policy_decision"] = "block"
    assert executor.execute(wrong_record, auth, authority, target=target, reason="test", now=NOW).reason == "quarantine_action_required"
    wrong_authority = ExecutorAuthority("different-executor", frozenset({"quarantine"}), frozenset({RESOURCE_TYPE}))
    assert executor.execute(record, auth, wrong_authority, target=target, reason="test", now=NOW).reason == "executor_binding_mismatch"
    assert target.apply_calls == 0


def test_revoked_key_and_suspended_executor_fail_closed():
    identities, keyring, record, auth, authority, executor, target = setup(resource_id="drive:space-1:file:file-8")
    keyring.revoke(KEY_ID, now=NOW, reason="test-revocation")
    assert executor.execute(record, auth, authority, target=target, reason="test", now=NOW).reason == "signing_key_revoked"
    assert target.apply_calls == 0

    identities2, keyring2, record2, auth2, authority2, executor2, target2 = setup(resource_id="drive:space-1:file:file-9")
    identities2.set_status(EXECUTOR, "suspended")
    assert executor2.execute(record2, auth2, authority2, target=target2, reason="test", now=NOW).reason == "service_identity_suspended"
    assert target2.apply_calls == 0


def test_receipt_persistence_failure_after_side_effect_requires_reconciliation():
    identities, keyring, record, auth, authority, _, target = setup(resource_id="drive:space-1:file:file-10")
    executor = QuarantineExecutor(
        identities=identities,
        keyring=keyring,
        state_store=FailingFinalizeStore(),
    )
    result = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    assert not result.accepted
    assert result.reason == "execution_receipt_persistence_failed"
    assert result.reconciliation_required
    assert target.apply_calls == 1


def test_audit_provenance_is_hash_bound_and_secret_free():
    _, _, record, auth, authority, executor, target = setup(resource_id="drive:space-1:file:file-11")
    result = executor.execute(record, auth, authority, target=target, reason="confirmed malware", now=NOW)
    serialized = str(result.audit_record).lower()
    assert "reference-quarantine-executor-key" not in serialized
    assert "signing_key_id" in serialized
    assert "issuer_id" in serialized
    assert "executor_id" in serialized


def main():
    tests = [name for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name in sorted(tests):
        globals()[name]()
    print(f"Wardveil quarantine executor tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
