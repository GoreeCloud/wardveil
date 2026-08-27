#!/usr/bin/env python3
"""Self-tests for Wardveil Foundation 0.9 service identity and key lifecycle."""
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_runtime_authorization import AuthorizationReplayLedger  # noqa: E402
from reference.wardveil_service_identity import (  # noqa: E402
    EXECUTOR_CAPABILITY,
    ISSUER_CAPABILITY,
    ReferenceSigningKeyring,
    ServiceIdentity,
    ServiceIdentityRegistry,
    create_identity_bound_execution_authorization,
    verify_identity_bound_execution_authorization,
)

NOW = datetime(2026, 8, 27, 11, 45, tzinfo=timezone.utc)
ISSUER = "wardveil-policy-production-candidate"
EXECUTOR = "wardveil-protect-executor-production-candidate"


def identity(service_id: str, *capabilities: str) -> ServiceIdentity:
    return ServiceIdentity(
        service_id=service_id,
        status="active",
        capabilities=frozenset(capabilities),
        created_at=(NOW - timedelta(days=1)).isoformat(),
        not_before=(NOW - timedelta(minutes=1)).isoformat(),
        valid_until=(NOW + timedelta(days=30)).isoformat(),
    )


def policy() -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": "policy-service-identity-test",
        "correlation_id": "corr-service-identity-test",
        "producer": {"id": ISSUER, "authoritative": True},
        "scope": {"resource_type": "file", "resource_id": "file-service-identity-1"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:service-identity-test"],
        "policy_decision": "block",
    }


def expect_raises(reason: str, fn) -> None:
    try:
        fn()
    except ValueError as exc:
        assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError(f"expected ValueError: {reason}")


def main() -> None:
    identities = ServiceIdentityRegistry([
        identity(ISSUER, ISSUER_CAPABILITY),
        identity(EXECUTOR, EXECUTOR_CAPABILITY),
    ])
    keyring = ReferenceSigningKeyring(identities)
    keyring.add_key(
        key_id="wardveil-auth-2026-08-a",
        issuer_id=ISSUER,
        key_material=b"wardveil-reference-key-a",
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1),
        now=NOW,
    )

    auth = create_identity_bound_execution_authorization(
        policy(),
        identities=identities,
        keyring=keyring,
        executor_id=EXECUTOR,
        idempotency_key="idem-service-identity-1",
        nonce="nonce-service-identity-1",
        now=NOW,
    )
    assert auth.signing_key_id == "wardveil-auth-2026-08-a"
    verified = verify_identity_bound_execution_authorization(
        auth,
        policy(),
        identities=identities,
        keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(),
        now=NOW,
    )
    assert verified.accepted and verified.reason == "validated_execution_authorization"

    serialized_envelope = str(auth.as_dict()).lower()
    serialized_metadata = str(keyring.all_metadata()).lower()
    for forbidden in (
        "wardveil-reference-key-a",
        "private_key",
        "password",
        "access_token",
        "refresh_token",
        "session_token",
        "authorization_header",
        "cookie",
    ):
        assert forbidden not in serialized_envelope
        assert forbidden not in serialized_metadata

    unknown_key = replace(auth, signing_key_id="missing-key")
    assert verify_identity_bound_execution_authorization(
        unknown_key, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW,
    ).reason == "unknown_signing_key"

    identities.set_status(ISSUER, "suspended")
    assert verify_identity_bound_execution_authorization(
        auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW,
    ).reason == "service_identity_suspended"
    identities.set_status(ISSUER, "active")

    identities.set_status(EXECUTOR, "suspended")
    assert verify_identity_bound_execution_authorization(
        auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW,
    ).reason == "service_identity_suspended"
    identities.set_status(EXECUTOR, "active")

    rotation_time = NOW + timedelta(seconds=30)
    retired, active = keyring.rotate(
        issuer_id=ISSUER,
        current_key_id="wardveil-auth-2026-08-a",
        new_key_id="wardveil-auth-2026-08-b",
        new_key_material=b"wardveil-reference-key-b",
        now=rotation_time,
        new_not_after=NOW + timedelta(hours=2),
        verification_overlap=timedelta(minutes=2),
    )
    assert retired.status == "retired" and active.status == "active"
    assert keyring.active_signing_key_id(ISSUER, now=rotation_time) == "wardveil-auth-2026-08-b"
    expect_raises(
        "signing_key_retired_for_signing",
        lambda: create_identity_bound_execution_authorization(
            policy(), identities=identities, keyring=keyring, executor_id=EXECUTOR,
            idempotency_key="idem-old-key", nonce="nonce-old-key",
            key_id="wardveil-auth-2026-08-a", now=rotation_time,
        ),
    )

    old_still_verifies = verify_identity_bound_execution_authorization(
        auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW + timedelta(minutes=1),
    )
    assert old_still_verifies.accepted

    new_auth = create_identity_bound_execution_authorization(
        policy(), identities=identities, keyring=keyring, executor_id=EXECUTOR,
        idempotency_key="idem-new-key", nonce="nonce-new-key", now=rotation_time,
    )
    assert new_auth.signing_key_id == "wardveil-auth-2026-08-b"
    assert verify_identity_bound_execution_authorization(
        new_auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=rotation_time,
    ).accepted

    assert verify_identity_bound_execution_authorization(
        auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW + timedelta(minutes=3),
    ).reason == "expired_authorization"

    keyring.revoke(
        "wardveil-auth-2026-08-a",
        now=NOW + timedelta(minutes=1),
        reason="rotation-compromise-test",
    )
    assert verify_identity_bound_execution_authorization(
        auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW + timedelta(minutes=1),
    ).reason == "signing_key_revoked"
    assert keyring.metadata("wardveil-auth-2026-08-a")["revocation_reason"] == "rotation-compromise-test"

    expect_raises(
        "invalid_or_duplicate_signing_key_id",
        lambda: keyring.add_key(
            key_id="wardveil-auth-2026-08-b", issuer_id=ISSUER,
            key_material=b"duplicate", not_before=NOW, not_after=NOW + timedelta(hours=1), now=NOW,
        ),
    )

    keyring.add_key(
        key_id="wardveil-auth-future",
        issuer_id=ISSUER,
        key_material=b"future",
        not_before=NOW + timedelta(hours=1),
        not_after=NOW + timedelta(hours=2),
        now=NOW,
    )
    assert keyring.resolve_for_signing(ISSUER, "wardveil-auth-future", now=NOW).reason == "signing_key_not_yet_valid"

    keyring.add_key(
        key_id="wardveil-auth-expired",
        issuer_id=ISSUER,
        key_material=b"expired",
        not_before=NOW - timedelta(hours=2),
        not_after=NOW - timedelta(hours=1),
        now=NOW,
    )
    assert keyring.resolve_for_verification(
        ISSUER, "wardveil-auth-expired", "HMAC-SHA256-reference-only", now=NOW,
    ).reason == "signing_key_expired"

    identities.register(identity("wardveil-observer-only", "observe_security_state"))
    expect_raises(
        "service_identity_capability_denied",
        lambda: create_identity_bound_execution_authorization(
            policy(), identities=identities, keyring=keyring,
            executor_id="wardveil-observer-only", idempotency_key="x", nonce="x", now=NOW,
        ),
    )
    expect_raises(
        "unknown_service_identity",
        lambda: create_identity_bound_execution_authorization(
            policy(), identities=identities, keyring=keyring,
            executor_id="missing-executor", idempotency_key="x", nonce="x", now=NOW,
        ),
    )

    identities.register(identity("wardveil-other-issuer", ISSUER_CAPABILITY))
    keyring.add_key(
        key_id="other-issuer-key", issuer_id="wardveil-other-issuer",
        key_material=b"other", not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(hours=1), now=NOW,
    )
    wrong_issuer_key = replace(auth, signing_key_id="other-issuer-key")
    assert verify_identity_bound_execution_authorization(
        wrong_issuer_key, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=NOW,
    ).reason == "signing_key_issuer_mismatch"

    wrong_algorithm = replace(new_auth, signature_algorithm="unexpected")
    assert verify_identity_bound_execution_authorization(
        wrong_algorithm, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=rotation_time,
    ).reason == "unsupported_signature_algorithm"

    identities.set_status(EXECUTOR, "revoked")
    assert verify_identity_bound_execution_authorization(
        new_auth, policy(), identities=identities, keyring=keyring,
        replay_ledger=AuthorizationReplayLedger(), now=rotation_time,
    ).reason == "service_identity_revoked"

    print("Wardveil service identity and key lifecycle tests passed (18 cases).")


if __name__ == "__main__":
    main()
