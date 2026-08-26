#!/usr/bin/env python3
"""Self-tests for the Wardveil Trust + Policy reference engine."""

from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_decision import AccessRequest, TrustSignal, decide, evaluate_policy, TrustDecision

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def request(*signals, sensitivity="normal", privilege="standard", operation="read"):
    return AccessRequest(
        principal_class="user",
        resource_type="document",
        resource_id="doc-123",
        operation=operation,
        producer_id="goreecloud-test",
        signals=tuple(signals),
        resource_sensitivity=sensitivity,
        requested_privilege=privilege,
    )


def main() -> None:
    trust, policy = decide(request(), now=NOW)
    check(trust.state == "restricted", "missing evidence must fail closed to restricted")
    check(policy.decision == "restrict", "restricted trust must restrict policy")

    unverified = TrustSignal("authentication_strength", "strong", authoritative=False, evidence_ref="ev-1")
    trust, policy = decide(request(unverified), now=NOW)
    check(trust.state == "restricted", "unverified evidence must not grant trust")
    check(policy.decision == "restrict", "unverified evidence must restrict access")

    safe = TrustSignal("authentication_strength", "passkey", evidence_ref="ev-auth")
    trust, policy = decide(request(safe), now=NOW)
    check(trust.state == "trusted", "zero-risk authoritative evidence should allow trusted reference state")
    check(policy.decision == "allow", "trusted ordinary read should allow")

    elevated = TrustSignal("unusual_authentication", True, risk_weight=45, evidence_ref="ev-anomaly")
    trust, policy = decide(request(elevated), now=NOW)
    check(trust.state == "elevated_risk", "moderate risk should produce elevated risk")
    check(policy.decision == "warn", "elevated risk ordinary operation should warn")

    compromised = TrustSignal("credential_compromised", True, evidence_ref="ev-compromise")
    trust, policy = decide(request(compromised), now=NOW)
    check(trust.state == "blocked", "confirmed credential compromise must block trust")
    check(policy.decision == "block", "blocked trust must block policy")

    trust, policy = decide(request(safe, privilege="privileged"), now=NOW)
    check(policy.decision == "allow", "trusted privileged request may proceed in reference policy")

    trust, policy = decide(request(elevated, privilege="privileged"), now=NOW)
    check(policy.decision == "step_up", "privileged elevated-risk request must require step-up")

    trust, policy = decide(request(safe, operation="rotate_secret"), now=NOW)
    check(policy.decision == "allow_and_log", "trusted sensitive operation must be auditable")

    expired = TrustDecision("trusted", ("test",), ("ev-old",), NOW - timedelta(minutes=10), NOW - timedelta(minutes=1))
    policy = evaluate_policy(request(safe), expired, now=NOW)
    check(policy.decision == "block", "expired trust evidence must fail closed")

    record = trust.as_runtime_record(request(elevated, privilege="privileged"), "corr-1")
    check(record["record_type"] == "trust_decision", "trust serialization must use runtime contract record type")
    check(record["producer"]["authoritative"] is True, "reference producer must declare authority for its own decision")

    print("Wardveil Trust + Policy reference self-tests passed.")


if __name__ == "__main__":
    main()
