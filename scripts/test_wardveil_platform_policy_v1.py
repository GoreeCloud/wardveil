#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_platform_policy_v1 import (
    POLICY_CONTRACT_REVISION,
    POLICY_DECISION_CONTRACT_ID,
    POLICY_EVALUATION_REQUEST_CONTRACT_ID,
    POLICY_DECISIONS,
    build_policy_evaluation_request,
    validate_policy_decision_evidence,
)


def request():
    return build_policy_evaluation_request(
        policy_id="wardveil.shared-security-policy",
        policy_version="1",
        authority="goreecloud-policy",
        subject="service:wardveil",
        resource="security-capability:opaque-001",
        action="evaluate",
        context={"security_domain": "runtime-security", "high_impact": True},
    )


def decision(**overrides):
    value = {
        "decision": "conditional",
        "policy_id": "wardveil.shared-security-policy",
        "policy_version": "1",
        "authority": "goreecloud-policy",
        "subject": "service:wardveil",
        "resource": "security-capability:opaque-001",
        "action": "evaluate",
        "reason": "Shared policy contributes a non-authorizing constraint.",
        "matched_rule_ids": ["shared-security-001"],
        "obligations": ["wardveil-runtime-authorization-still-required"],
        "evaluated_at": "2026-09-29T18:00:00-05:00",
        "fresh": True,
    }
    value.update(overrides)
    return value


class PlatformPolicyV1Tests(unittest.TestCase):
    def test_authoritative_contract_pins(self):
        self.assertEqual(POLICY_CONTRACT_REVISION, "46071886da37a6566b69cc923005eef64cce2bcc")
        self.assertEqual(POLICY_EVALUATION_REQUEST_CONTRACT_ID, "https://goreecloud.com/contracts/policy/evaluation-request/v1")
        self.assertEqual(POLICY_DECISION_CONTRACT_ID, "https://goreecloud.com/contracts/policy/decision/v1")
        self.assertEqual(POLICY_DECISIONS, ("allow", "deny", "conditional", "defer", "indeterminate", "error"))

    def test_exact_request_and_privacy_minimization(self):
        value = request()
        self.assertEqual(set(value), {"policy_id", "policy_version", "authority", "subject", "resource", "action", "context"})
        with self.assertRaisesRegex(ValueError, "not_allowed"):
            build_policy_evaluation_request(
                policy_id="p", policy_version="1", authority="goreecloud-policy",
                subject="s", resource="r", action="a", context={"access_token": "secret"},
            )
        with self.assertRaisesRegex(ValueError, "not_allowed"):
            build_policy_evaluation_request(
                policy_id="p", policy_version="1", authority="goreecloud-policy",
                subject="s", resource="r", action="a", context={"nested": {"request_body": "private"}},
            )

    def test_policy_allow_never_becomes_wardveil_execution_authority(self):
        result = validate_policy_decision_evidence(
            decision(decision="allow", obligations=[]),
            expected_request=request(),
        )
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["decision_evidence_usable"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["protection_authority"])
        self.assertFalse(result["obligations_executed"])
        self.assertFalse(result["production_accepted"])

    def test_stale_decision_is_not_usable(self):
        result = validate_policy_decision_evidence(decision(fresh=False), expected_request=request())
        self.assertFalse(result["decision_evidence_usable"])
        self.assertFalse(result["execution_authority"])

    def test_fails_closed_on_shape_provenance_and_time(self):
        with self.assertRaisesRegex(ValueError, "shape_invalid"):
            validate_policy_decision_evidence({**decision(), "extra": True})
        with self.assertRaisesRegex(ValueError, "provenance_mismatch_subject"):
            validate_policy_decision_evidence(decision(subject="other"), expected_request=request())
        with self.assertRaisesRegex(ValueError, "include_timezone"):
            validate_policy_decision_evidence(decision(evaluated_at="2026-09-29T18:00:00"))


if __name__ == "__main__":
    unittest.main()
