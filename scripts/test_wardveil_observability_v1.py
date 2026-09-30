#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_observability_v1 import (
    OBSERVABILITY_CONTRACT_REVISION,
    OBSERVABILITY_OPERATIONAL_SIGNAL_CONTRACT_ID,
    OBSERVABILITY_STATES,
    build_operational_signal,
)


class ObservabilityV1Tests(unittest.TestCase):
    def test_authoritative_contract_pin_and_vocabulary(self):
        self.assertEqual(OBSERVABILITY_CONTRACT_REVISION, "a7f6a65f442d3e517baddbe7b6ce7c250d142c8c")
        self.assertEqual(OBSERVABILITY_OPERATIONAL_SIGNAL_CONTRACT_ID, "https://goreecloud.com/contracts/observability/operational-signal/v1")
        self.assertEqual(len(OBSERVABILITY_STATES), 9)

    def test_builds_minimized_unknown_signal(self):
        value = build_operational_signal(
            signal_id="wardveil-readiness-001",
            source="wardveil-security-engine",
            signal_type="readiness",
            state="unknown",
            observed_at="2026-09-29T18:00:00-05:00",
            collected_at="2026-09-29T18:00:01-05:00",
            ttl_seconds=60,
            correlation_id="opaque-correlation-001",
            attributes={"scan_runtime": "observed", "policy_runtime": "not-observed"},
            collection_gaps=["live-observability-publication-not-configured"],
        )
        self.assertEqual(value["component_id"], "goreecloud-wardveil-security")
        self.assertEqual(value["state"], "unknown")

    def test_rejects_sensitive_attributes_recursively(self):
        base = dict(
            signal_id="s", source="wardveil", signal_type="readiness", state="unknown",
            observed_at="2026-09-29T18:00:00Z", collected_at="2026-09-29T18:00:01Z", ttl_seconds=60,
        )
        with self.assertRaisesRegex(ValueError, "not_allowed"):
            build_operational_signal(**base, attributes={"access_token": "secret"})
        with self.assertRaisesRegex(ValueError, "not_allowed"):
            build_operational_signal(**base, attributes={"nested": {"request_body": "private"}})
        with self.assertRaisesRegex(ValueError, "not_allowed"):
            build_operational_signal(**base, attributes={"device_id": "direct-device-id"})

    def test_rejects_ambiguous_time_and_contradictory_health(self):
        base = dict(
            signal_id="s", source="wardveil", signal_type="readiness", state="unknown",
            observed_at="2026-09-29T18:00:00Z", collected_at="2026-09-29T18:00:01Z", ttl_seconds=60,
        )
        with self.assertRaisesRegex(ValueError, "include_timezone"):
            build_operational_signal(**{**base, "observed_at": "2026-09-29T18:00:00"})
        with self.assertRaisesRegex(ValueError, "before_observed"):
            build_operational_signal(**{**base, "collected_at": "2026-09-29T17:59:59Z"})
        with self.assertRaisesRegex(ValueError, "healthy_signal"):
            build_operational_signal(**{**base, "state": "healthy"}, collection_gaps=["coverage-incomplete"])


if __name__ == "__main__":
    unittest.main()
