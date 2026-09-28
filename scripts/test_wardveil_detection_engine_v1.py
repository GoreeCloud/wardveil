#!/usr/bin/env python3
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from reference.wardveil_detection_engine_v1 import (
    BehavioralSignal,
    assess_behavioral_signals,
)


NOW = datetime(2026, 9, 28, 21, 30, tzinfo=timezone.utc)


def signal(
    signal_id: str,
    category: str,
    *,
    severity: str = "medium",
    confidence: float = 0.7,
    producer_id: str = "sensor-a",
    resource_type: str = "application",
    resource_id: str = "app-1",
    authoritative: bool = True,
    observed_delta: timedelta = timedelta(minutes=-1),
    valid_delta: timedelta = timedelta(minutes=4),
    evidence_ref: str | None = None,
) -> BehavioralSignal:
    return BehavioralSignal(
        signal_id=signal_id,
        category=category,
        resource_type=resource_type,
        resource_id=resource_id,
        producer_id=producer_id,
        authority_domain="runtime-security",
        severity=severity,
        confidence=confidence,
        observed_at=NOW + observed_delta,
        valid_until=NOW + valid_delta,
        evidence_refs=(evidence_ref or f"evidence:{signal_id}",),
        authoritative=authoritative,
    )


class DetectionEngineV1Tests(unittest.TestCase):
    def test_missing_evidence_fails_to_unknown(self) -> None:
        assessment = assess_behavioral_signals((), now=NOW)
        self.assertEqual(assessment.disposition, "unknown")
        self.assertFalse(assessment.incident_candidate)
        self.assertFalse(assessment.execution_authority)
        self.assertEqual(assessment.reason_codes, ("missing_behavioral_evidence",))

    def test_untrusted_only_signal_fails_to_unknown(self) -> None:
        assessment = assess_behavioral_signals(
            (signal("s1", "credential_harvesting", authoritative=False),),
            now=NOW,
        )
        self.assertEqual(assessment.disposition, "unknown")
        self.assertIn("untrusted_signals_excluded", assessment.reason_codes)

    def test_stale_signal_is_excluded(self) -> None:
        assessment = assess_behavioral_signals(
            (
                signal(
                    "s1",
                    "privilege_escalation",
                    observed_delta=timedelta(minutes=-20),
                    valid_delta=timedelta(minutes=-10),
                ),
            ),
            now=NOW,
        )
        self.assertEqual(assessment.disposition, "unknown")
        self.assertIn("stale_or_future_signals_excluded", assessment.reason_codes)

    def test_future_signal_is_excluded(self) -> None:
        assessment = assess_behavioral_signals(
            (
                signal(
                    "s1",
                    "privilege_escalation",
                    observed_delta=timedelta(minutes=1),
                    valid_delta=timedelta(minutes=5),
                ),
            ),
            now=NOW,
        )
        self.assertEqual(assessment.disposition, "unknown")
        self.assertIn("stale_or_future_signals_excluded", assessment.reason_codes)

    def test_single_category_requires_corroboration(self) -> None:
        assessment = assess_behavioral_signals(
            (signal("s1", "suspicious_process_spawn", confidence=0.75),),
            now=NOW,
        )
        self.assertEqual(assessment.disposition, "suspicious")
        self.assertFalse(assessment.correlated)
        self.assertIn("single_behavior_category_requires_corroboration", assessment.reason_codes)
        self.assertTrue(assessment.incident_candidate)

    def test_correlated_high_confidence_signals_escalate(self) -> None:
        assessment = assess_behavioral_signals(
            (
                signal(
                    "s1",
                    "credential_harvesting",
                    severity="high",
                    confidence=0.91,
                    producer_id="identity-monitor",
                ),
                signal(
                    "s2",
                    "privilege_escalation",
                    severity="high",
                    confidence=0.86,
                    producer_id="host-monitor",
                ),
            ),
            now=NOW,
        )
        self.assertEqual(assessment.disposition, "likely_malicious")
        self.assertEqual(assessment.severity, "high")
        self.assertTrue(assessment.correlated)
        self.assertTrue(assessment.incident_candidate)
        self.assertIn("independent_producers_present", assessment.reason_codes)
        self.assertFalse(assessment.execution_authority)

    def test_untrusted_signal_does_not_raise_severity(self) -> None:
        assessment = assess_behavioral_signals(
            (
                signal("s1", "abnormal_background_activity", severity="low", confidence=0.4),
                signal(
                    "s2",
                    "mass_file_encryption",
                    severity="critical",
                    confidence=1.0,
                    authoritative=False,
                ),
            ),
            now=NOW,
        )
        self.assertEqual(assessment.severity, "low")
        self.assertEqual(assessment.disposition, "informational")
        self.assertIn("untrusted_signals_excluded", assessment.reason_codes)

    def test_identical_duplicate_signal_is_deduplicated(self) -> None:
        item = signal("s1", "rapid_permission_change", severity="medium", confidence=0.6)
        assessment = assess_behavioral_signals((item, item), now=NOW)
        self.assertEqual(assessment.signal_categories, ("rapid_permission_change",))
        self.assertEqual(assessment.evidence_refs, ("evidence:s1",))

    def test_conflicting_signal_id_reuse_fails_closed(self) -> None:
        item = signal("s1", "rapid_permission_change")
        conflicting = replace(item, category="persistence_attempt")
        with self.assertRaisesRegex(ValueError, "conflicting_signal_id_reuse"):
            assess_behavioral_signals((item, conflicting), now=NOW)

    def test_mixed_resources_require_partitioning(self) -> None:
        with self.assertRaisesRegex(ValueError, "mixed_resource_signals_require_partitioning"):
            assess_behavioral_signals(
                (
                    signal("s1", "privilege_escalation", resource_id="app-1"),
                    signal("s2", "credential_harvesting", resource_id="app-2"),
                ),
                now=NOW,
            )

    def test_naive_timestamp_rejected(self) -> None:
        item = signal("s1", "privilege_escalation")
        naive = replace(item, observed_at=item.observed_at.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "timestamp_must_be_timezone_aware"):
            assess_behavioral_signals((naive,), now=NOW)

    def test_record_is_non_authorizing(self) -> None:
        assessment = assess_behavioral_signals(
            (
                signal("s1", "credential_harvesting", severity="high", confidence=0.9),
                signal("s2", "persistence_attempt", severity="high", confidence=0.85),
            ),
            now=NOW,
        )
        record = assessment.as_record()
        self.assertEqual(record["contract_version"], "0.1.0")
        self.assertEqual(record["record_type"], "detection_assessment")
        self.assertIs(record["execution_authority"], False)
        self.assertEqual(record["resource"], {"type": "application", "id": "app-1"})


if __name__ == "__main__":
    unittest.main()
