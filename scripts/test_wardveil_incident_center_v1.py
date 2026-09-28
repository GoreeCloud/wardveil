#!/usr/bin/env python3
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_detection_engine_v1 import BehavioralSignal, assess_behavioral_signals
from reference.wardveil_incident_center_v1 import build_incident_review_case

NOW = datetime(2026, 9, 28, 22, 0, tzinfo=timezone.utc)


def signal(signal_id: str, category: str, *, resource_id: str = "app-1", severity: str = "high", confidence: float = 0.9, producer_id: str = "sensor-a") -> BehavioralSignal:
    return BehavioralSignal(
        signal_id=signal_id,
        category=category,
        resource_type="application",
        resource_id=resource_id,
        producer_id=producer_id,
        authority_domain="runtime-security",
        severity=severity,
        confidence=confidence,
        observed_at=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=4),
        evidence_refs=(f"evidence:{signal_id}",),
        authoritative=True,
    )


def correlated_candidate(resource_id: str = "app-1"):
    return assess_behavioral_signals(
        (
            signal("s1-"+resource_id, "credential_harvesting", resource_id=resource_id, producer_id="identity-monitor"),
            signal("s2-"+resource_id, "anomalous_network_activity", resource_id=resource_id, producer_id="network-monitor"),
        ),
        now=NOW,
    )


class IncidentCenterV1Tests(unittest.TestCase):
    def test_empty_input_remains_unknown_and_non_authorizing(self) -> None:
        case = build_incident_review_case((), now=NOW)
        self.assertEqual(case.status, "unknown")
        self.assertEqual(case.assessment_count, 0)
        self.assertFalse(case.incident_established)
        self.assertFalse(case.execution_authority)
        self.assertFalse(case.containment_authority)
        self.assertFalse(case.production_accepted)

    def test_detection_candidate_becomes_review_required_not_incident(self) -> None:
        assessment = correlated_candidate()
        self.assertTrue(assessment.incident_candidate)
        case = build_incident_review_case((assessment,), now=NOW)
        self.assertEqual(case.status, "review_required")
        self.assertEqual(case.review_priority, "high")
        self.assertEqual(case.assessment_count, 1)
        self.assertEqual(case.correlated_assessment_count, 1)
        self.assertFalse(case.incident_established)
        self.assertFalse(case.execution_authority)
        self.assertIn("detection_candidate_requires_incident_review", case.reason_codes)

    def test_single_uncorroborated_candidate_is_triage_only(self) -> None:
        assessment = assess_behavioral_signals(
            (signal("single", "suspicious_process_spawn", severity="medium", confidence=0.75),),
            now=NOW,
        )
        self.assertTrue(assessment.incident_candidate)
        self.assertFalse(assessment.correlated)
        case = build_incident_review_case((assessment,), now=NOW)
        self.assertEqual(case.review_priority, "attention")
        self.assertEqual(case.correlated_assessment_count, 0)
        self.assertIn("uncorroborated_detection_candidate_requires_review", case.reason_codes)

    def test_non_candidate_does_not_create_review_case(self) -> None:
        assessment = assess_behavioral_signals(
            (signal("low", "abnormal_background_activity", severity="low", confidence=0.2),),
            now=NOW,
        )
        self.assertFalse(assessment.incident_candidate)
        case = build_incident_review_case((assessment,), now=NOW)
        self.assertEqual(case.status, "unknown")
        self.assertIn("non_candidate_assessments_excluded", case.reason_codes)

    def test_stale_or_future_candidate_is_excluded(self) -> None:
        candidate = correlated_candidate()
        stale = replace(candidate, observed_at=NOW - timedelta(minutes=30), valid_until=NOW + timedelta(minutes=1))
        case = build_incident_review_case((stale,), now=NOW)
        self.assertEqual(case.status, "unknown")
        self.assertIn("stale_or_future_detection_assessments_excluded", case.reason_codes)

        future = replace(candidate, observed_at=NOW + timedelta(seconds=1), valid_until=NOW + timedelta(minutes=5))
        future_case = build_incident_review_case((future,), now=NOW)
        self.assertEqual(future_case.status, "unknown")

    def test_mixed_resources_require_partitioning(self) -> None:
        with self.assertRaisesRegex(ValueError, "mixed_resource"):
            build_incident_review_case((correlated_candidate("app-1"), correlated_candidate("app-2")), now=NOW)

    def test_execution_authority_contamination_is_rejected(self) -> None:
        contaminated = replace(correlated_candidate(), execution_authority=True)
        with self.assertRaisesRegex(ValueError, "must_not_claim_execution_authority"):
            build_incident_review_case((contaminated,), now=NOW)

    def test_case_identity_and_evidence_are_deterministic(self) -> None:
        candidate = correlated_candidate()
        first = build_incident_review_case((candidate,), now=NOW)
        second = build_incident_review_case((candidate,), now=NOW)
        self.assertEqual(first.case_id, second.case_id)
        self.assertEqual(first.evidence_refs, second.evidence_refs)
        record = first.as_record()
        self.assertEqual(record["record_type"], "incident_review_case")
        self.assertFalse(record["incident_established"])
        self.assertFalse(record["execution_authority"])
        self.assertFalse(record["containment_authority"])
        self.assertFalse(record["production_accepted"])


if __name__ == "__main__":
    unittest.main()
