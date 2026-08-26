#!/usr/bin/env python3
from datetime import datetime, timezone

from reference.wardveil_detect_scan import (
    DetectionInput,
    EvidenceSignal,
    ScanInput,
    correlate_findings,
    evaluate_detection,
    evaluate_scan,
)

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def test_anomaly_is_not_confirmed_malicious():
    finding = evaluate_detection(
        DetectionInput(
            resource_type="session",
            resource_id="session-1",
            producer_id="wardveil-detect-reference",
            signals=(EvidenceSignal("login_anomaly", anomaly=True, confidence=0.95, evidence_ref="evidence:anomaly-1"),),
        ),
        now=NOW,
    )
    assert_equal(finding.disposition, "suspicious", "anomaly must remain suspicious")
    if "anomaly_requires_corroboration" not in finding.reason_codes:
        raise AssertionError("anomaly finding must explain corroboration requirement")


def test_confirmed_indicator_can_be_confirmed_malicious():
    finding = evaluate_detection(
        DetectionInput(
            resource_type="file",
            resource_id="file-1",
            producer_id="wardveil-detect-reference",
            signals=(EvidenceSignal("confirmed_malware", confirmed_indicator=True, malicious_indicator=True, confidence=0.99, evidence_ref="evidence:malware-1"),),
        ),
        now=NOW,
    )
    assert_equal(finding.disposition, "confirmed_malicious", "confirmed evidence should confirm malicious disposition")


def test_unverified_detection_fails_unknown():
    finding = evaluate_detection(
        DetectionInput(
            resource_type="service",
            resource_id="service-1",
            producer_id="wardveil-detect-reference",
            signals=(EvidenceSignal("unverified", authoritative=False, malicious_indicator=True, confidence=1.0),),
        ),
        now=NOW,
    )
    assert_equal(finding.disposition, "unknown", "unverified evidence must fail closed")


def test_unsupported_scan_is_not_clean():
    finding = evaluate_scan(
        ScanInput(
            resource_type="archive",
            resource_id="archive-1",
            producer_id="wardveil-scan-reference",
            scanner_supported=False,
            scan_completed=False,
        ),
        now=NOW,
    )
    assert_equal(finding.result, "unsupported", "unsupported scan must stay unsupported")


def test_incomplete_scan_is_unknown():
    finding = evaluate_scan(
        ScanInput(
            resource_type="file",
            resource_id="file-2",
            producer_id="wardveil-scan-reference",
            scanner_supported=True,
            scan_completed=False,
        ),
        now=NOW,
    )
    assert_equal(finding.result, "unknown", "incomplete scan must remain unknown")


def test_clean_requires_completed_supported_scan():
    finding = evaluate_scan(
        ScanInput(
            resource_type="file",
            resource_id="file-3",
            producer_id="wardveil-scan-reference",
            scanner_supported=True,
            scan_completed=True,
        ),
        now=NOW,
    )
    assert_equal(finding.result, "clean", "completed supported scan without findings may be clean")


def test_correlation_preserves_strongest_supported_disposition():
    anomaly = evaluate_detection(
        DetectionInput(
            resource_type="account",
            resource_id="account-1",
            producer_id="wardveil-detect-reference",
            signals=(EvidenceSignal("behavior", anomaly=True, confidence=0.8, evidence_ref="evidence:a"),),
        ), now=NOW,
    )
    likely = evaluate_detection(
        DetectionInput(
            resource_type="account",
            resource_id="account-1",
            producer_id="wardveil-detect-reference",
            signals=(EvidenceSignal("indicator", malicious_indicator=True, confidence=0.9, evidence_ref="evidence:b"),),
        ), now=NOW,
    )
    correlated = correlate_findings((anomaly, likely))
    assert_equal(correlated.disposition, "likely_malicious", "correlation must not over-promote beyond evidence")
    if set(correlated.evidence_refs) != {"evidence:a", "evidence:b"}:
        raise AssertionError("correlation must preserve evidence references")


def test_runtime_records():
    detect_input = DetectionInput(
        resource_type="url",
        resource_id="url-1",
        producer_id="wardveil-detect-reference",
        signals=(EvidenceSignal("reputation", malicious_indicator=True, confidence=0.85, evidence_ref="evidence:url"),),
    )
    detect = evaluate_detection(detect_input, now=NOW)
    record = detect.as_runtime_record(detect_input, "corr-1")
    assert_equal(record["record_type"], "detection_finding", "detection runtime type")
    assert_equal(record["detection_disposition"], "likely_malicious", "detection runtime disposition")

    scan_input = ScanInput(
        resource_type="attachment",
        resource_id="attachment-1",
        producer_id="wardveil-scan-reference",
        scanner_supported=True,
        scan_completed=True,
        suspicious_content=True,
        evidence_refs=("evidence:attachment",),
    )
    scan = evaluate_scan(scan_input, now=NOW)
    scan_record = scan.as_runtime_record(scan_input, "corr-2")
    assert_equal(scan_record["record_type"], "scan_finding", "scan runtime type")
    assert_equal(scan_record["scan_result"], "suspicious", "scan runtime result")


def main():
    tests = [name for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name in sorted(tests):
        globals()[name]()
    print(f"Wardveil Detect + Scan reference tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
