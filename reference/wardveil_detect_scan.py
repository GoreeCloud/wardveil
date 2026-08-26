#!/usr/bin/env python3
"""Dependency-free Wardveil Detect + Scan reference engine.

This reference implementation models evidence-producing detection and inspection
results. It does not perform malware scanning, URL reputation lookup, sandboxing,
or production threat-intelligence queries by itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable
from uuid import uuid4

DETECTION_DISPOSITIONS = (
    "informational", "suspicious", "likely_malicious", "confirmed_malicious", "unknown"
)
SCAN_RESULTS = ("clean", "suspicious", "malicious", "unknown", "unsupported")
SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class EvidenceSignal:
    name: str
    authoritative: bool = True
    confidence: float = 0.0
    malicious_indicator: bool = False
    confirmed_indicator: bool = False
    anomaly: bool = False
    evidence_ref: str | None = None


@dataclass(frozen=True)
class DetectionInput:
    resource_type: str
    resource_id: str
    producer_id: str
    signals: tuple[EvidenceSignal, ...] = field(default_factory=tuple)
    principal_class: str | None = None
    operation: str | None = None


@dataclass(frozen=True)
class DetectionFinding:
    disposition: str
    severity: str
    confidence: float
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def as_runtime_record(self, request: DetectionInput, correlation_id: str) -> dict:
        scope = {"resource_type": request.resource_type, "resource_id": request.resource_id}
        if request.operation:
            scope["operation"] = request.operation
        if request.principal_class:
            scope["principal_class"] = request.principal_class
        return {
            "contract_version": "0.1.0",
            "record_type": "detection_finding",
            "record_id": f"detect-{uuid4()}",
            "correlation_id": correlation_id,
            "producer": {"id": request.producer_id or "wardveil-detect-reference", "authoritative": True},
            "scope": scope,
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "detection_disposition": self.disposition,
            "severity": self.severity,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ScanInput:
    resource_type: str
    resource_id: str
    producer_id: str
    scanner_supported: bool
    scan_completed: bool
    malware_match: bool = False
    suspicious_content: bool = False
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScanFinding:
    result: str
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def as_runtime_record(self, request: ScanInput, correlation_id: str) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "scan_finding",
            "record_id": f"scan-{uuid4()}",
            "correlation_id": correlation_id,
            "producer": {"id": request.producer_id or "wardveil-scan-reference", "authoritative": True},
            "scope": {"resource_type": request.resource_type, "resource_id": request.resource_id},
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "scan_result": self.result,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def evaluate_detection(request: DetectionInput, *, now: datetime | None = None) -> DetectionFinding:
    observed_at = now or _now()
    if not request.signals:
        return DetectionFinding(
            "unknown", "informational", 0.0, ("missing_detection_evidence",), (),
            observed_at, observed_at + timedelta(minutes=2),
        )

    if any(not signal.authoritative for signal in request.signals):
        return DetectionFinding(
            "unknown", "informational", 0.0, ("unverified_detection_evidence",), (),
            observed_at, observed_at + timedelta(minutes=2),
        )

    evidence = tuple(dict.fromkeys(s.evidence_ref for s in request.signals if s.evidence_ref))
    confidence = max((_clamp_confidence(s.confidence) for s in request.signals), default=0.0)
    has_confirmed = any(s.confirmed_indicator for s in request.signals)
    has_malicious = any(s.malicious_indicator for s in request.signals)
    has_anomaly = any(s.anomaly for s in request.signals)

    reasons: list[str] = []
    if has_confirmed:
        disposition = "confirmed_malicious"
        severity = "critical" if confidence >= 0.9 else "high"
        reasons.append("confirmed_malicious_indicator")
    elif has_malicious and confidence >= 0.8:
        disposition = "likely_malicious"
        severity = "high"
        reasons.append("high_confidence_malicious_indicator")
    elif has_malicious:
        disposition = "suspicious"
        severity = "medium"
        reasons.append("malicious_indicator_below_confirmation_threshold")
    elif has_anomaly:
        disposition = "suspicious"
        severity = "low" if confidence < 0.7 else "medium"
        reasons.append("anomaly_requires_corroboration")
    else:
        disposition = "informational"
        severity = "informational"
        reasons.append("no_material_threat_indicator")

    return DetectionFinding(
        disposition, severity, confidence, tuple(reasons), evidence,
        observed_at, observed_at + timedelta(minutes=5),
    )


def evaluate_scan(request: ScanInput, *, now: datetime | None = None) -> ScanFinding:
    observed_at = now or _now()
    if not request.scanner_supported:
        return ScanFinding(
            "unsupported", ("scanner_does_not_support_resource",), request.evidence_refs,
            observed_at, observed_at + timedelta(minutes=2),
        )
    if not request.scan_completed:
        return ScanFinding(
            "unknown", ("scan_incomplete_or_unavailable",), request.evidence_refs,
            observed_at, observed_at + timedelta(minutes=2),
        )
    if request.malware_match:
        return ScanFinding(
            "malicious", ("malware_match",), request.evidence_refs,
            observed_at, observed_at + timedelta(minutes=10),
        )
    if request.suspicious_content:
        return ScanFinding(
            "suspicious", ("suspicious_content_detected",), request.evidence_refs,
            observed_at, observed_at + timedelta(minutes=10),
        )
    return ScanFinding(
        "clean", ("completed_supported_scan_no_material_finding",), request.evidence_refs,
        observed_at, observed_at + timedelta(minutes=10),
    )


def correlate_findings(findings: Iterable[DetectionFinding]) -> DetectionFinding:
    items = tuple(findings)
    if not items:
        now = _now()
        return DetectionFinding("unknown", "informational", 0.0, ("no_findings_to_correlate",), (), now, now)

    rank = {
        "unknown": 0,
        "informational": 1,
        "suspicious": 2,
        "likely_malicious": 3,
        "confirmed_malicious": 4,
    }
    chosen = max(items, key=lambda f: (rank[f.disposition], f.confidence))
    evidence = tuple(dict.fromkeys(ref for item in items for ref in item.evidence_refs))
    reasons = tuple(dict.fromkeys(reason for item in items for reason in item.reason_codes))
    return DetectionFinding(
        chosen.disposition,
        chosen.severity,
        max(item.confidence for item in items),
        reasons,
        evidence,
        max(item.observed_at for item in items),
        min(item.valid_until for item in items),
    )
