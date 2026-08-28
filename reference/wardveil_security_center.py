"""Dependency-free Wardveil Security Center reference read model."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

VALID_TYPES = {
    "trust_decision", "policy_decision", "detection_finding", "scan_finding",
    "protection_action", "quarantine_record", "incident_record", "audit_event",
}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class CenterSnapshot:
    generated_at: str
    protection_status: str
    active_threats: int
    quarantined_items: int
    open_incidents: int
    degraded_reasons: tuple[str, ...]
    records: tuple[dict, ...]
    execution_provenance: tuple[dict, ...] = ()

    def as_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "protection_status": self.protection_status,
            "active_threats": self.active_threats,
            "quarantined_items": self.quarantined_items,
            "open_incidents": self.open_incidents,
            "degraded_reasons": list(self.degraded_reasons),
            "records": list(self.records),
            "execution_provenance": list(self.execution_provenance),
        }


def _authoritative(record: dict) -> bool:
    return bool(record.get("producer", {}).get("authoritative") is True)


def _valid_record(record: dict) -> bool:
    return (
        record.get("record_type") in VALID_TYPES
        and _authoritative(record)
        and bool(record.get("record_id"))
        and bool(record.get("observed_at"))
    )


def _safe_execution_provenance(record: dict) -> dict | None:
    if record.get("record_type") != "audit_event":
        return None
    provenance = record.get("authorization_provenance")
    if not isinstance(provenance, dict):
        return None
    required = ("authorization_id", "issuer_id", "executor_id", "signing_key_id")
    if any(not isinstance(provenance.get(key), str) or not provenance[key] for key in required):
        return None
    allowed = {*required, "signature_algorithm"}
    if set(provenance) - allowed:
        return None
    return {key: provenance[key] for key in sorted(provenance)}


def build_snapshot(records: Iterable[dict], *, now: datetime | None = None) -> CenterSnapshot:
    now = now or datetime.now(timezone.utc)
    accepted = tuple(r for r in records if _valid_record(r))
    reasons: list[str] = []
    provenance: list[dict] = []
    active_threats = 0
    quarantined = 0
    open_incidents = 0
    successful_protection = False

    for record in accepted:
        record_type = record["record_type"]
        if record_type == "detection_finding" and record.get("detection_disposition") in {"likely_malicious", "confirmed_malicious"}:
            active_threats += 1
        elif record_type == "scan_finding" and record.get("scan_result") in {"suspicious", "malicious"}:
            active_threats += 1
        elif record_type == "quarantine_record" and record.get("review_state") in {"pending", "under_review", "retained"}:
            quarantined += 1
        elif record_type == "incident_record" and record.get("incident_status") not in {"verified", "closed"}:
            open_incidents += 1
        elif record_type == "protection_action" and record.get("execution_status") == "succeeded":
            successful_protection = True

        if record_type == "scan_finding" and record.get("scan_result") in {"unknown", "unsupported"}:
            reasons.append("scan_coverage_incomplete")
        if record_type == "protection_action" and record.get("execution_status") in {"failed", "rejected", "expired"}:
            reasons.append("protection_action_not_completed")

        safe_provenance = _safe_execution_provenance(record)
        if safe_provenance is not None:
            provenance.append(safe_provenance)

    if not accepted:
        status = "unknown"
        reasons.append("no_authoritative_records")
    elif reasons:
        status = "degraded"
    elif active_threats or open_incidents:
        status = "attention"
    elif successful_protection:
        status = "protected"
    else:
        status = "operational"

    return CenterSnapshot(
        generated_at=now.isoformat().replace("+00:00", "Z"),
        protection_status=status,
        active_threats=active_threats,
        quarantined_items=quarantined,
        open_incidents=open_incidents,
        degraded_reasons=tuple(sorted(set(reasons))),
        records=accepted,
        execution_provenance=tuple(provenance),
    )
