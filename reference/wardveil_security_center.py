"""Dependency-free Wardveil Security Center reference read model."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

VALID_TYPES={"trust_decision","policy_decision","detection_finding","scan_finding","protection_action","quarantine_record","incident_record","audit_event"}
SEVERITY_RANK={"informational":0,"low":1,"medium":2,"high":3,"critical":4}

@dataclass(frozen=True)
class CenterSnapshot:
    generated_at:str
    protection_status:str
    active_threats:int
    quarantined_items:int
    open_incidents:int
    degraded_reasons:tuple[str,...]
    records:tuple[dict,...]

    def as_dict(self)->dict:
        return {
            "generated_at":self.generated_at,
            "protection_status":self.protection_status,
            "active_threats":self.active_threats,
            "quarantined_items":self.quarantined_items,
            "open_incidents":self.open_incidents,
            "degraded_reasons":list(self.degraded_reasons),
            "records":list(self.records),
        }

def _authoritative(record:dict)->bool:
    return bool(record.get("producer",{}).get("authoritative") is True)

def _valid_record(record:dict)->bool:
    return record.get("record_type") in VALID_TYPES and _authoritative(record) and bool(record.get("record_id")) and bool(record.get("observed_at"))

def build_snapshot(records:Iterable[dict], *, now:datetime|None=None)->CenterSnapshot:
    now=now or datetime.now(timezone.utc)
    accepted=tuple(r for r in records if _valid_record(r))
    reasons=[]
    active_threats=0
    quarantined=0
    open_incidents=0
    successful_protection=False

    for r in accepted:
        rt=r["record_type"]
        if rt=="detection_finding" and r.get("detection_disposition") in {"likely_malicious","confirmed_malicious"}:
            active_threats+=1
        elif rt=="scan_finding" and r.get("scan_result") in {"suspicious","malicious"}:
            active_threats+=1
        elif rt=="quarantine_record" and r.get("review_state") in {"pending","under_review","retained"}:
            quarantined+=1
        elif rt=="incident_record" and r.get("incident_status") not in {"verified","closed"}:
            open_incidents+=1
        elif rt=="protection_action" and r.get("execution_status")=="succeeded":
            successful_protection=True

        if rt=="scan_finding" and r.get("scan_result") in {"unknown","unsupported"}:
            reasons.append("scan_coverage_incomplete")
        if rt=="protection_action" and r.get("execution_status") in {"failed","rejected","expired"}:
            reasons.append("protection_action_not_completed")

    if not accepted:
        status="unknown"
        reasons.append("no_authoritative_records")
    elif reasons:
        status="degraded"
    elif active_threats or open_incidents:
        status="attention"
    elif successful_protection:
        status="protected"
    else:
        status="operational"

    return CenterSnapshot(
        generated_at=now.isoformat().replace("+00:00","Z"),
        protection_status=status,
        active_threats=active_threats,
        quarantined_items=quarantined,
        open_incidents=open_incidents,
        degraded_reasons=tuple(sorted(set(reasons))),
        records=accepted,
    )
