#!/usr/bin/env python3
from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from reference.wardveil_security_center import build_snapshot  # noqa:E402
NOW=datetime(2026,8,26,12,0,tzinfo=timezone.utc)

def rec(t, **extra):
    base={"contract_version":"0.1.0","record_type":t,"record_id":f"{t}-1","producer":{"id":"wardveil","authoritative":True},"scope":{"resource_type":"file","resource_id":"x"},"observed_at":"2026-08-26T11:00:00Z","evidence_refs":["e:1"]}
    base.update(extra); return base

def main():
    s=build_snapshot([],now=NOW); assert s.protection_status=="unknown"
    s=build_snapshot([rec("scan_finding",scan_result="unsupported")],now=NOW); assert s.protection_status=="degraded" and "scan_coverage_incomplete" in s.degraded_reasons
    s=build_snapshot([rec("detection_finding",detection_disposition="confirmed_malicious",severity="high",confidence=.99)],now=NOW); assert s.protection_status=="attention" and s.active_threats==1
    s=build_snapshot([rec("protection_action",policy_decision="block",executor="wardveil-protect",idempotency_key="i",execution_status="succeeded",valid_until="2026-08-26T13:00:00Z")],now=NOW); assert s.protection_status=="protected"
    unauth=rec("protection_action",execution_status="succeeded"); unauth["producer"]["authoritative"]=False
    s=build_snapshot([unauth],now=NOW); assert s.protection_status=="unknown"
    s=build_snapshot([rec("quarantine_record",review_state="pending"),rec("incident_record",incident_status="open",severity="critical")],now=NOW); assert s.quarantined_items==1 and s.open_incidents==1 and s.protection_status=="attention"
    print("Wardveil Security Center tests passed: 6")
if __name__=="__main__": main()
