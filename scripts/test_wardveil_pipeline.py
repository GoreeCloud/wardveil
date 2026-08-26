#!/usr/bin/env python3
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reference.wardveil_decision import AccessRequest, TrustSignal
from reference.wardveil_detect_scan import DetectionInput, EvidenceSignal, ScanInput
from reference.wardveil_incident import Authority
from reference.wardveil_pipeline import WardveilPipeline
from reference.wardveil_protect import ExecutorAuthority

NOW = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)


def main() -> None:
    pipeline = WardveilPipeline()

    access = pipeline.evaluate_access(
        AccessRequest(
            principal_class="user",
            resource_type="vault_secret",
            resource_id="secret-1",
            operation="read",
            producer_id="goreecloud-vault",
            signals=(TrustSignal("passkey_verified", True, evidence_ref="evidence:passkey-1"),),
            resource_sensitivity="high",
        ),
        executor_authority=ExecutorAuthority(
            executor_id="vault-security-adapter",
            allowed_actions=frozenset({"allow", "allow_and_log", "warn", "step_up", "restrict", "block"}),
            allowed_resource_types=frozenset({"vault_secret"}),
        ),
        idempotency_key="access-1",
        now=NOW,
    )
    assert [r["record_type"] for r in access.records] == [
        "trust_decision", "policy_decision", "protection_action", "audit_event"
    ]
    assert len({r["correlation_id"] for r in access.records}) == 1
    assert access.snapshot.protection_status == "protected"

    threat = pipeline.evaluate_content(
        DetectionInput(
            resource_type="file",
            resource_id="file-1",
            producer_id="wardveil-detect-test",
            signals=(EvidenceSignal(
                "known_malware",
                confidence=0.99,
                malicious_indicator=True,
                confirmed_indicator=True,
                evidence_ref="evidence:malware-1",
            ),),
        ),
        ScanInput(
            resource_type="file",
            resource_id="file-1",
            producer_id="wardveil-scan-test",
            scanner_supported=True,
            scan_completed=True,
            malware_match=True,
            evidence_refs=("evidence:scan-1",),
        ),
        incident_authority=Authority(
            actor_id="wardveil-response-adapter",
            allowed_actions=frozenset({"quarantine"}),
        ),
        now=NOW,
    )
    types = [r["record_type"] for r in threat.records]
    assert types == ["detection_finding", "scan_finding", "quarantine_record", "incident_record", "audit_event"]
    assert threat.snapshot.active_threats == 2
    assert threat.snapshot.quarantined_items == 1
    assert threat.snapshot.open_incidents == 1
    assert threat.snapshot.protection_status == "attention"

    unsupported = pipeline.evaluate_content(
        DetectionInput(
            resource_type="archive",
            resource_id="archive-1",
            producer_id="wardveil-detect-test",
            signals=(EvidenceSignal("no_material_signal", evidence_ref="evidence:none-1"),),
        ),
        ScanInput(
            resource_type="archive",
            resource_id="archive-1",
            producer_id="wardveil-scan-test",
            scanner_supported=False,
            scan_completed=False,
            evidence_refs=("evidence:unsupported-1",),
        ),
        incident_authority=Authority(actor_id="wardveil-response-adapter", allowed_actions=frozenset()),
        now=NOW,
    )
    assert len(unsupported.records) == 2
    assert unsupported.snapshot.protection_status == "degraded"
    assert "scan_coverage_incomplete" in unsupported.snapshot.degraded_reasons

    print("Wardveil cross-service pipeline tests passed")


if __name__ == "__main__":
    main()
