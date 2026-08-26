"""Dependency-free Wardveil cross-service reference pipeline.

This module composes the accepted Wardveil reference services into bounded,
correlated flows. It does not create production authority or deployment state.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from reference.wardveil_decision import AccessRequest, decide
from reference.wardveil_detect_scan import DetectionInput, ScanInput, evaluate_detection, evaluate_scan
from reference.wardveil_incident import Authority, Scope, append_audit_event, create_incident, quarantine
from reference.wardveil_protect import ExecutorAuthority, ProtectEngine
from reference.wardveil_security_center import CenterSnapshot, build_snapshot


@dataclass(frozen=True)
class PipelineResult:
    correlation_id: str
    records: tuple[dict, ...]
    snapshot: CenterSnapshot

    def as_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "records": list(self.records),
            "snapshot": self.snapshot.as_dict(),
        }


class WardveilPipeline:
    """In-process orchestration reference for Wardveil service contracts."""

    def __init__(self) -> None:
        self._protect = ProtectEngine()

    def evaluate_access(
        self,
        request: AccessRequest,
        *,
        executor_authority: ExecutorAuthority,
        idempotency_key: str,
        handler=None,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> PipelineResult:
        observed_at = now or datetime.now(timezone.utc)
        correlation = correlation_id or f"wardveil-{uuid4()}"
        trust, policy = decide(request, now=observed_at)
        trust_record = trust.as_runtime_record(request, correlation)
        policy_record = policy.as_runtime_record(request, correlation)
        protection = self._protect.execute(
            policy_record,
            executor_authority,
            idempotency_key=idempotency_key,
            handler=handler,
            now=observed_at,
        )
        protection_record = protection.as_runtime_record(correlation)
        scope = Scope(
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            operation=request.operation,
            principal_class=request.principal_class,
        )
        evidence = tuple(policy_record.get("evidence_refs") or ()) or (policy_record["record_id"],)
        audit = append_audit_event(
            record_id=f"audit-{uuid4()}",
            correlation_id=correlation,
            producer_id="wardveil-audit-reference",
            scope=scope,
            event_type="protection_action",
            outcome=protection.status,
            actor_id=executor_authority.executor_id or "unassigned",
            evidence_refs=evidence,
            now=observed_at,
        ).as_runtime_record()
        records = (trust_record, policy_record, protection_record, audit)
        return PipelineResult(correlation, records, build_snapshot(records, now=observed_at))

    def evaluate_content(
        self,
        detection_input: DetectionInput,
        scan_input: ScanInput,
        *,
        incident_authority: Authority,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> PipelineResult:
        observed_at = now or datetime.now(timezone.utc)
        correlation = correlation_id or f"wardveil-{uuid4()}"
        detection = evaluate_detection(detection_input, now=observed_at)
        scan = evaluate_scan(scan_input, now=observed_at)
        detection_record = detection.as_runtime_record(detection_input, correlation)
        scan_record = scan.as_runtime_record(scan_input, correlation)
        records: list[dict] = [detection_record, scan_record]

        material_threat = detection.disposition in {"likely_malicious", "confirmed_malicious"} or scan.result == "malicious"
        if material_threat:
            scope = Scope(scan_input.resource_type, scan_input.resource_id)
            evidence = tuple(dict.fromkeys((*detection.evidence_refs, *scan.evidence_refs))) or (
                detection_record["record_id"], scan_record["record_id"]
            )
            source_ids = (detection_record["record_id"], scan_record["record_id"])
            quarantine_record = quarantine(
                record_id=f"quarantine-{uuid4()}",
                correlation_id=correlation,
                producer_id="wardveil-quarantine-reference",
                scope=scope,
                reason="material_threat_requires_isolation",
                evidence_refs=evidence,
                source_record_ids=source_ids,
                authority=incident_authority,
                now=observed_at,
            )
            severity = detection.severity if detection.severity in {"high", "critical"} else "high"
            incident = create_incident(
                record_id=f"incident-{uuid4()}",
                correlation_id=correlation,
                producer_id="wardveil-response-reference",
                scope=scope,
                severity=severity,
                evidence_refs=evidence,
                source_record_ids=source_ids,
                now=observed_at,
            )
            audit = append_audit_event(
                record_id=f"audit-{uuid4()}",
                correlation_id=correlation,
                producer_id="wardveil-audit-reference",
                scope=scope,
                event_type="quarantine_created",
                outcome="succeeded",
                actor_id=incident_authority.actor_id,
                evidence_refs=evidence,
                now=observed_at,
            )
            records.extend((quarantine_record.as_runtime_record(), incident.as_runtime_record(), audit.as_runtime_record()))

        result_records = tuple(records)
        return PipelineResult(correlation, result_records, build_snapshot(result_records, now=observed_at))
