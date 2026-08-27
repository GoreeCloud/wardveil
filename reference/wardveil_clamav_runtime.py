#!/usr/bin/env python3
"""Runtime health and clean-verdict gating for the Wardveil ClamAV adapter.

The adapter's scan verdict and the scanner runtime's health are separate evidence
streams. A positive malware match remains actionable evidence, while a clean
verdict is only reusable when current scanner-health evidence establishes daemon
reachability and sufficiently fresh signatures.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Mapping

from reference.wardveil_clamav import (
    ClamAVClient,
    ClamAVConfig,
    ClamAVVerdict,
    verdict_to_scan_input,
)
from reference.wardveil_detect_scan import ScanFinding, evaluate_scan

DEFAULT_MAX_SIGNATURE_AGE_HOURS = 48.0
DEFAULT_HEALTH_VALIDITY_MINUTES = 5.0
DEFAULT_MAX_SCAN_ERROR_RATE = 0.05
DEFAULT_MIN_ERROR_RATE_SAMPLES = 20


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ClamAVVersionInfo:
    engine_version: str
    database_version: str
    database_updated_at: datetime
    raw_reply: str


@dataclass(frozen=True)
class ClamAVRuntimePolicy:
    max_signature_age: timedelta = timedelta(hours=DEFAULT_MAX_SIGNATURE_AGE_HOURS)
    health_validity: timedelta = timedelta(minutes=DEFAULT_HEALTH_VALIDITY_MINUTES)
    max_scan_error_rate: float = DEFAULT_MAX_SCAN_ERROR_RATE
    min_error_rate_samples: int = DEFAULT_MIN_ERROR_RATE_SAMPLES

    def validate(self) -> None:
        if self.max_signature_age <= timedelta(0):
            raise ValueError("max_signature_age_must_be_positive")
        if self.health_validity <= timedelta(0):
            raise ValueError("health_validity_must_be_positive")
        if not 0 <= self.max_scan_error_rate <= 1:
            raise ValueError("max_scan_error_rate_must_be_between_zero_and_one")
        if self.min_error_rate_samples < 1:
            raise ValueError("min_error_rate_samples_must_be_positive")


@dataclass
class ClamAVRuntimeMetrics:
    total_scans: int = 0
    scan_errors: int = 0
    last_successful_scan_at: datetime | None = None

    @property
    def error_rate(self) -> float:
        return self.scan_errors / self.total_scans if self.total_scans else 0.0

    def validate(self) -> None:
        if self.total_scans < 0 or self.scan_errors < 0:
            raise ValueError("scan_metrics_must_be_non_negative")
        if self.scan_errors > self.total_scans:
            raise ValueError("scan_errors_cannot_exceed_total_scans")

    def record(self, verdict: ClamAVVerdict, *, now: datetime | None = None) -> None:
        self.total_scans += 1
        if verdict.completed:
            self.last_successful_scan_at = _utc(now)
        else:
            self.scan_errors += 1


@dataclass(frozen=True)
class ClamAVHealthEvidence:
    observed_at: datetime
    valid_until: datetime
    runtime_state: str
    daemon_reachable: bool
    engine_version: str | None
    database_version: str | None
    database_updated_at: datetime | None
    signature_freshness: str
    signature_age_seconds: float | None
    last_successful_scan_at: datetime | None
    scan_error_rate: float | None
    scan_sample_size: int
    configured_max_stream_bytes: int
    transport: str
    degraded_reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def clean_verdicts_eligible(self) -> bool:
        return (
            self.runtime_state == "healthy"
            and self.daemon_reachable
            and self.signature_freshness == "current"
            and not self.degraded_reasons
        )

    @property
    def evidence_ref(self) -> str:
        stamp = self.observed_at.isoformat().replace("+00:00", "Z")
        return f"wardveil:clamav-health:{stamp}:{self.runtime_state}"

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "component": "Wardveil ClamAV malware scanning runtime",
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "runtime_state": self.runtime_state,
            "daemon_reachable": self.daemon_reachable,
            "engine_version": self.engine_version,
            "database_version": self.database_version,
            "database_updated_at": self.database_updated_at.isoformat() if self.database_updated_at else None,
            "signature_freshness": self.signature_freshness,
            "signature_age_seconds": self.signature_age_seconds,
            "last_successful_scan_at": self.last_successful_scan_at.isoformat() if self.last_successful_scan_at else None,
            "scan_error_rate": self.scan_error_rate,
            "scan_sample_size": self.scan_sample_size,
            "configured_max_stream_bytes": self.configured_max_stream_bytes,
            "transport": self.transport,
            "degraded_reasons": list(self.degraded_reasons),
            "clean_verdicts_eligible": self.clean_verdicts_eligible,
            "protection_claim_authority": False,
        }

    def as_status_record(self) -> dict:
        if self.runtime_state == "healthy":
            state = "protected"
            evidence_status = "current"
        elif self.runtime_state == "degraded":
            state = "degraded"
            evidence_status = "stale" if self.signature_freshness == "stale" else "current"
        elif self.runtime_state == "unavailable":
            state = "unknown"
            evidence_status = "unavailable"
        else:
            state = "unknown"
            evidence_status = "unverified"

        summary = "ClamAV runtime health is healthy for the represented scanner control."
        if self.degraded_reasons:
            summary = "ClamAV runtime health: " + ", ".join(self.degraded_reasons)
        elif state == "unknown":
            summary = "ClamAV runtime health could not be verified."

        return {
            "contract_version": "0.1.0",
            "scope": {
                "kind": "control",
                "id": "wardveil-clamav-runtime",
                "display_name": "Wardveil ClamAV runtime health",
            },
            "authority": {
                "system": "Wardveil Scan",
                "control": "ClamAV runtime health",
                "authoritative": True,
            },
            "state": state,
            "source_state": self.runtime_state,
            "evidence": {
                "status": evidence_status,
                "observed_at": self.observed_at.isoformat(),
                "valid_until": self.valid_until.isoformat(),
                "summary": summary[:240],
                "reference": self.evidence_ref,
            },
            "claim": {"protected_by_wardveil": False},
            "privacy": {
                "details_withheld": True,
                "redactions": ["scanner endpoint", "socket path", "operational diagnostics"],
            },
        }


_VERSION_RE = re.compile(
    r"^ClamAV\s+(?P<engine>[^/\s]+)/(?P<database>[^/\s]+)/(?P<updated>.+)$",
    re.IGNORECASE,
)


def parse_version_reply(reply: str) -> ClamAVVersionInfo:
    text = " ".join(reply.strip().replace("\x00", "").split())
    match = _VERSION_RE.match(text)
    if not match:
        raise ValueError("unrecognized_clamav_version_reply")

    updated_text = match.group("updated")
    parsed = None
    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Z %Y"):
        try:
            parsed = datetime.strptime(updated_text, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        raise ValueError("unrecognized_clamav_database_timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return ClamAVVersionInfo(
        engine_version=match.group("engine"),
        database_version=match.group("database"),
        database_updated_at=parsed.astimezone(timezone.utc),
        raw_reply=reply,
    )


def _transport(config: ClamAVConfig) -> str:
    return "unix" if config.unix_socket else "tcp"


def collect_clamav_health(
    client: ClamAVClient,
    *,
    metrics: ClamAVRuntimeMetrics | None = None,
    policy: ClamAVRuntimePolicy | None = None,
    now: datetime | None = None,
) -> ClamAVHealthEvidence:
    observed_at = _utc(now)
    policy = policy or ClamAVRuntimePolicy()
    policy.validate()
    metrics = metrics or ClamAVRuntimeMetrics()
    metrics.validate()
    reasons: list[str] = []

    try:
        reachable = client.ping()
    except (OSError, TimeoutError, RuntimeError, ValueError):
        reachable = False

    base = dict(
        observed_at=observed_at,
        valid_until=observed_at + policy.health_validity,
        last_successful_scan_at=_utc(metrics.last_successful_scan_at) if metrics.last_successful_scan_at else None,
        scan_error_rate=metrics.error_rate if metrics.total_scans else None,
        scan_sample_size=metrics.total_scans,
        configured_max_stream_bytes=client.config.max_stream_bytes,
        transport=_transport(client.config),
    )

    if not reachable:
        return ClamAVHealthEvidence(
            runtime_state="unavailable",
            daemon_reachable=False,
            engine_version=None,
            database_version=None,
            database_updated_at=None,
            signature_freshness="unknown",
            signature_age_seconds=None,
            degraded_reasons=("clamd_unreachable",),
            **base,
        )

    try:
        version = parse_version_reply(client.version())
    except (OSError, TimeoutError, RuntimeError, ValueError):
        return ClamAVHealthEvidence(
            runtime_state="unknown",
            daemon_reachable=True,
            engine_version=None,
            database_version=None,
            database_updated_at=None,
            signature_freshness="unknown",
            signature_age_seconds=None,
            degraded_reasons=("signature_freshness_unverified",),
            **base,
        )

    signature_age = observed_at - version.database_updated_at
    if signature_age < timedelta(0):
        freshness = "unknown"
        reasons.append("signature_timestamp_in_future")
    elif signature_age > policy.max_signature_age:
        freshness = "stale"
        reasons.append("signature_database_stale")
    else:
        freshness = "current"

    if (
        metrics.total_scans >= policy.min_error_rate_samples
        and metrics.error_rate > policy.max_scan_error_rate
    ):
        reasons.append("scan_error_rate_high")

    if "signature_timestamp_in_future" in reasons:
        state = "unknown"
    elif reasons:
        state = "degraded"
    else:
        state = "healthy"

    return ClamAVHealthEvidence(
        runtime_state=state,
        daemon_reachable=True,
        engine_version=version.engine_version,
        database_version=version.database_version,
        database_updated_at=version.database_updated_at,
        signature_freshness=freshness,
        signature_age_seconds=max(0.0, signature_age.total_seconds()),
        degraded_reasons=tuple(sorted(set(reasons))),
        **base,
    )


def gate_clamav_verdict(
    verdict: ClamAVVerdict,
    health: ClamAVHealthEvidence,
    *,
    resource_id: str,
    producer_id: str = "wardveil-scan-clamav",
    now: datetime | None = None,
) -> ScanFinding:
    observed_at = _utc(now)
    request = verdict_to_scan_input(
        verdict,
        resource_id=resource_id,
        producer_id=producer_id,
    )
    finding = evaluate_scan(request, now=observed_at)
    health_current = health.observed_at <= observed_at < health.valid_until
    if finding.result != "clean" or (health.clean_verdicts_eligible and health_current):
        return finding

    health_reasons = list(health.degraded_reasons)
    if observed_at < health.observed_at:
        health_reasons.append("scanner_health_evidence_from_future")
    elif observed_at >= health.valid_until:
        health_reasons.append("scanner_health_evidence_expired")
    reasons = ("scanner_health_not_acceptable_for_clean_verdict",) + tuple(
        f"scanner_health:{reason}" for reason in sorted(set(health_reasons))
    )
    evidence = tuple(dict.fromkeys((*finding.evidence_refs, health.evidence_ref)))
    return ScanFinding(
        "unknown",
        reasons,
        evidence,
        observed_at,
        observed_at + timedelta(minutes=2),
    )


def config_from_env(env: Mapping[str, str] | None = None) -> ClamAVConfig:
    env = env or os.environ
    tcp_host = env.get("WARDVEIL_CLAMAV_TCP_HOST", "").strip() or None
    unix_socket = None if tcp_host else env.get(
        "WARDVEIL_CLAMAV_UNIX_SOCKET", "/run/clamav/clamd.ctl"
    ).strip()
    config = ClamAVConfig(
        unix_socket=unix_socket or None,
        tcp_host=tcp_host,
        tcp_port=int(env.get("WARDVEIL_CLAMAV_PORT", "3310")),
        timeout_seconds=float(env.get("WARDVEIL_CLAMAV_TIMEOUT_SECONDS", "30")),
        max_stream_bytes=int(env.get("WARDVEIL_CLAMAV_MAX_STREAM_BYTES", str(25 * 1024 * 1024))),
        chunk_bytes=int(env.get("WARDVEIL_CLAMAV_CHUNK_BYTES", str(64 * 1024))),
        producer_id=env.get("WARDVEIL_CLAMAV_PRODUCER_ID", "wardveil-scan-clamav"),
    )
    config.validate()
    return config


def policy_from_env(env: Mapping[str, str] | None = None) -> ClamAVRuntimePolicy:
    env = env or os.environ
    policy = ClamAVRuntimePolicy(
        max_signature_age=timedelta(
            hours=float(env.get("WARDVEIL_CLAMAV_MAX_SIGNATURE_AGE_HOURS", "48"))
        ),
        health_validity=timedelta(
            minutes=float(env.get("WARDVEIL_CLAMAV_HEALTH_VALIDITY_MINUTES", "5"))
        ),
        max_scan_error_rate=float(
            env.get("WARDVEIL_CLAMAV_MAX_SCAN_ERROR_RATE", "0.05")
        ),
        min_error_rate_samples=int(
            env.get("WARDVEIL_CLAMAV_MIN_ERROR_RATE_SAMPLES", "20")
        ),
    )
    policy.validate()
    return policy
