#!/usr/bin/env python3
"""Authenticated transport boundary for Wardveil Scan.

The transport authenticates first-party scan callers, binds the request to the
exact resource identity and content digest, calls the replaceable Wardveil Scan
engine, and returns the consumer-facing scan envelope. It never exposes clamd.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping
from uuid import uuid4

from reference.wardveil_clamav import ClamAVClient, ClamAVVerdict
from reference.wardveil_clamav_runtime import ClamAVHealthEvidence
from reference.wardveil_detect_scan import ScanFinding, ScanInput, evaluate_scan

CONTRACT_VERSION = "0.1.0"
RECORD_TYPE = "scan_finding"
SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-transport"
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60
DEFAULT_MAX_BODY_BYTES = 25 * 1024 * 1024
SUPPORTED_RESOURCE_TYPES = frozenset(
    {"mail_attachment", "drive_file", "browser_download", "ai_artifact"}
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return utc(datetime.fromisoformat(text))
    except ValueError as exc:
        raise ValueError("invalid_scan_request_timestamp") from exc


@dataclass(frozen=True)
class CallerCredential:
    caller_id: str
    key_id: str
    secret: bytes
    resource_types: frozenset[str]
    active: bool = True

    def validate(self) -> None:
        if not _TOKEN_RE.fullmatch(self.caller_id):
            raise ValueError("invalid_caller_id")
        if not _TOKEN_RE.fullmatch(self.key_id):
            raise ValueError("invalid_key_id")
        if len(self.secret) < 32:
            raise ValueError("scan_transport_secret_too_short")
        if not self.resource_types or not self.resource_types <= SUPPORTED_RESOURCE_TYPES:
            raise ValueError("invalid_caller_resource_types")


@dataclass(frozen=True)
class ScanTransportRequest:
    caller_id: str
    key_id: str
    timestamp: str
    nonce: str
    action: str
    resource_type: str
    resource_id: str
    correlation_id: str
    content_length: int
    content_sha256: str
    signature: str

    def validate_shape(self, *, max_body_bytes: int) -> None:
        for value, error in (
            (self.caller_id, "invalid_caller_id"),
            (self.key_id, "invalid_key_id"),
            (self.nonce, "invalid_nonce"),
            (self.action, "invalid_action"),
            (self.resource_type, "invalid_resource_type"),
            (self.correlation_id, "invalid_correlation_id"),
        ):
            if not _TOKEN_RE.fullmatch(value):
                raise ValueError(error)
        if not self.resource_id or len(self.resource_id) > 1024 or "\n" in self.resource_id or "\r" in self.resource_id:
            raise ValueError("invalid_resource_id")
        if self.resource_type not in SUPPORTED_RESOURCE_TYPES:
            raise ValueError("unsupported_resource_type")
        if self.content_length < 0 or self.content_length > max_body_bytes:
            raise ValueError("scan_content_length_invalid")
        if not _SHA256_RE.fullmatch(self.content_sha256):
            raise ValueError("invalid_content_sha256")
        if not _SHA256_RE.fullmatch(self.signature):
            raise ValueError("invalid_scan_signature")
        parse_timestamp(self.timestamp)


@dataclass(frozen=True)
class ReplayEntry:
    auth_digest: str
    response: dict | None = None


@dataclass
class InMemoryReplayLedger:
    entries: dict[tuple[str, str, str], ReplayEntry] = field(default_factory=dict)

    def claim(self, request: ScanTransportRequest, auth_digest: str) -> tuple[str, dict | None]:
        key = (request.caller_id, request.key_id, request.nonce)
        current = self.entries.get(key)
        if current is None:
            self.entries[key] = ReplayEntry(auth_digest=auth_digest)
            return "new", None
        if current.auth_digest != auth_digest:
            return "conflict", None
        if current.response is None:
            return "pending", None
        return "exact_replay", current.response

    def finalize(self, request: ScanTransportRequest, auth_digest: str, response: dict) -> None:
        key = (request.caller_id, request.key_id, request.nonce)
        current = self.entries.get(key)
        if current is None or current.auth_digest != auth_digest:
            raise RuntimeError("scan_replay_claim_lost")
        self.entries[key] = ReplayEntry(auth_digest=auth_digest, response=response)


class ScanTransportError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_auth_material(request: ScanTransportRequest) -> bytes:
    fields = (
        CONTRACT_VERSION,
        request.caller_id,
        request.key_id,
        request.timestamp,
        request.nonce,
        request.action,
        request.resource_type,
        request.resource_id,
        request.correlation_id,
        str(request.content_length),
        request.content_sha256,
    )
    return "\n".join(fields).encode("utf-8")


def sign_scan_request(request: ScanTransportRequest, secret: bytes) -> str:
    return hmac.new(secret, canonical_auth_material(request), hashlib.sha256).hexdigest()


def _finding_with_health(
    verdict: ClamAVVerdict,
    health: ClamAVHealthEvidence,
    *,
    request: ScanTransportRequest,
    producer_id: str,
    now: datetime,
) -> ScanFinding:
    evidence = tuple(ref for ref in (verdict.evidence_ref,) if ref)
    scan_input = ScanInput(
        resource_type=request.resource_type,
        resource_id=request.resource_id,
        producer_id=producer_id,
        scanner_supported=verdict.error_code != "unsupported_resource",
        scan_completed=verdict.completed,
        malware_match=verdict.malware_match,
        suspicious_content=False,
        evidence_refs=evidence,
    )
    finding = evaluate_scan(scan_input, now=now)
    health_current = health.observed_at <= now < health.valid_until

    if finding.result == "clean":
        combined = tuple(dict.fromkeys((*finding.evidence_refs, health.evidence_ref)))
        if health.clean_verdicts_eligible and health_current:
            return ScanFinding(
                finding.result,
                finding.reason_codes,
                combined,
                finding.observed_at,
                min(finding.valid_until, health.valid_until),
            )
        reasons = ["scanner_health_not_acceptable_for_clean_verdict"]
        reasons.extend(f"scanner_health:{item}" for item in health.degraded_reasons)
        if now < health.observed_at:
            reasons.append("scanner_health:scanner_health_evidence_from_future")
        elif now >= health.valid_until:
            reasons.append("scanner_health:scanner_health_evidence_expired")
        return ScanFinding(
            "unknown",
            tuple(dict.fromkeys(reasons)),
            combined,
            now,
            now + timedelta(minutes=2),
        )

    # A positive malware match remains actionable even when scanner health is
    # degraded; health state must never transform malicious into clean.
    return finding


class AuthenticatedScanService:
    def __init__(
        self,
        *,
        scanner: ClamAVClient,
        health_provider: Callable[[], ClamAVHealthEvidence],
        credentials: Mapping[tuple[str, str], CallerCredential],
        replay_ledger: InMemoryReplayLedger | None = None,
        max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        now: Callable[[], datetime] | None = None,
    ):
        if max_clock_skew_seconds < 1 or max_body_bytes < 1:
            raise ValueError("invalid_scan_transport_limits")
        self.scanner = scanner
        self.health_provider = health_provider
        self.credentials = dict(credentials)
        for credential in self.credentials.values():
            credential.validate()
        self.replay_ledger = replay_ledger or InMemoryReplayLedger()
        self.max_clock_skew = timedelta(seconds=max_clock_skew_seconds)
        self.max_body_bytes = max_body_bytes
        self._now = now or (lambda: datetime.now(timezone.utc))

    def scan(self, request: ScanTransportRequest, body: bytes) -> dict:
        request.validate_shape(max_body_bytes=self.max_body_bytes)
        if len(body) != request.content_length:
            raise ScanTransportError("scan_content_length_mismatch")
        actual_digest = hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(actual_digest, request.content_sha256):
            raise ScanTransportError("scan_content_digest_mismatch")

        credential = self.credentials.get((request.caller_id, request.key_id))
        if credential is None or not credential.active:
            raise ScanTransportError("scan_caller_not_authorized")
        if request.resource_type not in credential.resource_types:
            raise ScanTransportError("scan_resource_type_not_authorized")

        observed_now = utc(self._now())
        signed_at = parse_timestamp(request.timestamp)
        if abs(observed_now - signed_at) > self.max_clock_skew:
            raise ScanTransportError("scan_request_timestamp_outside_window")

        expected = sign_scan_request(request, credential.secret)
        if not hmac.compare_digest(expected, request.signature):
            raise ScanTransportError("scan_signature_invalid")

        auth_digest = hashlib.sha256(canonical_auth_material(request) + b"\n" + request.signature.encode("ascii")).hexdigest()
        replay_state, cached = self.replay_ledger.claim(request, auth_digest)
        if replay_state == "conflict":
            raise ScanTransportError("scan_nonce_conflict")
        if replay_state == "pending":
            raise ScanTransportError("scan_request_already_in_progress")
        if replay_state == "exact_replay":
            return dict(cached or {})

        health = self.health_provider()
        verdict = self.scanner.scan_bytes(body)
        finding = _finding_with_health(
            verdict,
            health,
            request=request,
            producer_id=self.scanner.config.producer_id,
            now=observed_now,
        )
        record = {
            "contract_version": CONTRACT_VERSION,
            "record_id": f"scan-{uuid4()}",
            "record_type": RECORD_TYPE,
            "correlation_id": request.correlation_id,
            "producer": {"id": self.scanner.config.producer_id, "authoritative": True},
            "scope": {"resource_type": request.resource_type, "resource_id": request.resource_id},
            "observed_at": finding.observed_at.isoformat(),
            "valid_until": finding.valid_until.isoformat(),
            "result": finding.result,
            "evidence_refs": list(finding.evidence_refs),
        }
        envelope = {
            "resource_id": request.resource_id,
            "resource_digest_sha256": actual_digest,
            "scan_record": record,
        }
        self.replay_ledger.finalize(request, auth_digest, envelope)
        return envelope
