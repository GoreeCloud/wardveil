"""Authenticated loopback HTTP transport for Wardveil Scan.

The service keeps ClamAV behind Wardveil, binds only to loopback, authenticates
each request against caller-scoped credentials, binds authentication to exact
resource metadata and content digest, and returns the consumer-facing Wardveil
``scan_finding`` envelope. Raw bytes are processed in memory only and are not
included in responses or shared evidence records.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Mapping
from uuid import uuid4

from reference.wardveil_clamav import ClamAVClient, ClamAVVerdict
from reference.wardveil_clamav_runtime import (
    ClamAVRuntimePolicy,
    collect_clamav_health,
    config_from_env,
    gate_clamav_verdict,
    policy_from_env,
)
from reference.wardveil_detect_scan import ScanFinding

SCAN_PATH = "/v1/scan"
HEALTH_PATH = "/healthz"
READINESS_PATH = "/readyz"
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_SCAN_SERVICE_PORT = 8791
DEFAULT_MAX_CONCURRENT_SCANS = 8
DEFAULT_REPLAY_MAX_ENTRIES = 4096
DEFAULT_REPLAY_TTL_SECONDS = 180
REQUEST_BODY_TIMEOUT_SECONDS = 30.0
MAX_RESOURCE_ID_BYTES = 1024
MAX_CALLER_SECRET_BYTES = 4096
MAX_CLOCK_SKEW_SECONDS = 60
CONTRACT_VERSION = "0.1.0"
RECORD_TYPE = "scan_finding"
SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-transport"
SUPPORTED_RESOURCE_TYPES = frozenset(
    {"mail_attachment", "drive_file", "browser_download", "ai_artifact"}
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_:-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ScanServiceRequestError(ValueError):
    def __init__(self, code: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class CallerCredential:
    caller_id: str
    key_id: str
    secret: bytes
    resource_types: frozenset[str]
    active: bool = True

    def validate(self) -> None:
        if not _TOKEN_RE.fullmatch(self.caller_id):
            raise ValueError("scan caller id is invalid")
        if not _TOKEN_RE.fullmatch(self.key_id):
            raise ValueError("scan key id is invalid")
        if len(self.secret) < 32 or len(self.secret) > MAX_CALLER_SECRET_BYTES:
            raise ValueError("scan caller secret must be between 32 and 4096 bytes")
        if not self.resource_types or not self.resource_types <= SUPPORTED_RESOURCE_TYPES:
            raise ValueError("scan caller resource types are invalid")


@dataclass(frozen=True)
class ScanServiceRequest:
    caller_id: str
    key_id: str
    timestamp: str
    nonce: str
    resource_type: str
    resource_id: str
    digest_sha256: str
    size_bytes: int
    action: str
    correlation_id: str
    signature: str

    def validate(self, *, max_stream_bytes: int) -> None:
        for value, code in (
            (self.caller_id, "caller_id_invalid"),
            (self.key_id, "key_id_invalid"),
            (self.nonce, "nonce_invalid"),
            (self.correlation_id, "correlation_id_invalid"),
        ):
            if not _TOKEN_RE.fullmatch(value):
                raise ScanServiceRequestError(code)
        if self.resource_type not in SUPPORTED_RESOURCE_TYPES:
            raise ScanServiceRequestError("resource_type_unsupported")
        encoded_id = self.resource_id.encode("utf-8", errors="strict")
        if (
            not self.resource_id
            or len(encoded_id) > MAX_RESOURCE_ID_BYTES
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.resource_id)
        ):
            raise ScanServiceRequestError("resource_id_invalid")
        if not _SHA256_RE.fullmatch(self.digest_sha256):
            raise ScanServiceRequestError("resource_digest_invalid")
        if self.size_bytes < 0:
            raise ScanServiceRequestError("resource_size_invalid")
        if self.size_bytes > max_stream_bytes:
            raise ScanServiceRequestError(
                "resource_stream_limit_exceeded", HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            )
        if not _ACTION_RE.fullmatch(self.action):
            raise ScanServiceRequestError("action_invalid")
        if not _SHA256_RE.fullmatch(self.signature):
            raise ScanServiceRequestError("signature_invalid", HTTPStatus.UNAUTHORIZED)
        parse_request_timestamp(self.timestamp)


@dataclass(frozen=True)
class ReplayEntry:
    request_digest: str
    expires_at: datetime
    response: dict | None = None


@dataclass
class InMemoryReplayLedger:
    max_entries: int = DEFAULT_REPLAY_MAX_ENTRIES
    ttl: timedelta = field(
        default_factory=lambda: timedelta(seconds=DEFAULT_REPLAY_TTL_SECONDS)
    )
    entries: dict[tuple[str, str, str], ReplayEntry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            raise ValueError("scan replay max entries must be positive")
        if self.ttl <= timedelta(0):
            raise ValueError("scan replay TTL must be positive")

    def _prune_locked(self, now: datetime) -> None:
        expired = [key for key, entry in self.entries.items() if entry.expires_at <= now]
        for key in expired:
            self.entries.pop(key, None)

    def claim(
        self,
        request: ScanServiceRequest,
        request_digest: str,
        *,
        now: datetime,
    ) -> tuple[str, dict | None]:
        key = (request.caller_id, request.key_id, request.nonce)
        with self._lock:
            self._prune_locked(now)
            current = self.entries.get(key)
            if current is None:
                if len(self.entries) >= self.max_entries:
                    return "capacity", None
                self.entries[key] = ReplayEntry(
                    request_digest=request_digest,
                    expires_at=now + self.ttl,
                )
                return "new", None
            if current.request_digest != request_digest:
                return "conflict", None
            if current.response is None:
                return "pending", None
            return "exact_replay", dict(current.response)

    def finalize(
        self,
        request: ScanServiceRequest,
        request_digest: str,
        response: dict,
        *,
        now: datetime,
    ) -> None:
        key = (request.caller_id, request.key_id, request.nonce)
        with self._lock:
            self._prune_locked(now)
            current = self.entries.get(key)
            if current is None or current.request_digest != request_digest:
                raise RuntimeError("scan_replay_claim_lost")
            self.entries[key] = ReplayEntry(
                request_digest=request_digest,
                expires_at=current.expires_at,
                response=dict(response),
            )


def parse_request_timestamp(value: str) -> datetime:
    if value != value.strip():
        raise ScanServiceRequestError("request_timestamp_invalid", HTTPStatus.UNAUTHORIZED)
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ScanServiceRequestError("request_timestamp_invalid", HTTPStatus.UNAUTHORIZED) from exc
    if parsed.tzinfo is None:
        raise ScanServiceRequestError("request_timestamp_invalid", HTTPStatus.UNAUTHORIZED)
    return parsed.astimezone(timezone.utc)


def canonical_auth_material(request: ScanServiceRequest) -> bytes:
    return "\n".join(
        (
            CONTRACT_VERSION,
            request.caller_id,
            request.key_id,
            request.timestamp,
            request.nonce,
            request.action,
            request.resource_type,
            request.resource_id,
            request.correlation_id,
            str(request.size_bytes),
            request.digest_sha256,
        )
    ).encode("utf-8")


def sign_scan_request(request: ScanServiceRequest, secret: bytes) -> str:
    return hmac.new(secret, canonical_auth_material(request), hashlib.sha256).hexdigest()


def credentials_from_json(raw: str) -> dict[tuple[str, str], CallerCredential]:
    if not raw.strip():
        raise ValueError("Wardveil Scan caller credential file is empty")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Wardveil Scan caller credential file must be valid JSON") from exc
    if not isinstance(payload, list) or not payload:
        raise ValueError("Wardveil Scan caller credential file must contain at least one caller")
    result: dict[tuple[str, str], CallerCredential] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("scan caller entry must be an object")
        resource_types = item.get("resource_types")
        if not isinstance(resource_types, list) or not all(
            isinstance(value, str) for value in resource_types
        ):
            raise ValueError("scan caller resource_types must be a list of strings")
        secret = item.get("secret")
        if not isinstance(secret, str):
            raise ValueError("scan caller secret must be a string")
        active = item.get("active", True)
        if not isinstance(active, bool):
            raise ValueError("scan caller active flag must be boolean")
        credential = CallerCredential(
            caller_id=str(item.get("caller_id", "")),
            key_id=str(item.get("key_id", "")),
            secret=secret.encode("utf-8"),
            resource_types=frozenset(resource_types),
            active=active,
        )
        credential.validate()
        key = (credential.caller_id, credential.key_id)
        if key in result:
            raise ValueError("duplicate scan caller/key identity")
        result[key] = credential
    return result


class WardveilScanService:
    def __init__(
        self,
        *,
        credentials: Mapping[tuple[str, str], CallerCredential],
        client: ClamAVClient | None = None,
        policy: ClamAVRuntimePolicy | None = None,
        replay_ledger: InMemoryReplayLedger | None = None,
        now: Callable[[], datetime] | None = None,
        max_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
    ):
        self.client = client or ClamAVClient(config_from_env())
        self.policy = policy or policy_from_env()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.credentials = dict(credentials)
        if not self.credentials:
            raise ValueError("at least one Wardveil Scan caller credential is required")
        for credential in self.credentials.values():
            credential.validate()
        if max_clock_skew_seconds < 1:
            raise ValueError("max scan clock skew must be positive")
        self.max_clock_skew = timedelta(seconds=max_clock_skew_seconds)
        self.replay_ledger = replay_ledger or InMemoryReplayLedger()

    @property
    def max_stream_bytes(self) -> int:
        return self.client.config.max_stream_bytes

    def readiness(self) -> tuple[bool, dict]:
        """Return bounded scanner readiness without granting protection authority."""
        observed_now = self.now()
        if observed_now.tzinfo is None:
            raise ValueError("Wardveil Scan clock must be timezone-aware")
        observed_now = observed_now.astimezone(timezone.utc)
        health = collect_clamav_health(
            self.client,
            policy=self.policy,
            now=observed_now,
        )
        current = health.observed_at <= observed_now < health.valid_until
        ready = health.clean_verdicts_eligible and current
        payload = {
            "status": "ready" if ready else "not_ready",
            "component": "Wardveil Scan authenticated transport",
            "scanner_runtime_state": health.runtime_state,
            "signature_freshness": health.signature_freshness,
            "production_runtime_status": "unaccepted",
            "protection_claim_authority": False,
        }
        if not ready:
            payload["reason_codes"] = list(health.degraded_reasons) or [
                "scanner_health_not_acceptable_for_clean_verdict"
            ]
        return ready, payload

    def authenticate_request(
        self,
        request: ScanServiceRequest,
        *,
        now: datetime | None = None,
    ) -> datetime:
        request.validate(max_stream_bytes=self.max_stream_bytes)
        credential = self.credentials.get((request.caller_id, request.key_id))
        if credential is None or not credential.active:
            raise ScanServiceRequestError("scan_caller_not_authorized", HTTPStatus.UNAUTHORIZED)
        if request.resource_type not in credential.resource_types:
            raise ScanServiceRequestError("scan_resource_type_not_authorized", HTTPStatus.FORBIDDEN)

        observed_now = now if now is not None else self.now()
        if observed_now.tzinfo is None:
            raise ValueError("Wardveil Scan clock must be timezone-aware")
        observed_now = observed_now.astimezone(timezone.utc)
        signed_at = parse_request_timestamp(request.timestamp)
        if abs(observed_now - signed_at) > self.max_clock_skew:
            raise ScanServiceRequestError(
                "scan_request_timestamp_outside_window", HTTPStatus.UNAUTHORIZED
            )
        expected_signature = sign_scan_request(request, credential.secret)
        if not hmac.compare_digest(expected_signature, request.signature):
            raise ScanServiceRequestError("scan_signature_invalid", HTTPStatus.UNAUTHORIZED)
        return observed_now

    def scan(self, request: ScanServiceRequest, content: bytes) -> dict:
        observed_now = self.authenticate_request(request)
        if len(content) != request.size_bytes:
            raise ScanServiceRequestError("resource_size_mismatch")
        actual_digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual_digest, request.digest_sha256):
            raise ScanServiceRequestError(
                "resource_digest_mismatch", HTTPStatus.UNPROCESSABLE_ENTITY
            )

        request_digest = hashlib.sha256(
            canonical_auth_material(request) + b"\n" + request.signature.encode("ascii")
        ).hexdigest()
        replay_state, cached = self.replay_ledger.claim(
            request,
            request_digest,
            now=observed_now,
        )
        if replay_state == "capacity":
            raise ScanServiceRequestError(
                "scan_replay_capacity_exhausted", HTTPStatus.SERVICE_UNAVAILABLE
            )
        if replay_state == "conflict":
            raise ScanServiceRequestError("scan_nonce_conflict", HTTPStatus.CONFLICT)
        if replay_state == "pending":
            raise ScanServiceRequestError("scan_request_already_in_progress", HTTPStatus.CONFLICT)
        if replay_state == "exact_replay":
            return dict(cached or {})

        health = collect_clamav_health(
            self.client,
            policy=self.policy,
            now=observed_now,
        )
        verdict: ClamAVVerdict = self.client.scan_bytes(content)
        finding = gate_clamav_verdict(
            verdict,
            health,
            resource_id=request.resource_id,
            producer_id=self.client.config.producer_id,
            now=observed_now,
        )
        finding = _with_required_health_evidence(finding, health.evidence_ref)

        record = {
            "contract_version": CONTRACT_VERSION,
            "record_id": f"scan-{uuid4()}",
            "record_type": RECORD_TYPE,
            "correlation_id": request.correlation_id,
            "producer": {
                "id": self.client.config.producer_id,
                "authoritative": True,
            },
            "scope": {
                "resource_type": request.resource_type,
                "resource_id": request.resource_id,
            },
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
        self.replay_ledger.finalize(
            request,
            request_digest,
            envelope,
            now=observed_now,
        )
        return envelope


def _with_required_health_evidence(finding: ScanFinding, health_ref: str) -> ScanFinding:
    evidence = tuple(dict.fromkeys((*finding.evidence_refs, health_ref)))
    return ScanFinding(
        finding.result,
        finding.reason_codes,
        evidence,
        finding.observed_at,
        finding.valid_until,
    )


def build_http_server(
    service: WardveilScanService,
    *,
    port: int = DEFAULT_SCAN_SERVICE_PORT,
    max_concurrent_scans: int = DEFAULT_MAX_CONCURRENT_SCANS,
) -> ThreadingHTTPServer:
    if port <= 0 or port > 65535:
        raise ValueError("scan service port must be between 1 and 65535")
    if max_concurrent_scans < 1:
        raise ValueError("max concurrent scans must be positive")
    scan_slots = threading.BoundedSemaphore(max_concurrent_scans)

    class Handler(BaseHTTPRequestHandler):
        server_version = "WardveilScan"
        sys_version = ""

        def log_message(self, _format: str, *_args: object) -> None:
            # Resource IDs and authentication-bound metadata are intentionally
            # absent from the default access log.
            return

        def do_GET(self) -> None:
            if self.path == HEALTH_PATH:
                self._json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "component": "Wardveil Scan authenticated transport",
                        "production_runtime_status": "unaccepted",
                        "protection_claim_authority": False,
                    },
                )
                return
            if self.path == READINESS_PATH:
                ready, payload = service.readiness()
                self._json(HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE, payload)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != SCAN_PATH:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                request, content_length = self._scan_request_headers(
                    service.max_stream_bytes
                )
                # Reject unauthenticated or out-of-scope callers before reading
                # the declared payload body into memory.
                service.authenticate_request(request)
            except ScanServiceRequestError as exc:
                self._json(exc.status, {"error": "scan_request_rejected"})
                return

            if not scan_slots.acquire(blocking=False):
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "scan_service_busy"})
                return
            try:
                self.connection.settimeout(REQUEST_BODY_TIMEOUT_SECONDS)
                try:
                    content = self.rfile.read(content_length)
                except (OSError, TimeoutError) as exc:
                    raise ScanServiceRequestError(
                        "request_body_timeout", HTTPStatus.REQUEST_TIMEOUT
                    ) from exc
                if len(content) != content_length:
                    raise ScanServiceRequestError("request_body_incomplete")
                payload = service.scan(request, content)
            except ScanServiceRequestError as exc:
                self._json(exc.status, {"error": "scan_request_rejected"})
                return
            finally:
                scan_slots.release()
            self._json(HTTPStatus.OK, payload)

        def _scan_request_headers(
            self,
            max_stream_bytes: int,
        ) -> tuple[ScanServiceRequest, int]:
            if self.headers.get("Transfer-Encoding"):
                raise ScanServiceRequestError("transfer_encoding_not_supported")
            if self.headers.get_content_type() != "application/octet-stream":
                raise ScanServiceRequestError("content_type_invalid")

            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise ScanServiceRequestError("content_length_required")
            try:
                content_length = int(raw_length)
            except ValueError as exc:
                raise ScanServiceRequestError("content_length_invalid") from exc
            if content_length < 0:
                raise ScanServiceRequestError("content_length_invalid")
            if content_length > max_stream_bytes:
                raise ScanServiceRequestError(
                    "resource_stream_limit_exceeded", HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                )

            try:
                size_bytes = int(self.headers.get("X-Wardveil-Size-Bytes", ""))
            except ValueError as exc:
                raise ScanServiceRequestError("resource_size_invalid") from exc

            request = ScanServiceRequest(
                caller_id=self.headers.get("X-Wardveil-Caller-ID", ""),
                key_id=self.headers.get("X-Wardveil-Key-ID", ""),
                timestamp=self.headers.get("X-Wardveil-Timestamp", ""),
                nonce=self.headers.get("X-Wardveil-Nonce", ""),
                resource_type=self.headers.get("X-Wardveil-Resource-Type", ""),
                resource_id=self.headers.get("X-Wardveil-Resource-ID", ""),
                digest_sha256=self.headers.get("X-Wardveil-Digest-SHA256", "").lower(),
                size_bytes=size_bytes,
                action=self.headers.get("X-Wardveil-Action", ""),
                correlation_id=self.headers.get("X-Wardveil-Correlation-ID", ""),
                signature=self.headers.get("X-Wardveil-Signature", "").lower(),
            )
            request.validate(max_stream_bytes=max_stream_bytes)
            if content_length != request.size_bytes:
                raise ScanServiceRequestError("resource_size_mismatch")
            return request, content_length

        def _json(self, status: HTTPStatus, payload: dict) -> None:
            encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    return Server((LOOPBACK_HOST, port), Handler)
