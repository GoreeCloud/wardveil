"""Authenticated loopback HTTP transport for Wardveil Scan.

The service keeps ClamAV behind Wardveil, binds only to loopback, authenticates
each scan request, and returns canonical Wardveil ``scan_finding`` records.
Raw resource bytes are processed in memory only and are not included in
responses or shared evidence records.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from uuid import uuid4

from reference.wardveil_clamav import ClamAVClient, ClamAVVerdict
from reference.wardveil_clamav_runtime import (
    ClamAVRuntimePolicy,
    collect_clamav_health,
    config_from_env,
    gate_clamav_verdict,
    policy_from_env,
)
from reference.wardveil_detect_scan import ScanFinding, ScanInput

SCAN_PATH = "/v1/scan"
HEALTH_PATH = "/healthz"
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_SCAN_SERVICE_PORT = 8791
MAX_RESOURCE_ID_BYTES = 512
MAX_TOKEN_BYTES = 4096
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_:-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ScanServiceRequestError(ValueError):
    def __init__(self, code: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class ScanServiceRequest:
    resource_type: str
    resource_id: str
    digest_sha256: str
    size_bytes: int
    action: str

    def validate(self, *, max_stream_bytes: int) -> None:
        if not _TOKEN_RE.fullmatch(self.resource_type):
            raise ScanServiceRequestError("resource_type_invalid")
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


class WardveilScanService:
    def __init__(
        self,
        *,
        client: ClamAVClient | None = None,
        policy: ClamAVRuntimePolicy | None = None,
        now: Callable[[], datetime] | None = None,
    ):
        self.client = client or ClamAVClient(config_from_env())
        self.policy = policy or policy_from_env()
        self.now = now or (lambda: datetime.now(timezone.utc))

    @property
    def max_stream_bytes(self) -> int:
        return self.client.config.max_stream_bytes

    def scan(self, request: ScanServiceRequest, content: bytes) -> dict:
        request.validate(max_stream_bytes=self.max_stream_bytes)
        if len(content) != request.size_bytes:
            raise ScanServiceRequestError("resource_size_mismatch")
        actual_digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(actual_digest.lower(), request.digest_sha256.lower()):
            raise ScanServiceRequestError(
                "resource_digest_mismatch", HTTPStatus.UNPROCESSABLE_ENTITY
            )

        health_observed = self.now().astimezone(timezone.utc)
        health = collect_clamav_health(
            self.client,
            policy=self.policy,
            now=health_observed,
        )
        verdict: ClamAVVerdict = self.client.scan_bytes(content)
        finding_observed = self.now().astimezone(timezone.utc)
        finding = gate_clamav_verdict(
            verdict,
            health,
            resource_id=request.resource_id,
            producer_id=self.client.config.producer_id,
            now=finding_observed,
        )
        finding = _with_health_evidence(finding, health.evidence_ref)

        record_request = ScanInput(
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            producer_id=self.client.config.producer_id,
            scanner_supported=verdict.error_code != "unsupported_resource",
            scan_completed=verdict.completed,
            malware_match=verdict.malware_match,
            suspicious_content=False,
            evidence_refs=finding.evidence_refs,
        )
        record = finding.as_runtime_record(
            record_request,
            correlation_id=f"scan-request-{uuid4()}",
        )
        return {
            "resource_id": request.resource_id,
            "resource_digest_sha256": actual_digest,
            "scan_record": record,
        }


def _with_health_evidence(finding: ScanFinding, health_ref: str) -> ScanFinding:
    evidence = tuple(dict.fromkeys((*finding.evidence_refs, health_ref)))
    return ScanFinding(
        finding.result,
        finding.reason_codes,
        evidence,
        finding.observed_at,
        finding.valid_until,
    )


def validate_service_token(token: str) -> str:
    if token != token.strip() or len(token.encode("utf-8")) < 32:
        raise ValueError(
            "WARDVEIL_SCAN_SERVICE_TOKEN must be at least 32 bytes with no surrounding whitespace"
        )
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise ValueError("WARDVEIL_SCAN_SERVICE_TOKEN is unreasonably large")
    return token


def build_http_server(
    service: WardveilScanService,
    token: str,
    *,
    port: int = DEFAULT_SCAN_SERVICE_PORT,
) -> ThreadingHTTPServer:
    token = validate_service_token(token)
    if port <= 0 or port > 65535:
        raise ValueError("scan service port must be between 1 and 65535")

    class Handler(BaseHTTPRequestHandler):
        server_version = "WardveilScan"
        sys_version = ""

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path != HEALTH_PATH:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "component": "Wardveil Scan authenticated transport",
                    "protection_claim_authority": False,
                },
            )

        def do_POST(self) -> None:
            if self.path != SCAN_PATH:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if not self._authorized(token):
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                request, content = self._scan_request(service.max_stream_bytes)
                payload = service.scan(request, content)
            except ScanServiceRequestError as exc:
                self._json(exc.status, {"error": exc.code})
                return
            self._json(HTTPStatus.OK, payload)

        def _authorized(self, expected_token: str) -> bool:
            value = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not value.startswith(prefix):
                return False
            supplied = value[len(prefix) :]
            return hmac.compare_digest(
                supplied.encode("utf-8"), expected_token.encode("utf-8")
            )

        def _scan_request(self, max_stream_bytes: int) -> tuple[ScanServiceRequest, bytes]:
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

            raw_size = self.headers.get("X-Wardveil-Size-Bytes", "")
            try:
                size_bytes = int(raw_size)
            except ValueError as exc:
                raise ScanServiceRequestError("resource_size_invalid") from exc

            request = ScanServiceRequest(
                resource_type=self.headers.get("X-Wardveil-Resource-Type", ""),
                resource_id=self.headers.get("X-Wardveil-Resource-ID", ""),
                digest_sha256=self.headers.get("X-Wardveil-Digest-SHA256", ""),
                size_bytes=size_bytes,
                action=self.headers.get("X-Wardveil-Action", ""),
            )
            request.validate(max_stream_bytes=max_stream_bytes)
            if content_length != request.size_bytes:
                raise ScanServiceRequestError("resource_size_mismatch")
            content = self.rfile.read(content_length)
            if len(content) != content_length:
                raise ScanServiceRequestError("request_body_incomplete")
            return request, content

        def _json(self, status: HTTPStatus, payload: dict) -> None:
            encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    return Server((LOOPBACK_HOST, port), Handler)
