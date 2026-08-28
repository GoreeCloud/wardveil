#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping

from reference.wardveil_clamav import ClamAVClient
from reference.wardveil_clamav_runtime import collect_clamav_health, config_from_env, policy_from_env
from reference.wardveil_scan_transport import (
    AuthenticatedScanService,
    CallerCredential,
    ScanTransportError,
    ScanTransportRequest,
)

HEADER_MAP = {
    "caller_id": "X-Wardveil-Caller-ID",
    "key_id": "X-Wardveil-Key-ID",
    "timestamp": "X-Wardveil-Timestamp",
    "nonce": "X-Wardveil-Nonce",
    "action": "X-Wardveil-Action",
    "resource_type": "X-Wardveil-Resource-Type",
    "resource_id": "X-Wardveil-Resource-ID",
    "correlation_id": "X-Wardveil-Correlation-ID",
    "content_sha256": "X-Wardveil-Content-SHA256",
    "signature": "X-Wardveil-Signature",
}


def _credential_map(env: Mapping[str, str] | None = None) -> dict[tuple[str, str], CallerCredential]:
    env = env or os.environ
    raw = env.get("WARDVEIL_SCAN_CALLERS_JSON", "").strip()
    if not raw:
        raise ValueError("WARDVEIL_SCAN_CALLERS_JSON is required")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("WARDVEIL_SCAN_CALLERS_JSON must be valid JSON") from exc
    if not isinstance(payload, list) or not payload:
        raise ValueError("WARDVEIL_SCAN_CALLERS_JSON must contain at least one caller")
    result: dict[tuple[str, str], CallerCredential] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("scan caller entry must be an object")
        secret = str(item.get("secret", "")).encode("utf-8")
        credential = CallerCredential(
            caller_id=str(item.get("caller_id", "")),
            key_id=str(item.get("key_id", "")),
            secret=secret,
            resource_types=frozenset(str(value) for value in item.get("resource_types", [])),
            active=bool(item.get("active", True)),
        )
        credential.validate()
        key = (credential.caller_id, credential.key_id)
        if key in result:
            raise ValueError("duplicate scan caller/key identity")
        result[key] = credential
    return result


def _build_service() -> AuthenticatedScanService:
    clamav_config = config_from_env()
    scanner = ClamAVClient(clamav_config)
    policy = policy_from_env()
    return AuthenticatedScanService(
        scanner=scanner,
        health_provider=lambda: collect_clamav_health(scanner, policy=policy),
        credentials=_credential_map(),
        max_clock_skew_seconds=int(os.environ.get("WARDVEIL_SCAN_MAX_CLOCK_SKEW_SECONDS", "60")),
        max_body_bytes=int(os.environ.get("WARDVEIL_SCAN_MAX_BODY_BYTES", str(clamav_config.max_stream_bytes))),
    )


class Handler(BaseHTTPRequestHandler):
    service: AuthenticatedScanService
    server_version = "WardveilScan/0.9"
    sys_version = ""

    def log_message(self, _format: str, *_args) -> None:
        # Do not emit resource identifiers, authentication headers, signatures,
        # filenames, URLs, or raw content through the default request logger.
        return

    def _json(self, status: int, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._json(404, {"error": "not_found"})
            return
        self._json(200, {"service": "Wardveil Scan", "status": "ok", "production_runtime_status": "unaccepted"})

    def do_POST(self) -> None:
        if self.path != "/v1/scan":
            self._json(404, {"error": "not_found"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/octet-stream":
            self._json(415, {"error": "scan_request_rejected"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._json(400, {"error": "scan_request_rejected"})
            return
        if content_length < 0 or content_length > self.service.max_body_bytes:
            self._json(413, {"error": "scan_request_rejected"})
            return
        body = self.rfile.read(content_length)
        try:
            values = {key: self.headers.get(header, "").strip() for key, header in HEADER_MAP.items()}
            request = ScanTransportRequest(content_length=content_length, **values)
            envelope = self.service.scan(request, body)
        except (ScanTransportError, ValueError):
            self._json(401, {"error": "scan_request_rejected"})
            return
        self._json(200, envelope)


def _parse_bind(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise ValueError("WARDVEIL_SCAN_BIND must be host:port")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError("WARDVEIL_SCAN_BIND port invalid")
    if host not in {"127.0.0.1", "::1", "localhost"} and os.environ.get("WARDVEIL_SCAN_ALLOW_NON_LOOPBACK", "false").lower() != "true":
        raise ValueError("non-loopback scan bind requires WARDVEIL_SCAN_ALLOW_NON_LOOPBACK=true")
    return host, port


def main() -> None:
    service = _build_service()
    Handler.service = service
    host, port = _parse_bind(os.environ.get("WARDVEIL_SCAN_BIND", "127.0.0.1:8788"))
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
