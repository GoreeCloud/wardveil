#!/usr/bin/env python3
"""ClamAV adapter for Wardveil Scan.

This adapter treats ClamAV as a replaceable malware-scanning engine beneath
Wardveil Security. It streams bytes to ``clamd`` using the documented INSTREAM
protocol and converts daemon replies into Wardveil Scan evidence without
performing quarantine, deletion, or remediation itself.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from reference.wardveil_detect_scan import ScanFinding, ScanInput, evaluate_scan

DEFAULT_MAX_STREAM_BYTES = 25 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ClamAVConfig:
    unix_socket: str | None = "/run/clamav/clamd.ctl"
    tcp_host: str | None = None
    tcp_port: int = 3310
    timeout_seconds: float = 30.0
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    producer_id: str = "wardveil-scan-clamav"

    def validate(self) -> None:
        if bool(self.unix_socket) == bool(self.tcp_host):
            raise ValueError("configure exactly one ClamAV transport: unix_socket or tcp_host")
        if self.tcp_port <= 0 or self.tcp_port > 65535:
            raise ValueError("tcp_port must be between 1 and 65535")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_stream_bytes <= 0:
            raise ValueError("max_stream_bytes must be positive")
        if self.chunk_bytes <= 0 or self.chunk_bytes > 1024 * 1024:
            raise ValueError("chunk_bytes must be between 1 and 1048576")


@dataclass(frozen=True)
class ClamAVVerdict:
    completed: bool
    malware_match: bool
    signature: str | None = None
    raw_reply: str | None = None
    error_code: str | None = None
    digest_sha256: str | None = None

    @property
    def evidence_ref(self) -> str | None:
        if not self.digest_sha256:
            return None
        if self.malware_match and self.signature:
            return f"clamav:sha256:{self.digest_sha256}:found:{self.signature}"
        if self.completed:
            return f"clamav:sha256:{self.digest_sha256}:clean"
        if self.error_code:
            return f"clamav:sha256:{self.digest_sha256}:error:{self.error_code}"
        return f"clamav:sha256:{self.digest_sha256}:unknown"


class ClamAVProtocolError(RuntimeError):
    """Raised when clamd returns an unexpected or malformed protocol response."""


class ClamAVClient:
    def __init__(self, config: ClamAVConfig | None = None):
        self.config = config or ClamAVConfig()
        self.config.validate()

    def _connect(self) -> socket.socket:
        if self.config.unix_socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout_seconds)
            sock.connect(self.config.unix_socket)
            return sock
        return socket.create_connection(
            (self.config.tcp_host or "127.0.0.1", self.config.tcp_port),
            timeout=self.config.timeout_seconds,
        )

    @staticmethod
    def _read_reply(sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\0" in data or b"\n" in data:
                break
        if not chunks:
            raise ClamAVProtocolError("clamd returned an empty response")
        return b"".join(chunks).rstrip(b"\0\r\n").decode("utf-8", errors="replace")

    def ping(self) -> bool:
        with self._connect() as sock:
            sock.sendall(b"zPING\0")
            return self._read_reply(sock).strip() == "PONG"

    def version(self) -> str:
        with self._connect() as sock:
            sock.sendall(b"zVERSION\0")
            reply = self._read_reply(sock).strip()
            if not reply:
                raise ClamAVProtocolError("clamd returned an empty version")
            return reply

    def _scan_bytes_over_socket(self, sock: socket.socket, data: bytes) -> ClamAVVerdict:
        if len(data) > self.config.max_stream_bytes:
            digest = hashlib.sha256(data).hexdigest()
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code="wardveil_stream_limit_exceeded",
                digest_sha256=digest,
            )

        digest = hashlib.sha256(data).hexdigest()
        sock.sendall(b"zINSTREAM\0")
        view = memoryview(data)
        for offset in range(0, len(data), self.config.chunk_bytes):
            chunk = view[offset : offset + self.config.chunk_bytes]
            sock.sendall(struct.pack("!I", len(chunk)))
            sock.sendall(chunk)
        sock.sendall(struct.pack("!I", 0))
        reply = self._read_reply(sock)
        return parse_scan_reply(reply, digest_sha256=digest)

    def scan_bytes(self, data: bytes) -> ClamAVVerdict:
        try:
            with self._connect() as sock:
                return self._scan_bytes_over_socket(sock, data)
        except (OSError, TimeoutError, ClamAVProtocolError) as exc:
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code=f"clamd_unavailable:{exc.__class__.__name__}",
                digest_sha256=hashlib.sha256(data).hexdigest(),
            )

    def scan_file(self, path: str | Path) -> ClamAVVerdict:
        target = Path(path)
        if not target.is_file():
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code="unsupported_resource",
            )
        try:
            size = target.stat().st_size
            if size > self.config.max_stream_bytes:
                return ClamAVVerdict(
                    completed=False,
                    malware_match=False,
                    error_code="wardveil_stream_limit_exceeded",
                    digest_sha256=_sha256_file(target),
                )
            return self.scan_bytes(target.read_bytes())
        except OSError as exc:
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code=f"file_read_error:{exc.__class__.__name__}",
            )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(DEFAULT_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_scan_reply(reply: str, *, digest_sha256: str | None = None) -> ClamAVVerdict:
    text = reply.strip().rstrip("\0")
    if not text:
        raise ClamAVProtocolError("empty clamd scan response")

    if text.endswith(" OK") or text == "stream: OK":
        return ClamAVVerdict(
            completed=True,
            malware_match=False,
            raw_reply=text,
            digest_sha256=digest_sha256,
        )

    if text.endswith(" FOUND"):
        payload = text[:-6].strip()
        signature = payload.split(":", 1)[1].strip() if ":" in payload else payload
        if not signature:
            raise ClamAVProtocolError("clamd FOUND response did not include a signature")
        return ClamAVVerdict(
            completed=True,
            malware_match=True,
            signature=signature,
            raw_reply=text,
            digest_sha256=digest_sha256,
        )

    if text.endswith(" ERROR"):
        message = text[:-6].strip()
        return ClamAVVerdict(
            completed=False,
            malware_match=False,
            raw_reply=text,
            error_code=_normalize_error(message),
            digest_sha256=digest_sha256,
        )

    raise ClamAVProtocolError(f"unrecognized clamd response: {text!r}")


def _normalize_error(message: str) -> str:
    normalized = "_".join(message.lower().replace(":", " ").split())
    return f"clamd_error:{normalized[:160] or 'unknown'}"


def verdict_to_scan_input(
    verdict: ClamAVVerdict,
    *,
    resource_id: str,
    producer_id: str = "wardveil-scan-clamav",
) -> ScanInput:
    evidence_refs = (verdict.evidence_ref,) if verdict.evidence_ref else ()
    supported = verdict.error_code != "unsupported_resource"
    return ScanInput(
        resource_type="file",
        resource_id=resource_id,
        producer_id=producer_id,
        scanner_supported=supported,
        scan_completed=verdict.completed,
        malware_match=verdict.malware_match,
        suspicious_content=False,
        evidence_refs=evidence_refs,
    )


def scan_file_as_wardveil(
    path: str | Path,
    *,
    client: ClamAVClient | None = None,
    resource_id: str | None = None,
) -> ScanFinding:
    scanner = client or ClamAVClient()
    verdict = scanner.scan_file(path)
    request = verdict_to_scan_input(
        verdict,
        resource_id=resource_id or str(Path(path)),
        producer_id=scanner.config.producer_id,
    )
    return evaluate_scan(request)
