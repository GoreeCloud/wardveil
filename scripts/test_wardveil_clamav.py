#!/usr/bin/env python3
"""Dependency-free tests for the Wardveil ClamAV adapter."""

from __future__ import annotations

import socket
import struct
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import (  # noqa: E402
    ClamAVClient,
    ClamAVConfig,
    ClamAVVerdict,
    parse_scan_reply,
    verdict_to_scan_input,
)
from reference.wardveil_detect_scan import evaluate_scan  # noqa: E402


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def test_parse_clean_reply():
    verdict = parse_scan_reply("stream: OK", digest_sha256="abc")
    assert_equal(verdict.completed, True, "clean reply completed")
    assert_equal(verdict.malware_match, False, "clean reply malware flag")
    assert_equal(verdict.evidence_ref, "clamav:sha256:abc:clean", "clean evidence reference")


def test_parse_found_reply():
    verdict = parse_scan_reply("stream: Eicar-Signature FOUND", digest_sha256="def")
    assert_equal(verdict.completed, True, "found reply completed")
    assert_equal(verdict.malware_match, True, "found reply malware flag")
    assert_equal(verdict.signature, "Eicar-Signature", "signature extraction")


def test_error_maps_to_unknown_not_clean():
    verdict = parse_scan_reply("stream: INSTREAM size limit exceeded. ERROR", digest_sha256="ghi")
    request = verdict_to_scan_input(verdict, resource_id="file-1")
    finding = evaluate_scan(request)
    assert_equal(finding.result, "unknown", "scanner error must fail closed")


def test_unsupported_resource_stays_unsupported():
    request = verdict_to_scan_input(
        ClamAVVerdict(False, False, error_code="unsupported_resource"),
        resource_id="resource-1",
    )
    finding = evaluate_scan(request)
    assert_equal(finding.result, "unsupported", "unsupported resource must remain unsupported")


def test_instream_framing_and_found_reply():
    client = ClamAVClient(
        ClamAVConfig(
            unix_socket="/tmp/not-used",
            max_stream_bytes=1024,
            chunk_bytes=4,
        )
    )
    client_sock, server_sock = socket.socketpair()
    received = bytearray()

    def server():
        try:
            command = b""
            while not command.endswith(b"\0"):
                command += server_sock.recv(1)
            assert_equal(command, b"zINSTREAM\0", "INSTREAM command framing")
            while True:
                header = server_sock.recv(4)
                if len(header) != 4:
                    raise AssertionError("incomplete INSTREAM length header")
                length = struct.unpack("!I", header)[0]
                if length == 0:
                    break
                chunk = bytearray()
                while len(chunk) < length:
                    chunk.extend(server_sock.recv(length - len(chunk)))
                received.extend(chunk)
            server_sock.sendall(b"stream: Unit-Test-Signature FOUND\0")
        finally:
            server_sock.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        verdict = client._scan_bytes_over_socket(client_sock, b"abcdefghij")
    finally:
        client_sock.close()
        thread.join(timeout=2)
    assert_equal(bytes(received), b"abcdefghij", "streamed bytes")
    assert_equal(verdict.signature, "Unit-Test-Signature", "found signature")


def test_adapter_stream_limit_fails_closed():
    client = ClamAVClient(
        ClamAVConfig(unix_socket="/tmp/not-used", max_stream_bytes=4, chunk_bytes=4)
    )
    client_sock, server_sock = socket.socketpair()
    try:
        verdict = client._scan_bytes_over_socket(client_sock, b"12345")
    finally:
        client_sock.close()
        server_sock.close()
    assert_equal(verdict.completed, False, "oversized stream must not be complete")
    request = verdict_to_scan_input(verdict, resource_id="large-file")
    assert_equal(evaluate_scan(request).result, "unknown", "oversized stream must not be clean")


def main():
    tests = [name for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name in sorted(tests):
        globals()[name]()
    print(f"Wardveil ClamAV adapter tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
