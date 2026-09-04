#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_platform_registry_delivery import publish_platform_record


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Platform Registry delivery test failed: {message}")


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


record = {
    "schema": "goreecloud.mesh.platform-record.v1",
    "source": {
        "repository": "GoreeCloud/goreecloud-wardveil-security",
        "revision": "c" * 40,
        "contract_schema_version": "0.2",
        "authority_transfer": False,
    },
    "component": {
        "id": "goreecloud-wardveil-security",
        "product_name": "Wardveil Security by GoreeCloud",
        "kind": "service",
        "repository": "GoreeCloud/goreecloud-wardveil-security",
        "lifecycle": "development",
        "version": "0.9.0",
        "supported_platforms": ["linux-server"],
    },
}
provider_calls = []
received = {}


class AcceptedHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        received["path"] = self.path
        received["authorization"] = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", "0"))
        received["record"] = json.loads(self.rfile.read(length).decode("utf-8"))
        payload = {
            "record": received["record"],
            "accepted_at": "2026-09-04T06:45:00Z",
            "producer_service_id": "goreecloud-wardveil-security",
            "authority_transfer": False,
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server, thread = start_server(AcceptedHandler)
try:
    receipt = publish_platform_record(
        record,
        mesh_base_url=f"http://127.0.0.1:{server.server_port}",
        credential_provider=lambda requested: provider_calls.append(requested) or "wardveil-registry-token",
    )
finally:
    server.shutdown(); server.server_close(); thread.join(timeout=2)

expected_request = {
    "service_id": "goreecloud-wardveil-security",
    "audience": "goreecloud-mesh",
    "scopes": ("mesh.platform-registry.write",),
}
if provider_calls != [expected_request]:
    fail(f"unexpected Identity credential request: {provider_calls!r}")
if received.get("path") != "/v1/platform-registry":
    fail("publisher used the wrong Mesh endpoint")
if received.get("authorization") != "Bearer wardveil-registry-token":
    fail("publisher did not use the scoped Identity credential")
if received.get("record") != record:
    fail("publisher changed the producer-owned platform record")
if receipt != {
    "component_id": "goreecloud-wardveil-security",
    "accepted_at": "2026-09-04T06:45:00Z",
    "producer_service_id": "goreecloud-wardveil-security",
    "authority_transfer": False,
}:
    fail(f"unexpected receipt: {receipt!r}")
if "wardveil-registry-token" in json.dumps(receipt):
    fail("credential leaked into receipt")

invalid_records = [
    {**record, "component": {**record["component"], "id": "goreecloud-manager"}},
    {**record, "source": {**record["source"], "authority_transfer": True}},
    {**record, "source": {**record["source"], "revision": "NOT-A-GIT-REVISION"}},
]
for invalid in invalid_records:
    try:
        publish_platform_record(
            invalid,
            mesh_base_url="https://mesh.example.test",
            bearer_token="never-sent",
        )
    except ValueError:
        pass
    else:
        fail("invalid producer record must fail before transport")

try:
    publish_platform_record(
        record,
        mesh_base_url="http://mesh.example.test",
        credential_provider=lambda _request: (_ for _ in ()).throw(
            RuntimeError("provider-should-not-have-run")
        ),
    )
except ValueError:
    pass
else:
    fail("unsafe Mesh destination must be rejected before credential acquisition")


class RejectionHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        body = json.dumps({
            "error": f"Authorization: {self.headers.get('Authorization')}",
            "error_code": "scope_denied",
        }).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


rejection_server, rejection_thread = start_server(RejectionHandler)
try:
    try:
        publish_platform_record(
            record,
            mesh_base_url=f"http://127.0.0.1:{rejection_server.server_port}",
            credential_provider=lambda _request: "wardveil-registry-reflection-secret",
        )
    except RuntimeError as exc:
        if str(exc) != "Mesh Platform Registry publication failed with HTTP 403 (scope_denied)":
            fail(f"unexpected sanitized rejection: {exc}")
        if "wardveil-registry-reflection-secret" in repr(exc):
            fail("remote rejection leaked credential material")
    else:
        fail("Mesh registry rejection must fail closed")
finally:
    rejection_server.shutdown(); rejection_server.server_close(); rejection_thread.join(timeout=2)

for bad_identity in ("bad\r\ntoken", "x" * 16_385):
    try:
        publish_platform_record(
            record,
            mesh_base_url="https://mesh.example.test",
            credential_provider=lambda _request, value=bad_identity: value,
        )
    except ValueError:
        pass
    else:
        fail("malformed or oversized Identity credential must be rejected")

print("Wardveil producer-bound Platform Registry delivery: OK")
