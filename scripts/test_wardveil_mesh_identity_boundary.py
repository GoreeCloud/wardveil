#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_delivery import deliver_mesh_evidence
from reference.wardveil_mesh_evidence import create_mesh_evidence_envelope


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Mesh Identity boundary test failed: {message}")


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


now = datetime.now(timezone.utc)
record = {
    "record_id": "identity-boundary-001",
    "producer": {"id": "wardveil-policy", "authoritative": True},
    "scope": {"resource_type": "service", "resource_id": "goreecloud-mail", "component": "attachment-ingress"},
    "reason_code": "attachment_policy_satisfied",
    "valid_until": (now + timedelta(hours=1)).isoformat(),
}
envelope = create_mesh_evidence_envelope(
    record,
    revision="b" * 40,
    assertion="policy-decision",
    outcome="allow",
    observed_at=now,
)

provider_calls = []
received = {}


class AcceptedHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        received["authorization"] = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        payload = {
            "envelope": {**body, "fresh": True},
            "replayed": False,
            "accepted_at": now.isoformat().replace("+00:00", "Z"),
            "producer_service_id": "wardveil-security",
        }
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def provider(requested):
    provider_calls.append(requested)
    return "fresh-wardveil-identity-token"


server, thread = start_server(AcceptedHandler)
try:
    receipt = deliver_mesh_evidence(
        envelope,
        mesh_base_url=f"http://127.0.0.1:{server.server_port}",
        credential_provider=provider,
    )
finally:
    server.shutdown(); server.server_close(); thread.join(timeout=2)

expected_request = {
    "service_id": "wardveil-security",
    "audience": "goreecloud-mesh",
    "scopes": ("mesh.evidence.write",),
}
if provider_calls != [expected_request]:
    fail(f"unexpected Identity credential request: {provider_calls!r}")
if received.get("authorization") != "Bearer fresh-wardveil-identity-token":
    fail("fresh Identity credential was not used for delivery")
if "fresh-wardveil-identity-token" in json.dumps(receipt):
    fail("credential leaked into receipt")

try:
    deliver_mesh_evidence(
        envelope,
        mesh_base_url="https://mesh.example.test",
        bearer_token="direct",
        credential_provider=lambda _request: "provider",
    )
except ValueError as exc:
    if "either bearer_token or credential_provider" not in str(exc):
        fail("ambiguous credential error was not bounded")
else:
    fail("ambiguous credential ownership must be rejected")

for invalid in ("bad\r\ntoken", "x" * 16_385):
    try:
        deliver_mesh_evidence(
            envelope,
            mesh_base_url="https://mesh.example.test",
            credential_provider=lambda _request, value=invalid: value,
        )
    except ValueError:
        pass
    else:
        fail("malformed or oversized credential must fail before transport")

try:
    deliver_mesh_evidence(
        envelope,
        mesh_base_url="https://mesh.example.test",
        credential_provider=lambda _request: (_ for _ in ()).throw(
            RuntimeError("credential=wardveil-private-material")
        ),
    )
except RuntimeError as exc:
    if str(exc) != "GoreeCloud Identity credential acquisition failed":
        fail("provider failure message was not sanitized")
    if exc.__cause__ is not None or exc.__context__ is not None:
        fail("provider failure retained a sensitive exception chain")
    if "wardveil-private-material" in repr(exc):
        fail("provider secret leaked into local error")
else:
    fail("provider failure must fail closed")

provider_called = False

def should_not_issue(_request):
    global provider_called
    provider_called = True
    return "should-not-be-issued"

try:
    deliver_mesh_evidence(
        envelope,
        mesh_base_url="http://mesh.example.test",
        credential_provider=should_not_issue,
    )
except ValueError:
    pass
else:
    fail("unsafe destination must be rejected")
if provider_called:
    fail("unsafe destination triggered Identity credential issuance")


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
        deliver_mesh_evidence(
            envelope,
            mesh_base_url=f"http://127.0.0.1:{rejection_server.server_port}",
            credential_provider=lambda _request: "wardveil-reflection-secret",
        )
    except RuntimeError as exc:
        if str(exc) != "Mesh evidence delivery failed with HTTP 403 (scope_denied)":
            fail(f"unexpected sanitized rejection: {exc}")
        if exc.__cause__ is not None or "wardveil-reflection-secret" in repr(exc):
            fail("remote reflection leaked credential material")
    else:
        fail("Mesh rejection must fail closed")
finally:
    rejection_server.shutdown(); rejection_server.server_close(); rejection_thread.join(timeout=2)

print("Wardveil Mesh Identity credential boundary: OK")
