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
    raise SystemExit(f"Wardveil Mesh delivery test failed: {message}")


now = datetime.now(timezone.utc)
record = {
    "record_id": "delivery-001",
    "producer": {"id": "wardveil-policy", "authoritative": True},
    "scope": {"resource_type": "service", "resource_id": "goreecloud-mail", "component": "attachment-ingress"},
    "reason_code": "attachment_policy_satisfied",
    "valid_until": (now + timedelta(hours=1)).isoformat(),
    "raw_payload": "must not be delivered",
}
envelope = create_mesh_evidence_envelope(
    record,
    revision="a" * 40,
    assertion="policy-decision",
    outcome="allow",
    observed_at=now,
)

received = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        if self.path != "/v1/evidence/envelopes":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        received["authorization"] = self.headers.get("Authorization")
        received["body"] = json.loads(self.rfile.read(length).decode("utf-8"))
        payload = {
            "envelope": {**received["body"], "fresh": True},
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


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    token = "test-identity-credential"
    receipt = deliver_mesh_evidence(
        envelope,
        mesh_base_url=f"http://127.0.0.1:{server.server_port}",
        bearer_token=token,
    )
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)

if received.get("authorization") != "Bearer test-identity-credential":
    fail("Identity credential was not sent as bearer authorization")
if received.get("body") != envelope:
    fail("delivered envelope changed in transit")
if "raw_payload" in received.get("body", {}):
    fail("raw Wardveil payload leaked into Mesh delivery")
if receipt.get("producer_service_id") != "wardveil-security" or receipt.get("evidence_id") != envelope["id"]:
    fail("delivery receipt was not producer/evidence bound")

try:
    deliver_mesh_evidence(
        envelope,
        mesh_base_url="http://mesh.example.test",
        bearer_token="secret",
    )
except ValueError:
    pass
else:
    fail("non-loopback plaintext HTTP must be rejected")

wrong = dict(envelope)
wrong["producer"] = dict(envelope["producer"])
wrong["producer"]["system"] = "privacy-shield"
try:
    deliver_mesh_evidence(wrong, mesh_base_url="https://mesh.example.test", bearer_token="secret")
except ValueError:
    pass
else:
    fail("cross-producer envelope must be rejected before transport")

print("Wardveil authenticated Mesh evidence delivery: OK")
