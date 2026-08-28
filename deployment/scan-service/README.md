# Wardveil authenticated Scan service

This deployment surface exposes Wardveil Scan to same-host first-party GoreeCloud consumers while keeping `clamd` private and replaceable. The listener is loopback-only and every scan request is authenticated and bound to the exact resource metadata and SHA-256 digest before the service reads the declared payload body.

## Runtime boundary

- HTTP listener: `127.0.0.1:8791` by default.
- Scanner backend: Wardveil's configured ClamAV runtime from `/etc/goreecloud/wardveil/clamav.env`.
- Application boundary: applications call Wardveil Scan; they do not receive or use the `clamd` endpoint.
- Authentication: caller-scoped `HMAC-SHA256-reference-transport` over caller identity, key identity, timestamp, nonce, action, resource type, resource ID, correlation ID, byte length, and SHA-256 digest.
- Caller authorization: each configured key has an explicit resource-type allowlist.
- Payload handling: raw bytes are read only after request metadata and signature validation succeeds; raw content is not returned in the scan envelope or shared evidence.
- Response: the consumer envelope contains `resource_id`, `resource_digest_sha256`, and an authoritative `scan_record` whose result field is `result`. The application-facing envelope does not use `scan_result`.
- Clean semantics: a clean result requires current acceptable scanner-health evidence and evidence references.
- Positive evidence: a malicious exact-content finding remains actionable when scanner health is degraded.
- Replay handling: a bounded, thread-safe, expiring in-memory nonce ledger rejects conflicting reuse, returns the identical cached envelope for an exact retry, and fails closed when capacity is exhausted.
- Resource controls: the default service permits at most eight concurrent scans and uses a 30-second body-read timeout.
- Claims: source installation or a synthetic clean/EICAR probe does not by itself satisfy deployed application-consumer integration, production service-identity acceptance, quarantine execution, or a broad `Protected by Wardveil` claim.

Do not proxy, firewall-publish, Tunnel-publish, or otherwise expose this listener outside loopback. A future cross-host transport requires an independently accepted authenticated and encrypted private service boundary.

## Credential separation

The checked-in `.env.example` contains non-secret runtime tuning only. Caller secrets belong in the protected file:

`/etc/goreecloud/wardveil/scan-callers.json`

The systemd `LoadCredential` directive delivers this file to the DynamicUser process without placing caller secrets in the service environment. The source example `scan-callers.example.json` intentionally contains an unusable placeholder; copying it unchanged must fail credential validation.

A production credential entry has this shape, but the secret value must be generated and stored outside source control and ordinary documentation:

```json
[
  {
    "caller_id": "goreecloud-drive",
    "key_id": "scan-current",
    "secret": "REPLACE_WITH_A_REAL_SECRET_OUTSIDE_SOURCE_CONTROL",
    "resource_types": ["drive_file"],
    "active": true
  }
]
```

The Foundation 0.9 HMAC mechanism is a dependency-free source and deployment candidate. It is **not** accepted production service identity, key lifecycle, rotation, or revocation evidence.

## Request contract

A `POST /v1/scan` request uses `Content-Type: application/octet-stream` plus these headers:

- `X-Wardveil-Caller-ID`
- `X-Wardveil-Key-ID`
- `X-Wardveil-Timestamp`
- `X-Wardveil-Nonce`
- `X-Wardveil-Action`
- `X-Wardveil-Resource-Type`
- `X-Wardveil-Resource-ID`
- `X-Wardveil-Correlation-ID`
- `X-Wardveil-Digest-SHA256`
- `X-Wardveil-Size-Bytes`
- `X-Wardveil-Signature`

The signature binds all request metadata above except the signature itself. The timestamp must be timezone-aware and within the configured acceptance window. Missing, malformed, expired/future, unauthorized, out-of-scope, or incorrectly signed requests fail closed. Body length or digest mismatch also fails closed.

## Installation layout

The source-controlled unit expects the accepted scan-service release at:

`/opt/goreecloud/wardveil/scan-service/current`

and the accepted ClamAV runtime configuration at:

`/etc/goreecloud/wardveil/clamav.env`

The optional non-secret tuning file is:

`/etc/goreecloud/wardveil/scan-service.env`

The required caller credential file is:

`/etc/goreecloud/wardveil/scan-callers.json`

Keep the credential file root-owned and inaccessible to group/other users. Do not print or copy live caller secrets into CI logs, changelogs, documentation, or source files.

Install the source-controlled systemd unit only from an exact accepted release and validate the loopback listener and health endpoint after restart. The exact-revision production deployment workflow in `.github/workflows/deploy-scan-service-production.yml` performs source checksum validation, protected credential validation, service restart/rollback, loopback health validation, and a sanitized authenticated clean/EICAR probe.

## Replay and scaling boundary

The source implementation's replay ledger is appropriate only for a single process instance: it is bounded, synchronized, expiring, and fail closed, but it is not a durable distributed replay store. Multi-instance or horizontally scaled production requires a deployment-appropriate shared replay/idempotency mechanism and acceptance evidence before that topology can be considered production-accepted.

## Acceptance boundary

The runtime probe can prove only the deployed Wardveil Scan service-to-scanner path for its synthetic resources. It deliberately records:

- authenticated transport: passed when verified;
- consumer-envelope compatibility: passed when verified;
- clean control: passed when verified;
- EICAR detection: passed when verified;
- direct ClamAV application access: false;
- deployed application-consumer integration: not proven by the probe;
- production service identity/key management: not proven by the probe;
- authorized quarantine execution: not proven by the probe;
- production runtime acceptance: `unaccepted`.

A real application acceptance milestone must exercise that application's own Wardveil integration code against the deployed transport with the exact resource identity/digest and all of its local release/enforcement semantics. Direct `clamd` access is never a substitute.
