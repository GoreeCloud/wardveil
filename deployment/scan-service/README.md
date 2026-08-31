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
- Replay handling: development/reference execution may use the bounded in-memory ledger. The source-controlled production systemd unit sets a private SQLite replay database so nonce claims and finalized cached envelopes survive same-host process restart.
- Resource controls: the default service permits at most eight concurrent scans and uses a 30-second body-read timeout.
- Claims: source installation or a synthetic clean/EICAR probe does not by itself satisfy deployed application-consumer integration, production service-identity acceptance, quarantine execution, durable replay runtime acceptance, or a broad `Protected by Wardveil` claim.

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

The production unit uses `StateDirectory=wardveil-scan` with mode `0700` and sets:

`WARDVEIL_SCAN_REPLAY_DB=/var/lib/wardveil-scan/replay.sqlite3`

The SQLite database is created as an owner-only regular file (`0600`). It stores only caller/key/nonce identifiers, an authentication-bound request digest, expiry, and the sanitized cached response envelope. Raw scanned content and caller secrets are not persisted in replay state.

Keep the credential file root-owned and inaccessible to group/other users. Do not print or copy live caller secrets into CI logs, changelogs, documentation, or source files.

Install the source-controlled systemd unit only from an exact accepted release and validate the loopback listener and health endpoint after restart. The exact-revision production deployment workflow in `.github/workflows/deploy-scan-service-production.yml` performs source checksum validation, protected credential validation, service restart/rollback, loopback health validation, a sanitized authenticated clean/EICAR probe, and the same-host replay restart acceptance described below.

## Replay and scaling boundary

`InMemoryReplayLedger` remains available for isolated development/reference execution and is appropriate only for a single process instance. It is bounded, synchronized, expiring, and fail closed, but process restart loses its state.

The production systemd unit instead selects `SQLiteReplayLedger`. Its claim and finalize operations use transactional SQLite writes, prune expired entries, preserve pending claims across restart until TTL expiry, return the cached envelope for exact replay, reject conflicting nonce reuse, and fail closed when the configured capacity or replay store is unavailable. SQLite provides shared serialization for processes on the same host that use the same database file.

This source change does **not** by itself prove target-environment restart durability. That requires an exact deployed-revision acceptance test that creates/finalizes a signed request, restarts `wardveil-scan.service`, then proves exact replay returns the cached envelope and conflicting reuse still fails. Multi-host or horizontally scaled production requires a deployment-appropriate shared replay/idempotency mechanism; a node-local SQLite database is not evidence for that topology.

## Same-host restart acceptance

The source-controlled command `scripts/accept_wardveil_scan_replay_restart.py` is the runtime gate for single-host restart durability. It must run as root only against the loopback `wardveil-scan.service` deployment and the protected caller registry. The command:

1. selects an active scoped caller/key without printing its secret;
2. sends a signed clean control request and verifies the finalized cached response exists in the private replay database;
3. stores only private mode-0600 transient request metadata and the sanitized first response, excluding raw test bytes and the caller secret;
4. captures the current systemd `InvocationID` and `MainPID`, restarts `wardveil-scan.service`, waits for the health boundary to recover, and requires a changed invocation identity;
5. resends the identical signed request within the authenticated timestamp window and requires the identical cached response envelope;
6. reopens the SQLite replay state and verifies the same nonce still has the expected unexpired cached envelope;
7. sends a correctly signed conflicting request with the same nonce and requires HTTP 409;
8. verifies the service remains healthy, deletes the transient request-state file, and writes sanitized mode-0600 acceptance evidence.

The resulting evidence may mark `single_host_restart_durability=passed` only when all of those conditions succeed. It must keep `multi_host_replay_durability=not_proven`, `production_runtime_acceptance=unaccepted`, and `protection_claim_authority=false`. Passing this command establishes same-host restart durability for the exact deployed revision and environment only; it does not prove shared replay across independent hosts or a horizontally scaled topology.

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

The restart acceptance command proves only the durable same-host replay property for its exact deployed revision and environment. It does not promote production service identity/key management, runtime revocation, multi-host replay, quarantine execution, Audit/Security Center provenance, Privacy Shield, Everkeep, or overall Wardveil production acceptance.

A real application acceptance milestone must exercise that application's own Wardveil integration code against the deployed transport with the exact resource identity/digest and all of its local release/enforcement semantics. Direct `clamd` access is never a substitute.
