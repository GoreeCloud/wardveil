# Wardveil — Development Event Service

| Field | Value |
| --- | --- |
| Type | Developer and test instructions |
| Status | Development prototype, not production-ready |
| Owner | GoreeCloud |
| Updated | 2026-11-04 |
| Canonical location | `GoreeCloud/wardveil/docs/developer-setup.md` |

## Scope

This initial Go standard-library service implements only a tightly scoped, single-instance security **event ingestion and listing** loop. It is **not** an antivirus engine, SIEM, incident tracker, auth platform, hosted API, or hardened production service. No network blocking, file quarantine, credential handling, or session revocation is implemented. The service deliberately binds to a loopback IP and has no TLS listener; do not forward or expose it publicly. It has no tenant isolation, role directory, retention scheduler, database replication, or production-grade transactional store. `GET /healthz` is a minimal process/journal-writability signal, not full operational readiness.

## Build and test

Prerequisite: the supported Go 1.27.3 toolchain or newer supported release. Local source-compatibility tests were run on an older Go 1.23 toolchain; that is not evidence of current-toolchain CI or production runtime acceptance. From the repository root:

```sh
go test -race ./...
go vet ./...
go build ./cmd/wardveil
```

## Controlled local launch

Use two **different**, high-entropy secrets of at least 32 bytes, kept out of shell history and logs and managed through an approved secret facility in later deployment. Set environment variables `WARDVEIL_INGEST_TOKEN`, `WARDVEIL_READ_TOKEN`, optionally `WARDVEIL_STATUS_TOKEN` (opt-in scoped health reader), `WARDVEIL_DATA_DIR` and `WARDVEIL_LISTEN`. When enabled, the status token must be a distinct secret of 32–1024 bytes, different from both event credentials; the service refuses startup if it overlaps. Example shell input below references pre-provisioned environment variables, not hard-coded credentials:

```sh
WARDVEIL_DATA_DIR=./var WARDVEIL_LISTEN=127.0.0.1:8787 go run ./cmd/wardveil
```

With a valid ingest token:

```sh
curl -sS -X POST http://127.0.0.1:8787/v1/events \
  -H "Authorization: Bearer $WARDVEIL_INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"schema_version":"1","source":"identity","source_event_id":"demo-1","event_type":"auth.anomaly","severity":"high","asset_id":"test-asset","occurred_at":"2026-10-25T12:00:00Z"}'
```

The example timestamp is illustrative; substitute a current RFC3339 timestamp when running the command. With the separate read token, query `GET /v1/events?limit=25`. Use test identifiers only, not production identifiers. Never paste real credentials into issues, shell logs, screenshots or documentation.

## API contract — prototype

- `GET /healthz` — unauthenticated minimal liveness and in-process journal-writability status; 503 after a detected uncertain journal write **or** when the development event capacity is exhausted. It is not a full runtime readiness or remote-dependency probe.
- `GET /v1/status` — **disabled/404 by default** until `WARDVEIL_STATUS_TOKEN` is set. Requires a distinct status-only Bearer token; neither event-ingest nor event-read tokens authorize it, and the status token cannot read or ingest events. A valid read returns a minimal `wardveil.status.v1` response `{schema_version,state,observed_at}` (UTC source-observed millisecond timestamp). HTTP 200 maps to `ok` when the journal is writable, HTTP 503 to `degraded` when it is not. Query parameters and request bodies are rejected; no event identities, counts or payloads are included. `/healthz` remains unauthenticated and unchanged.
- `POST /v1/events` — ingest-scope Bearer token; one strict JSON event with case-insensitively unique field names (duplicate keys return HTTP 400); 4 KiB maximum; required fields: `schema_version`, `source`, `source_event_id`, `event_type`, `severity`, `asset_id`, `occurred_at`. Supports `schema_version=1` and severity `info|low|medium|high|critical`. Source, type and asset are bounded opaque identifiers, not arbitrary log message bodies. Event time must not be more than five minutes ahead or over 365 days old.
- `GET /v1/events?limit=25` — read-scope token; limit 1–100, most recent first. No pagination or filtering yet.
- Same `(source, source_event_id)` with identical data returns existing event; conflicting reuse returns HTTP 409.
- Response status codes include 201 created, 200 replay/list, 400 invalid request, 401 missing credentials, 403 insufficient credentials, 409 conflicting replay, 413 oversized request, 415 unsupported content type, 422 invalid input, 503 uncertain journal write requiring recovery, 507 capacity exceeded, 500 other storage error.

## Security and operational limitations

- Event data is append-only JSONL in a private data directory (`0700`) and file (`0600`); the store refuses existing files/directories with permissive permissions and refuses malformed/incomplete data. On Linux, an exclusive advisory file lock prevents a second cooperating service instance from opening the same journal; the lock is released on close or process exit. A second instance fails startup without truncating the journal. The prototype fails closed on platforms without an implemented lock instead of silently allowing concurrent writers. Maximum 10,000 events or ~8 MiB startup store. This limits damage but is not a substitute for a transactional database, a network filesystem guarantee, or defense against a non-cooperating writer.
- Source authentication uses static per-service tokens with separate read/write scopes; there is **no token issuance, expiry, rotation API, mTLS, SSO, or fine-grained actor auditing**. These must be designed before external access.
- All data remains in a single organization's prototype store; a source name is an untrusted string, not independently verified provenance. Future production ingestion needs authenticated per-source identities, replay windows, origin attestation and scoped tenant IDs.
- This service has no secure transport on its own; binding to loopback is mandatory. Do not deploy behind an externally reachable reverse proxy without a separate security review, access control and TLS design.
- File writes are synchronized individually but not transactional. A failed append or sync may have persisted some or all bytes without a safe acknowledgement. The current process therefore stops accepting **all** subsequent ingests, including replays, and `/healthz` returns 503. Stop the service, preserve the journal for inspection, determine whether its final record is complete and valid, and only then use an authorized recovery/restart procedure. Do not blindly truncate, delete, or retry writes. Interrupted writes can also cause a subsequent startup to fail closed. Do not depend on this prototype as a production incident record store.
- This MVP creates no incident case, automated response, alert route or malware verdict. Explicitly evaluate privacy, storage integrity, recovery, telemetry ingestion rates, sensitivity controls and response semantics before expanding.

## Follow-up

Build approved storage migrations, incident/audit models, source credential scoping, retention policies, and only then isolate ClamAV scanning behind source-owned quarantine contracts. Follow `docs/roadmap.md` and `docs/security-model.md`. UI development must use authoritative GC UI and verify each declared native OS target separately.

### Dedicated Mesh status-only development scope

The source-owned `/v1/status` route is **opt-in** for a reviewed, isolated local development session. Use a third independently generated high-entropy token exclusively for that route, never share the event-listing token with Mesh, and do not place any real credential in source, screenshots, logs, CI artifacts or issue reports. The secret is processed only in memory as an SHA-256 comparison reference; it is not a durable Keycloak or GoreeCloud Identity credential, nor does it implement revocation during an already running process. Revocation currently requires removing/replacing the configured status token and restarting the development process; a real production Identity revocation flow is unimplemented.

Do not proxy this plain HTTP loopback service externally, place it on an internet-facing host, or treat the status result as Wardveil cybersecurity posture. A real Mesh connector must validate the **source-owned** version and timestamp and reject schema drift, untrusted origins, missing authentication, ambiguous headers, body overflow and credential scope crossover. The temporary hosted source CI smoke uses disposable test-only tokens and private journal data. This feature does not approve any production deployment, full incident record access, signed response, or Stable release.
