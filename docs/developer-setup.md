# Wardveil — Development Event Service

| Field | Value |
| --- | --- |
| Type | Developer and test instructions |
| Status | Development prototype, not production-ready |
| Owner | GoreeCloud |
| Updated | 2026-10-25 |
| Canonical location | `GoreeCloud/wardveil/docs/developer-setup.md` |

## Scope

This initial Go 1.23 standard-library service implements only a tightly scoped, single-instance security **event ingestion and listing** loop. It is **not** an antivirus engine, SIEM, incident tracker, auth platform, hosted API, or hardened production service. No network blocking, file quarantine, credential handling, or session revocation is implemented. The service deliberately binds to a loopback IP and has no TLS listener; do not forward or expose it publicly. It has no tenant isolation, role directory, retention scheduler, database replication, or production-grade transactional store. `GET /healthz` is only process liveness, not readiness.

## Build and test

Prerequisite: Go 1.23 or newer. From the repository root:

```sh
go test -race ./...
go vet ./...
go build ./cmd/wardveil
```

## Controlled local launch

Use two **different**, high-entropy secrets of at least 32 bytes, kept out of shell history and logs and managed through an approved secret facility in later deployment. Set environment variables `WARDVEIL_INGEST_TOKEN`, `WARDVEIL_READ_TOKEN`, optionally `WARDVEIL_DATA_DIR` and `WARDVEIL_LISTEN`. Example shell input below references pre-provisioned environment variables, not hard-coded credentials:

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

- `GET /healthz` — unauthenticated minimal liveness.
- `POST /v1/events` — ingest-scope Bearer token; one strict JSON event; 4 KiB maximum; required fields: `schema_version`, `source`, `source_event_id`, `event_type`, `severity`, `asset_id`, `occurred_at`. Supports `schema_version=1` and severity `info|low|medium|high|critical`. Source, type and asset are bounded opaque identifiers, not arbitrary log message bodies. Event time must not be more than five minutes ahead or over 365 days old.
- `GET /v1/events?limit=25` — read-scope token; limit 1–100, most recent first. No pagination or filtering yet.
- Same `(source, source_event_id)` with identical data returns existing event; conflicting reuse returns HTTP 409.
- Response status codes include 201 created, 200 replay/list, 400 invalid request, 401 missing credentials, 403 insufficient credentials, 409 conflicting replay, 413 oversized request, 415 unsupported content type, 422 invalid input, 507 capacity exceeded, 500 storage error.

## Security and operational limitations

- Event data is append-only JSONL in a private data directory (`0700`) and file (`0600`); the store refuses existing files/directories with permissive permissions and refuses malformed/incomplete data. Maximum 10,000 events or ~8 MiB startup store in this prototype. This limits damage but is not a substitute for a transactional database.
- Source authentication uses static per-service tokens with separate read/write scopes; there is **no token issuance, expiry, rotation API, mTLS, SSO, or fine-grained actor auditing**. These must be designed before external access.
- All data remains in a single organization's prototype store; a source name is an untrusted string, not independently verified provenance. Future production ingestion needs authenticated per-source identities, replay windows, origin attestation and scoped tenant IDs.
- This service has no secure transport on its own; binding to loopback is mandatory. Do not deploy behind an externally reachable reverse proxy without a separate security review, access control and TLS design.
- File writes are synchronized individually but not transactional. Interrupted writes can cause a subsequent startup to fail closed. Do not depend on this prototype as a production incident record store.
- This MVP creates no incident case, automated response, alert route or malware verdict. Explicitly evaluate privacy, storage integrity, recovery, telemetry ingestion rates, sensitivity controls and response semantics before expanding.

## Follow-up

Build approved storage migrations, incident/audit models, source credential scoping, retention policies, and only then isolate ClamAV scanning behind source-owned quarantine contracts. Follow `docs/roadmap.md` and `docs/security-model.md`. UI development must use authoritative GC UI and verify each declared native OS target separately.
