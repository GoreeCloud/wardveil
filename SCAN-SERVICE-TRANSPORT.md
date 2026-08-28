# Wardveil Scan Authenticated Transport

Wardveil Foundation 0.9 defines a first-party authenticated transport between GoreeCloud application consumers and Wardveil Scan. Applications continue to consume Wardveil Scan; they do not receive ClamAV endpoint configuration and do not connect to `clamd` directly.

## Runtime sequence

1. The application computes the exact content SHA-256 digest and uses its stable internal Wardveil resource identity.
2. The caller creates a bounded scan request containing caller ID, key ID, current timestamp, nonce, lifecycle action, resource type, resource ID, correlation ID, content length, and content digest.
3. The caller signs the canonical request metadata with its configured service credential.
4. Wardveil verifies caller/key state, the caller's resource-type allow-list, timestamp window, body length, exact body digest, signature, and nonce state before scanning.
5. Wardveil submits the exact request bytes to the replaceable scanner through the internal ClamAV adapter.
6. A would-be clean verdict is accepted only when current scanner-health evidence is healthy and signature-fresh. The health evidence reference is included in the clean scan record.
7. Wardveil returns the consumer-facing envelope containing the exact resource ID, exact SHA-256 digest, and authoritative `scan_finding` record.
8. The application independently applies its lifecycle policy. A scan response does not transfer application resource authority and does not authorize quarantine by itself.

## Request authentication

The Foundation 0.9 transport reference uses `HMAC-SHA256-reference-transport` for dependency-free conformance. The signature binds:

- contract version;
- caller ID;
- key ID;
- timestamp;
- nonce;
- lifecycle action;
- resource type;
- resource ID;
- correlation ID;
- content length;
- SHA-256 content digest.

Verification uses constant-time comparison. Unknown/inactive callers, unknown keys, unauthorized resource types, digest or length mismatches, invalid signatures, and timestamps outside the accepted window fail closed before the scanner is called.

This HMAC scheme is not accepted production service identity or key management. Production acceptance still requires the approved long-term authentication, rotation, revocation, secret-storage, and abuse-resistance architecture.

## Replay behavior

The source reference keeps a bounded request ledger interface. Exact reuse of the same caller/key/nonce and the same authenticated request may return the identical cached scan envelope without rescanning. Reuse of the nonce with different authenticated material fails closed. An in-progress duplicate does not start another scan.

A production service must provide replay behavior appropriate to its deployment topology and availability model; the in-memory reference is not durable production replay protection.

## Consumer envelope

The transport returns the exact shape already consumed by GoreeCloud Drive and aligned consumers:

- `resource_id` — stable application-owned resource identity;
- `resource_digest_sha256` — exact body digest verified by the transport;
- `scan_record.contract_version` — `0.1.0`;
- `scan_record.record_type` — `scan_finding`;
- authoritative producer identity;
- exact `resource_type` + `resource_id` scope;
- evidence validity window;
- `result` — `clean`, `suspicious`, `malicious`, `unknown`, or `unsupported`;
- minimized evidence references.

Clean evidence contains both the digest-bound scanner evidence reference and current scanner-health evidence reference. Scanner unavailability, incomplete scans, or unacceptable health cannot produce clean.

A positive malware match remains actionable when scanner health is degraded. Degraded health prevents false clean reassurance; it does not erase positive exact-digest malware evidence.

## VPS source deployment

`deployment/scan-service/` provides a loopback-only Python service using the standard library, a dedicated `wardveil-scan` system user, and a hardened systemd unit. The service loads the existing Wardveil ClamAV runtime settings plus a separately provisioned `WARDVEIL_SCAN_CALLERS_JSON` credential set.

The HTTP surface is intentionally narrow:

- `POST /v1/scan` — authenticated binary scan transport;
- `GET /healthz` — minimal local service liveness;
- all other routes — not found.

The service suppresses the default HTTP access logger so authentication metadata, resource IDs, filenames, URLs, and scan signatures are not emitted by the server framework. Raw content is streamed only into process memory and the scanner path; it is not included in shared scan records.

The default bind is `127.0.0.1:8788`. A non-loopback bind requires explicit configuration but is not by itself authorization for Internet exposure. An external/private transport would still need separately accepted authentication, encryption, firewall, and service-identity controls.

## Deployment gate and runtime probe

`.github/workflows/deploy-scan-service-production.yml` is manual, main-branch-only, exact-revision-bound, and uses the existing `wardveil-production` VPS trust boundary. It refuses deployment unless:

- the exact approved main revision is checked out;
- the pinned VPS SSH host identity is verified;
- the existing ClamAV runtime environment exists;
- `/etc/goreecloud/wardveil/scan-service.env` already contains at least one scoped caller credential;
- every configured secret is at least 32 bytes and every caller has an explicit resource-type scope.

The workflow does not generate caller secrets. Credential provisioning and rotation remain separate controlled operations.

After deployment the workflow runs an authenticated loopback clean control and EICAR control through the Wardveil Scan service. The probe validates the response digest, authoritative producer, resource scope, clean result, and malicious EICAR result without printing credentials or content.

Passing that probe proves the Wardveil Scan transport can reach the accepted scanner runtime for controlled test content. It does **not** prove a deployed GoreeCloud application is using the transport, does not prove production service-identity/key management acceptance, and does not satisfy quarantine execution evidence.

## Privacy Shield and authority boundaries

Shared security records require stable resource identity, SHA-256 digest, producer/correlation metadata, evidence references, and result state. User-facing filenames, raw URLs, cookies, account credentials, authorization secrets, and unrelated user metadata are not required.

Privacy Shield remains the privacy and minimization authority. Application resource owners remain authoritative for their content and lifecycle actions. Wardveil Scan is authoritative only for the represented security scan result. Everkeep remains authoritative for backup, preservation, and recovery.

## Production acceptance

`production_runtime_status` remains `unaccepted`. Source tests or even a successful service deployment do not satisfy the complete application-consumer acceptance requirement.

Acceptance still requires approved production service authentication/key management, a deployed scan service bound to the accepted live scanner, at least one deployed application consumer using this authenticated transport, controlled consumer-level clean/EICAR/error/stale-health tests, runtime key rotation/revocation, abuse-rate controls, Audit/Security Center provenance, Privacy Shield runtime acceptance, and authorized quarantine execution evidence.
