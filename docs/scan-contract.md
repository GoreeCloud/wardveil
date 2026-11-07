# Wardveil Scan — Advisory Contract (Development Foundation)

| Field | Value |
| --- | --- |
| Document type | Technical contract |
| Responsible owner | GoreeCloud / Wardveil |
| Status | Development advisory contract and in-process adapter/coordination only; no production service |
| Created / updated | 2026-10-25 / 2026-11-06 |
| Canonical location | `GoreeCloud/wardveil/docs/scan-contract.md` |
| Code | [`internal/scan/contracts.go`](../internal/scan/contracts.go) |

## Purpose and ownership

This contract defines **metadata-only requests**, **non-authoritative scan results**, and **advisory dispositions** for a future Wardveil Scan integration.

The file-owning GoreeCloud product—not Wardveil—retains authority over upload visibility, quarantine, release, deletion, and access permissions. These advisory contract types do not read or execute files, create scan jobs, invoke ClamAV, or perform security actions. A separate [development-only Unix-socket adapter](clamd-adapter.md) supports caller-provided byte streaming and was tested against an isolated real ClamAV daemon with synthetic fixtures. The [held-object coordinator](scan-coordinator.md) defines an in-process authorization/owner-hold/result-recording handshake with injectable trusted interfaces. Neither establishes an authenticated production endpoint or a connected source-product release workflow.

## Proposed request flow

1. A source product receives an upload and keeps it in a private pending state according to the product's authorized file-handling policy.
2. The source supplies a validated scan request with `request_id`, `owner_product`, `object_id`, lowercase SHA-256 digest, length metadata, and `requested_at`. No filesystem path, authentication token, raw contents, or arbitrary URL is accepted by the contract.
3. A future trusted adapter obtains file bytes **only** through a separately authorized, scope-limited file-owner interface. That adapter must enforce sandboxing, size, timeout, archive, decompression, and engine-update controls.
4. An adapter returns a structured verdict. Wardveil checks that the result matches the original request, product, object and hash. Provenance and engine trust must be enforced by a future authenticated service layer.
5. Wardveil recommends `eligible_for_owner_review` **only** for `clean`. All other verdicts—including `malicious`, `suspicious`, `inconclusive`, `error`, or an unknown value—recommend `retain_pending_review`.
6. The file-owning product applies its own permission checks, policy, quarantine/release controls and audit process. A clean verdict is **not** an authorization to publish or release a file.

## Version 1 types

| Type | Required fields | Validation |
| --- | --- | --- |
| `Request` | `schema_version`, `request_id`, `owner_product`, `object_id`, `sha256`, `size_bytes`, `requested_at` | Version 1; bounded opaque IDs; lowercase 64-digit hex digest; 0 to 1 TiB declared bytes; timestamp no more than 24h old or 5m in the future |
| `Result` | `schema_version`, matching request/product/object/digest, `verdict`, `engine`, `engine_version`, `scanned_at` | Must match the exact request; bounded engine IDs; valid verdict; scan time not before request by more than 5m or later than 5m in the future |
| `Disposition` | `eligible_for_owner_review` or `retain_pending_review` | Advisory only; never directly changes file state |

The request's 1 TiB value is a **metadata validation ceiling**, not a promise of scanning support at that size. A future engine or source-product policy must enforce tighter operational limits.

## Security and failure boundaries

- No arbitrary filesystem path or network URL is part of the contract.
- There is **no deployed authenticated scan service, source-product pending/quarantine integration, permanent daemon provisioning, durable job scheduling, or release adapter**. Isolated ClamAV lab verification used only synthetic fixtures; production signature readiness and host hardening remain unverified.
- The result's hash field is a claimed identity. The ClamAV adapter verifies streamed content and the in-process coordinator independently checks the engine-consumed bytes, size and EOF before accepting advisory results. A real authenticated service boundary and source-owner permission checks are still required.
- The development [private admission guard](scan-admission.md) rejects duplicate single-host pending lease admissions and bounds in-process concurrency. The system does **not** yet provide production credential verification, owner lease expiry/revocation, distributed replay controls, signature freshness attestation, multi-tenant authorization, durable audit persistence, retries/queues, source-owned quarantine state, or release decisions. Development interfaces and context cancellation are not substitutes.
- A forged but syntactically valid `clean` result remains untrusted without a signed/authenticated provider boundary and source-owner review. Validation does not establish truth.
- Never send raw user files, sensitive metadata, or hashes to an external malware/reputation provider without explicit authorization and applicable privacy review.
- No automatic clearing of pending holds for scans that fail, time out, return ambiguous evidence, or produce unknown verdicts.

## Verification and integration gates

Implementation validation should include request bounds, path-like identifier rejection, bad hash rejection, future/stale timestamps, binding of results to original product/object/hash/request, unknown verdict rejection, and fail-closed disposition recommendations. The tests are in [`internal/scan/contracts_test.go`](../internal/scan/contracts_test.go).

Before the feature is integrated with a live GoreeCloud service, verify authenticated source identity, service-owned quarantine workflow, safe isolated engine execution, content-hash verification, retention rules, retries, cancellation, auditability and recovery. Integrations must not bypass GoreeCloud Vault or Identity ownership boundaries, and any native client must satisfy the governing GC UI and OS-native standards.

**Status boundary:** Advisory types, a local Unix-socket ClamAV adapter, and a source-owner held-object coordinator exist as developer code. A controlled real ClamAV synthetic smoke test passed; **no source-product upload/quarantine integration, production malware protection, or deployment** has been verified.
