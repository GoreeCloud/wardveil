# Wardveil Scan — Held-Object Coordinator (Development Only)

| Field | Value |
| --- | --- |
| Status | Development-stage in-process handshake; not integrated with a live source owner or production authentication |
| Date | November 6, 2026 |
| Source | `internal/scan/coordinator.go`, `internal/scan/admission.go`, their tests |
| Dependency | [ClamAV Unix-socket adapter](clamd-adapter.md); [scan advisory schema](scan-contract.md) |

## Purpose

Prevent an engine's syntactically valid clean verdict from being mistaken for permission to expose a source-owned file. **The file-owning product remains solely responsible for holding, granting access to, releasing, deleting, exporting, and retaining its files.** Wardveil produces advisory scan results only.

`ScanCoordinator.Process` is a synchronous, in-process developer component. It does **not** listen on a network port, ship a credential issuer, own quarantine state, create a durable queue, deploy ClamAV or grant file release.

## Trust flow

1. Validate the existing versioned `scan.Request` and reject absent or oversized opaque credentials. Credential material is passed directly to a trusted `CallerAuthenticator` implementation; the coordinator neither stores nor logs it.
2. An injected **trusted** authenticator derives `VerifiedCaller` from the credential. The verified product and subject must have bounded identifiers, and the product must match `Request.OwnerProduct`. Request-supplied product names are **never** sufficient for authentication.
3. A source-product-owned `HeldSourceOwner.OpenHeld` checks the verified identity and its own object permissions, then attests that the exact product/object/version is **still pending and inaccessible** to normal download, export and release paths. This adapter supplies an already-open content handle and owner-generated scoped lease ID, not a caller-supplied filesystem path or URL.
4. The coordinator rejects any missing hold, mismatched product/object/SHA-256/size, invalid lease identifier, absent bytes or canceled request before scanning. The returned source is closed on all completed paths.
5. The trusted `MalwareEngine` consumes the content. The coordinator independently hashes every byte read and requires the exact declared size **and end-of-stream** before considering even a syntactically clean `scan.Result`. It also validates result request/product/object/hash and engine metadata using `Result.ValidateFor`.
6. `AdvisoryRecorder.RecordAdvice` receives the authenticated caller, owner-generated lease, request, result and `Recommend` recommendation. Clean means **eligible for owner review**, not automatic release; all other outcomes retain the owner's pending-review disposition. A missing/failed recorder returns an error rather than releasing content.

Authentication, source-owner attestation and result recording are **interfaces**, not implemented adapters to GoreeCloud Identity, any source product, or an authenticated transport. An interface alone does not prove end-to-end authorization or stop a dishonest/misconfigured source owner. The source owner's pending-state and lease assertions must be independently verified in its actual code and API before integration.

## Explicit admission and bounded in-flight capacity

The coordinator now **requires** an injected `JobAdmission` and `ScanLimiter` along with its trusted caller authenticator, held source, engine and advisory recorder. After authentication it acquires a bounded capacity slot without a queued wait, rejecting overloaded requests **before** opening source bytes. After exact pending-lease attestation, it calls `JobAdmission.Reserve` **before** invoking the engine. A rejected replay or uncertain journal write fails closed, closes the source handle, records no verdict, and never releases the owner hold.

The reference `FileAdmission` creates private, fsynced, create-exclusive markers for the exact owner lease, and never deletes them automatically. **The owning product must generate a new authorized pending lease for an explicit rescan**; a failed or crashed scan with the old lease remains blocked until operator-directed recovery. See [admission requirements, tests and limitations](scan-admission.md). The `ScanLimiter` slots apply to a **single process** only; a production multi-worker service still needs global capacity, retention and durable queue design.

## Important unfinished safeguards

- Use established GoreeCloud Identity/Vault ownership, with an explicitly authenticated and encrypted private service transport. Implement credential rotation and peer authorization in the owner-specific integration. No new standalone identity provider is proposed here.
- Source products must default to a private pending state **before** upload bytes can be downloaded, listed as available, previewed, exported, restored or otherwise disclosed. They must enforce it consistently on every path and handle membership revocation.
- The owner must enforce lease uniqueness, expiry, revocation, legitimate rescan authorization, retries and recovery. A new private, filesystem-backed [lease admission guard](scan-admission.md) gives **single-host, per-lease replay denial** and a local bounded concurrency limit. It does **not** provide distributed/global admission, an authenticated owner API, a durable work queue or persistent audit logging.
- The engine must independently impose CPU/RAM/archive/concurrency limits, current signatures and health/readiness checks. The coordinator validates the bytes **read by the engine** but cannot prove detection efficacy, signature freshness, or the truthfulness of a malicious/clean engine itself.
- The source reader must support bounded reads and cancellation; its trusted owner implementation must not use arbitrary path/URL fetching. The surrounding caller must provide a bounded request deadline and backpressure.
- `RecordAdvice` implementations must be **advisory-only** and must never unilaterally authorize release, deletion, privacy-policy changes or retention changes. Follow GoreeShield minimization/retention policies and Wardveil's audit model. If recording fails, the owner's pre-release hold remains in force.
- Candidate source products, including GoreeCloud Workspace Teams, are **not approved or integrated** merely by defining these interfaces. Its currently available files lack a pending-scan gate; a separate owner-side change with tests must precede a live handshake.

## Validation evidence

On an authorized Linux development laptop with Go 1.27.3, `go test -race ./... -count=1`, `go vet ./...`, formatting and diff checks passed for the development checkout. Coordinator unit tests use only synthetic bytes and trusted-component test doubles to exercise clean/malicious advice, missing/invalid authentication, cross-product denial, incorrect/absent pending holds, lease binding, incomplete/extra/altered bytes, forged results, engine errors, recorder failures, cancellation and content-handle cleanup.

The opt-in rootless isolated ClamAV lab (`bash scripts/verify-clamd-lab.sh`) also runs `TestCoordinatorLiveClamd`, wiring this coordinator to a genuine **ClamAV 1.4.6** daemon with synthetic content, a **fake** source-owner hold adapter, a **fake** caller authenticator and a **real private local lease-admission journal**. Both clean and custom-signature malicious cases passed, and owner advisory dispositions remained `eligible_for_owner_review` and `retain_pending_review` respectively. The test container was removed. This is real-engine protocol validation but **not end-to-end integration with any real source-product pending/quarantine API or a live identity-provider credential verifier.** Keep deployment and source-product integration acceptance blocked until those gates pass.

See [Scan MVP issue](https://github.com/GoreeCloud/wardveil/issues/2) for end-to-end acceptance and the founder-directed **VPS-first, local-server-later** hosting decision.
