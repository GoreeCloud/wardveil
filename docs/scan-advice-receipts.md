# Wardveil Scan — Private Advisory Receipt Journal (Development Only)

| Property | Status |
| --- | --- |
| Component | `internal/scan/advice_store.go` |
| Scope | Single-host, private, local filesystem; trusted worker only |
| Date | November 7, 2026 |
| Dependencies | [Held-object coordinator](scan-coordinator.md), [lease admission](scan-admission.md), [advisory contract](scan-contract.md) |
| Production status | **Not deployed or connected to any live source-owner, identity provider or audit/case service** |

## Goal and non-authority

The file-owning GoreeCloud product—not Wardveil—must enforce the pending/held state and decide when to release, delete, export or retain content. A malware verdict is **advisory only**, including `clean`. The existing coordinator closes the already-authorized source reader, validates the engine-consumed SHA-256, exact length and EOF, and calls `AdvisoryRecorder.RecordAdvice` only after the result matches the original request.

The reference `FileAdviceRecorder` implements the previously missing persistent local advice receipt. It does **not** authenticate an external caller, provide a signed audit ledger, mutate holds or release files. It is development-only: there is no network endpoint, durable distributed queue, case-view API, file owner or identity integration.

## Receipt format and privacy

`OpenFileAdviceRecorder` requires an absolute administrator-configured private (`0700`) directory, preferably separate from admission records. It reuses the existing private-directory initialization and parent-directory sync checks. Each valid owner/lease pair gets a private (`0600`) **create-exclusive** `.advice` file, with filename SHA-256(`owner_product + NUL + owner_lease`). The file contains bounded JSON with only:

- Schema version and the pseudonymous owner/lease fingerprint.
- An evidence fingerprint of the validated request, result and recommendation (SHA-256 over canonical Go JSON encoding).
- Verdict, recommendation, engine name/version, scan timestamp and record timestamp.

**The receipt does not persist:** raw owner lease, source object/file ID, raw file SHA-256, request ID, identity subject, credential, source content, file path, malware sample or scan payload. The fingerprints are *deterministic identifiers*, **not encryption or tamper-proof signatures**. Private filesystem access and applicable GoreeShield retention/backup requirements are still mandatory. Future source-owned audit/case views will require an authenticated mapping from source objects to the receipt fingerprint, and must not blindly disclose the mapping.

## Validation and safe failure

`RecordAdvice` checks the trusted caller's product scope and subject, validated owner lease, current request bounds, `Result.ValidateFor(request)`, and `Recommend(result.Verdict)`. An inconsistent or forged `eligible_for_owner_review` disposition is rejected unless the verdict is genuinely `clean` and the entire result matches the original request. No record is written for unverified advice.

The recorder atomically creates the file with Linux `openat(O_EXCL | O_NOFOLLOW)` relative to a verified private directory handle, writes bounded JSON, fsyncs the receipt and that same directory, and rechecks the configured directory identity before success. This avoids the former final-component pathname race; see [private journal directory hardening](scan-private-journal-directory.md). Pre-existing markers (even empty crash-left markers) reject duplicate writes with `ErrAdviceAlreadyRecorded`. The journal never rewrites or automatically removes markers; an interrupted/uncertain write is treated as an operator-recovery case. Errors must never be interpreted as permission to release a held object. Filesystem integrity, free-space monitoring, key/scope ownership and retention are operational dependencies.

`ReadReceipt` is **internal only**. It reads through `openat(O_NOFOLLOW | O_NONBLOCK)` from the same verified private directory handle and validates the opened regular file's private mode, bounded size, single-hard-link count, full newline-delimited JSON structure, expected lease fingerprint and minimal result/recommendation metadata. It uses a previously *trusted* `VerifiedCaller`, which is not a credential; exposing this helper to an untrusted HTTP caller would bypass real authentication. The read is useful for recovery investigation, **not** proof that an attacker with filesystem access could not alter stored bytes.

## Verification

On the authorized Linux developer checkout, unit tests with synthetic content and test-only source/identity/engine adapters cover:

- Clean receipt creation/readback after reopening the journal and no raw data or credentials in the receipt or filename.
- One successful record across **40 concurrent writers**, with all other writes rejected; duplicate same-lease and incomplete crash-marker denial.
- Invalid owner, absent identity, unsafe/mismatched object metadata, nonmatching result/hash and forged recommendation rejection without writing.
- Rejection of symlink/public directory, permissions drift, cancellation, malformed or world-readable receipts.
- Coordinator integration with private admission and receipt journaling. A synthetic malicious result produces `retain_pending_review`; a replayed owner lease does not execute a second scan.

The **opt-in isolated real-ClamAV 1.4.6 test** was additionally run on the authorized Linux development laptop using a preinstalled rootless Podman image, a local Unix socket, no network access and **only synthetic** benign/custom-malicious fixtures. Both verdicts were written to and read back from the **real local private receipt store**; the custom-signature-only daemon was rejected as official-CVD ready. `GOMAXPROCS=2 GOFLAGS=-p=1 GOMEMLIMIT=512MiB timeout 100s bash scripts/verify-clamd-lab.sh` completed with exit **0**; disposable daemon cleanup was verified. Repository-wide Go race tests, static analysis and formatting/diff checks passed afterward with exit **0**. These checks do **not** demonstrate genuine current official ClamAV signatures, authenticated source-product holds, production audit durability, disaster recovery, or tamper-evidence.

## Remaining acceptance gates

Implement the real authenticated GoreeCloud Identity integration and a source-product pending/held API covering **all** download, preview, export, restore, backup and release paths; verify owner-generated lease uniqueness, expiry, revocation and crash recovery. Add durable cross-host job scheduling, explicit audit access controls, measured retention and storage quotas, tamper-evidence and trusted clock treatment, backup/restore verification, and privacy-preserving case views. Validate genuine current official ClamAV signatures and the FreshClam CLD update path in an approved nonproduction environment before any authorized VPS deployment. Keep [Wardveil Scan issue #2](https://github.com/GoreeCloud/wardveil/issues/2) open. The target remains owner-controlled VPS first, then separately validated local-server migration.
