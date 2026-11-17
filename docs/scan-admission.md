# Wardveil Scan — Private Lease Admission Journal (Development)

| Field | Value |
| --- | --- |
| Status | Local-only Go library; **not wired into a real owner workflow or deployed** |
| Source | `internal/scan/admission.go`, `internal/scan/private_journal_linux.go` |
| Tests | `admission_test.go`, `private_journal_linux_test.go`, `private_journal_owner_linux_test.go` |
| Target | Trusted single-user Linux service process; **not** a Cloudflare Pages function |

## What this provides

`FileAdmission.Reserve` atomically marks a validated **owner product + held-lease** pair before a trusted worker would scan it. The marker name is a SHA-256 digest of product, a NUL delimiter and the lease ID; it contains only a fixed version string. A private `0700` journal directory and `0600` records are used. Reservation uses `openat` relative to a pinned, verified directory descriptor with `O_EXCL|O_NOFOLLOW` and calls file and directory `fsync`. A repeated or incomplete marker **denies** the same lease; ambiguous writes are treated as failed admission and may consume a lease requiring explicit operator recovery. No user content, raw object ID, credentials or file path is persisted.

`ScanLimiter` is a local, bounded nonblocking concurrency gate (between 1 and 32 slots); it returns an error on exhaustion and its release callback is idempotent. **It does not reserve capacity across different processes or hosts.**

## Security boundary and assumptions

Only **administrator-owned absolute configuration paths** are accepted. The directory must actually belong to the current effective Linux UID, remain private, not be a symlink at its final component, and match its opened descriptor. Journal record reads also require current-account ownership, regular-file type, restricted permissions, a single hard link and exact bounded size. Record creation and reads remain anchored to `openat` rather than re-opening a potentially substituted path. Non-Linux platforms fail closed instead of silently substituting a weaker method.

These controls **do not make an attacker-writable ancestor safe**. The entire ancestor path, filesystem and operator must be trusted and protected against path swaps or hostile mounts. They do not prevent a privileged actor from modifying the filesystem, guarantee disk hardware durability, enforce remote consensus, authenticate the source owner, enforce GoreeShield retention, or guarantee immutable/cryptographically signed receipts. Marker retention, backups and restore are **not designed**. There is no automatic deletion, retry, expiry, remote lookup, queue or rescan allowance. A trusted source owner must issue a new pending lease for any authorized rescan.

The in-process development `ScanCoordinator` now **requires** an explicit `JobAdmission` and a `ScanLimiter`. Following verified caller identity, it reserves bounded capacity **before opening** the source-owner handle, and commits the held-lease marker **before scanning**. Missing admission/capacity, full capacity, replay or uncertain journal writes fail closed without running the scanner. Nevertheless these remain **development-only interfaces**, not connected to a real Identity service, source-product pending file/hold policy, a production scan queue, the running VPS Mesh ClamAV socket, or Cloudflare Pages. Before wiring into a real job, require an authenticated owner attestation, source-held object state enforced on every read/export/restore path, approved private worker isolation, global resource admission, privacy-minimized audit/retention, a service-restart recovery plan and a trusted private transport. Never let a lease marker or a clean result grant file release.

## Offline verification

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
```

Unit tests exercise owner-held directory and records; simulated different Linux UID without privileged `chown`; path/symlink/hardlink substitutions; disk-mode drift; exclusive replay markers; concurrency and limiter backpressure. These tests use **synthetic local metadata only**, with no malware sample, user file or production service access.

This component is an intentionally narrow port and hardening of the older [draft #16](https://github.com/GoreeCloud/wardveil/pull/16) and its [pinned journal draft #19](https://github.com/GoreeCloud/wardveil/pull/19). Their historical aggregate branches should not be merged directly into newer `main`. Follow the live [Scan MVP issue](https://github.com/GoreeCloud/wardveil/issues/2) for integration acceptance.
