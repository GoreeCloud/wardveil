# Wardveil Scan — Private Lease Admission and Backpressure (Development)

| Field | Verified or intended status |
| --- | --- |
| Repository | `GoreeCloud/wardveil` |
| Component | `internal/scan/admission.go` |
| Date | November 6, 2026 |
| Stage | Development-only; not deployed or connected to a source-product owner |
| Dependency | [Held-object coordinator](scan-coordinator.md) and [ClamAV adapter](clamd-adapter.md) |

## Problem and security objective

A successful clean scan does not authorize file release. A scanned object can also be harmed by replayed requests, duplicate concurrent jobs, and uncontrolled simultaneous scanner workloads. `ScanCoordinator` therefore requires an explicit `JobAdmission` and `ScanLimiter`, in addition to its authenticated caller, trusted source owner, engine and advisory recorder.

The coordinator authenticates the caller, reserves a bounded in-flight slot **before opening** source-owned content, verifies a matching pending/held owner lease, then durably admits that lease **before calling the scanner**. Admission failure or capacity exhaustion returns an error with no scanner execution or advisory record. Successful admission does **not** modify or release the source owner's hold.

## Reference `FileAdmission`

`OpenFileAdmission(/absolute/private/journal)` is a small, **single-host Linux/local-filesystem** reference implementation. The configured directory is trusted administrator configuration, **not** an API field or user path. It must be private `0700`, not a symlink, persistent, and reside on a filesystem with reliable atomic `O_EXCL` and `fsync`; initial directory creation also synchronizes its parent. Permission drift is checked before each reservation.

For each validated `OwnerProduct + LeaseID` pair, the store hashes a NUL-delimited composite identity and atomically creates one `0600` file containing only a fixed version marker. It fsyncs the marker and directory before letting a scan begin; no credentials, personal file content, file paths or raw lease identifiers are written. Existing markers, including zero-length markers left by a crash, reject a duplicate `Reserve`.

The owner must guarantee lease uniqueness and binding to the exact object version, and must issue a **new**, independently authorized pending lease for any legitimate rescan. Retry with the same lease—even after a scanner outage or recorder failure—is denied. This conservative behavior avoids silently producing two verdicts for one hold, but requires an explicit operator recovery workflow.

**Limits:** This is **not** a multi-host consensus or distributed idempotency service, an authenticated network endpoint, a persistent work queue, an audit event store, a file-owner lease validator, or a replacement for database transactions. Untrusted or network-mounted filesystems, directory replacement races in a hostile parent, disk exhaustion, backup/restore of marker files, marker retention, manual deletion, concurrent multi-instance capacity and crash recovery still require an approved operational design. Never automatically delete old markers or suppress/ignore an uncertain-write error. Even successful fsyncs rely on underlying storage guarantees.

## Capacity limits

`NewScanLimiter(n)` accepts `1 <= n <= 32` for the number of simultaneous calls in one coordinator process. `Acquire` returns `ErrScanBusy` immediately when full; it does not accumulate unbounded waiting workers. Its release function is idempotent and runs through a `defer`. A canceled context cannot acquire a slot.

Multiple service processes **do not share** these local slots. A live deployment needs an external global concurrency quota, authenticated request rate limits, disk/memory budgets, queue backpressure, cleanup, deadline propagation and maximum archival recursion.

## Safe failure behavior

- Invalid or cross-product caller: reject before opening source content or reserving a job.
- Saturated capacity: reject before source opening or reservation.
- Missing or contradictory owner hold: close returned source and reject.
- Replay, incomplete marker or unsafe journal permissions: reject without scanning; retain pending state.
- Storage failure or uncertain sync: fail closed and escalate for operator recovery.
- Scanner error, digest/EOF failure, canceled request or unavailable advisory recorder: no release; any already-created reservation remains consumed.
- Clean result: **eligible for source-owner review only**; never auto-release.
- Malicious, suspicious or inconclusive result: **retain pending review** under the source product's policy.

## Verification

On an authorized Linux developer laptop, `go test -race ./... -count=1`, `go vet ./...` and formatting checks exercise synthetic source-reader data, and test:

- Exactly one winner from 48 concurrent reservations for the same lease.
- Duplicate rejection across a new `FileAdmission` instance and when the request ID changes but the lease is reused.
- Atomic incomplete-marker refusal, private directory modes, symlink refusal and permission-drift denial.
- Separate fresh lease admission, no credential/filename disclosure in markers.
- Backpressure and idempotent slot release.
- Coordinator replay denial before engine execution, source closure on duplicate, and fail-closed recorder failure with a consumed lease.

The pre-existing isolated real-ClamAV smoke test covers the coordinator using **synthetic authentication and held-owner implementations**, not this filesystem admission store or live GoreeCloud Identity. No production source-product authority or VPS deployment is implemented.

## Remaining acceptance gates

Implement a real source-product pending/held-file API with authorization on **all** download, export, preview, list, backup/recovery and release paths; verify the existing GoreeCloud Identity provider and credential transport; design durable queues, lease renewal/revocation, collision/replay handling across multiple service hosts, owner-directed rescans and operator recovery; verify current ClamAV signatures/EICAR, outage handling, strict retention and audit traceability. Keep [Wardveil issue #2](https://github.com/GoreeCloud/wardveil/issues/2) and the stacked draft PRs open until acceptance.

The approved target architecture remains **VPS-first** with migration to a local server only after purchase, provisioning and independently verified cutover. This developer admission component does not authorize deployment or migration.
