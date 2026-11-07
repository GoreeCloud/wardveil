# ClamAV Unix-socket adapter — development boundary

**Status:** Protocol adapter and fake-daemon unit tests only. No ClamAV daemon, production scanner, queue, authenticated service API, file-owner quarantine handshake, or VPS deployment is supplied or verified by this change.

## Scope

The `internal/scan.Clamd` adapter implements the documented ClamAV `zINSTREAM\0` protocol over an **absolute Unix-domain socket path only**. It does not accept network addresses, arbitrary file paths, URLs, or instructions to operate on source files. Its caller must already be an authorized file-owning product or trusted worker and must supply an already-open, finite, approved `io.ReadCloser` bound to the exact `scan.Request` object. The adapter takes responsibility for closing that reader on return or context cancellation; the source owner's `Close` must unblock pending reads. The adapter does not provide identity verification or access authorization by itself.

The code:
- Validates the existing advisory request; imposes an 8 MiB default and 64 MiB absolute client-side stream ceiling, with a 30-second default and two-minute maximum scan timeout.
- Queries clamd `VERSION`, then sends `INSTREAM` in bounded 32 KiB chunks, terminating with a zero-length chunk.
- Rejects missing/excess source bytes, SHA-256 mismatches, unknown/malformed/extra reply records, unavailable version metadata, timeouts, and disconnected daemon responses.
- Returns a versioned, **non-authoritative** `scan.Result` with `clean` or `malicious` only when the exact supported daemon reply is parsed. It never automatically releases, deletes, quarantines, or changes ownership of a file.
- Leaves non-clean and failed jobs under the source owner's pending/review policy. The error return must not be transformed into an allow decision.

The caller must supply a closable source whose `Close` unblocks a pending `Read` on cancellation; a custom reader that ignores Close can still stall this prototype. Owner integration must verify this contract. The ClamAV daemon's isolation, archive/decompression limits, memory/CPU/disk controls, concurrency and update policy are **outside the adapter** and must be independently implemented and tested.

## Hosting and trust

The founder-directed target is an owner-controlled **VPS first**, followed by a separately validated migration to a purchased local server. This is a hosting plan, not authorization or evidence of a live service. Keep any eventual `clamd` socket local and accessible only to the dedicated least-privilege scan worker; **never expose clamd's unauthenticated TCP service publicly**.

Before staging or production, verify a supported installed ClamAV build, signed/provenance-checked and sufficiently fresh signatures, socket ownership and permissions, daemon service isolation, compatible `StreamMaxLength`, bounded source retrieval, retention/cleanup, authenticated job requests, idempotency, audit events, evidence integrity, queue backpressure, and safe recovery. Follow GoreeShield privacy policy and retain source-product authority over holds/releases.

The `VERSION` query identifies the engine but **does not certify current signatures or a healthy scan policy**. Missing readiness checks and external source authorization must block release acceptance.

## Tests and evidence

`go test -race ./internal/scan` exercises a fake Unix-socket server: stream framing, clean/malicious classifications, exact content and digest binding, source errors, stalled-source cancellation, malformed daemon responses, missing version data, transport outages, and timeouts. These tests **do not execute real ClamAV**, prove malware-detection efficacy, or validate an actual VPS.

See [scan advisory contracts](scan-contract.md), [security model](security-model.md), and [VPS-to-local hosting decision](architecture.md). ClamAV's official [clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) defines `zINSTREAM` framing and reply semantics.
