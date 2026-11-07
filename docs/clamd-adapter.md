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

### Real-daemon smoke test (nonproduction, November 6, 2026)

The opt-in `internal/scan/clamd_real_integration_test.go` test exercises this actual adapter against a running local ClamAV daemon. Ordinary CI skips this test unless `WARDVEIL_CLAMD_TEST_SOCKET` points to an explicitly isolated **test** Unix socket.

A controlled test was executed on an authorized Linux development laptop with a preinstalled official `clamav/clamav:1.4_base` image. Rootless Podman ran ClamAV **1.4.6** with no network, no published ports, a read-only container root, dropped capabilities, no-new-privileges, a 512 MiB memory limit, a 32-process limit, and a private owner-accessible Unix socket. The daemon used only a **single custom synthetic .hdb signature**, not the production or official full malware database. Both real-engine adapter cases passed:

- Harmless synthetic input → `clean`, empty signature.
- Test-only matching input → `malicious`, `Wardveil.Test.Fixture.UNOFFICIAL`, with the owner disposition remaining pending review.

To reproduce with a separately prepared isolated test daemon containing the matching custom rule:

```bash
WARDVEIL_CLAMD_TEST_SOCKET=/absolute/path/to/private/clamd.sock \
  go test -v -count=1 -run '^TestClamdLiveEngine, [security model](security-model.md), and [VPS-to-local hosting decision](architecture.md). ClamAV's official [clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) defines `zINSTREAM` framing and reply semantics.
 ./internal/scan
```

This proves the basic Unix-socket command framing, content binding, strict reply parsing, and real daemon interaction for the two synthetic cases; it does **not** prove real-world malware detection accuracy, up-to-date signatures, EICAR detection with the official databases, concurrent-load safety, recovery, quarantine enforcement, VPS suitability, or deployment readiness. The manual lab container was stopped after validation.

See [scan advisory contracts](scan-contract.md), [security model](security-model.md), and [VPS-to-local hosting decision](architecture.md). ClamAV's official [clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) defines `zINSTREAM` framing and reply semantics.
