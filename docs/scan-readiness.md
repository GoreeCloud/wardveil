# Wardveil Scan — Official CVD Readiness Gate (Development)

| Field | Value |
| --- | --- |
| Component | `internal/scan/readiness.go` |
| Status | Development-stage pre-scan validation; not a deployed signature update service |
| Scope | Conservative **signed CVD-only** ClamAV readiness, in-process on a trusted scan worker |
| Authority | ClamAV's official database signature verification utility and an owner-selected scan policy |
| Deployment | None; no official signatures installed or updated by this change |

## Why readiness is required

A running `clamd` Unix socket and a successful synthetic malware detection demonstrate only a working protocol and custom fixture. They do **not** demonstrate a current or complete **official** ClamAV signature set, support for current signatures by the engine, or safe production scanning.

The `ScanCoordinator` now **requires** an injected `ScanReadiness`. After authenticating the caller and validating metadata, it invokes `Check(ctx)` **before acquiring scanner capacity, opening any source-owned file, reserving a source lease, or invoking the engine**. A missing, canceled, stale, malformed or failed readiness check returns an error and retains the source owner's hold. A verifier's internal error is not passed through in the coordinator's caller-facing error.

## Conservative reference implementation

`VerifiedCVDReadiness` is a concrete, local-only reference implementation. It uses trusted **absolute administrator-configured** `SigtoolPath` and `DatabaseDirectory`; no user-controlled request path is accepted. It performs the following steps for each scan:

1. Validate a configured executable `sigtool` regular file and a directory without group/other write access. Reject symlinks or writable CVD files. Operator provisioning must independently verify that the installed binary is the authentic, supported ClamAV utility. Code does not pin a vendor signing key or prove the executable's provenance.
2. Require **both** `main.cvd` and `daily.cvd` as regular, non-group/world-writable files. This strict implementation **does not support `.cld` files**, as FreshClam incremental updates use a different archive format with a distinct provenance chain. It fails closed instead of treating a CLD as a verified CVD. Supporting CLD requires a separate verified update/metadata design.
3. Execute the configured `sigtool --info <fixed CVD path>` with no shell or network. Require each call to exit successfully and emit unique, parseable version, signature count, build time, and an exact `Verification OK.` line. Reject missing/duplicated fields, zero counts, implausible timestamps and oversized command output (8 KiB).
4. Enforce an operator-configurable **daily database build age**, default 72 hours, with a permitted range of 1 hour to 7 days. Reject future build times beyond five minutes. `main.cvd` may legitimately be much older; its signature and future-time checks apply, but not the short daily age window.
5. Query the actual locally addressed `clamd` using `zVERSION\0`. Require the daemon to report a numeric loaded database version **equal to the verified `daily.cvd` version**. An engine-only response such as the custom-fixture laboratory's `ClamAV 1.4.6` fails this official readiness gate. No arbitrary remote `clamd` TCP address is accepted.
6. Apply a bounded per-check deadline (default 8 seconds, maximum 30 seconds). Every failure returns unready, not clean.

This is an intentionally strict **necessary** precondition for future production scanning, not proof of detection efficacy. Source-product authorization, GoreeShield privacy and retention policies, official engine provenance, signature update trust, socket isolation, a monitored refresh schedule, engine compatibility with signature database functionality, and post-reload consistency are separate deployment acceptance gates.

## Threats and limits

- **Do not use the test-only `syntheticReadiness()` checker in deployed services.** Unit tests use synthetic signed-looking `sigtool` output from an explicitly fake tool and controlled daemon responses. The real isolated smoke-test daemon has only a synthetic `.hdb` and must fail this official-CVD readiness check. A successful fake test does not authenticate Cisco Talos signatures.
- A malicious local process or compromised `sigtool` may lie about `Verification OK.`; executable origin, package integrity, service identities, filesystem mounts, and daemon socket ownership need explicit verification before staging.
- A check immediately before scanning cannot guarantee consistency across a concurrent daemon reload or file replacement. Production controls should tie the signature generation actually used for the scan to an authenticated result, or serialize reloads with scan admission.
- CVD-only strictness may reject legitimate FreshClam-managed `daily.cld` installations. Do **not** rename CLD files or bypass verification; implement a verified FreshClam update-state adapter instead.
- The reference gate synchronously invokes `sigtool` each scan; batching, bounded caching with short expiry and invalidation after reload require an independently tested optimization. Operator-configured OS process/CPU/memory limits still apply.
- No signatures are downloaded, updated, inventoried, or sent to a third-party service, and no host file is scanned by this component.

## Tests and current acceptance

Unit tests use only synthetic fixtures to verify checked/unchecked command output, duplicated or malformed metadata, old/future database dates, missing `main.cvd`/`daily.cvd`, unsafe permissions, symlinks, missing daemon, wrong loaded database version, timeouts and cancellation. Coordinator tests assert that **no file-owner bytes are opened and no admission occurs when readiness is missing or rejected**.

The opt-in isolated ClamAV 1.4.6 lab tests both clean and synthetic-detection protocol paths, and explicitly checks that its custom-only database cannot pass official-CVD readiness. Neither this test nor repository-wide Go race/CI tests proves that a production VPS has verified official signature coverage.

Official ClamAV documentation explains [signature database formats and `sigtool --info`](https://docs.clamav.net/manual/Signatures.html) and [the FreshClam update path](https://docs.clamav.net/manual/Usage/SignatureManagement.html). This reference intentionally does **not** replace FreshClam.

## Integration checklist

Before any owner-facing upload/release integration: select and audit a source product; implement an authenticated file-owner pending state and all access gates; verify a trusted scanner process and native ClamAV installation; provision valid signed signatures and controlled reloads; support FreshClam's **actual** update mode (including CLD where applicable); implement monitored freshness and degraded-mode handling, lease revocation, cross-host queue limits, replay recovery, audit retention and rollback; run nonproduction real-file EICAR/benign tests with current official signatures. Require explicit production deployment approval. The founder's hosting decision remains owner-controlled VPS first, then a validated local-server migration.
