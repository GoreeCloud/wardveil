# Wardveil Security ClamAV Integration

Wardveil Security owns the GoreeCloud malware-protection product boundary. ClamAV is the initial replaceable malware-scanning engine beneath Wardveil Scan; it is not a separate GoreeCloud antivirus product and does not become authoritative for Wardveil policy, quarantine, response, or Security Center state.

## Architecture decision

Use ClamAV for signature-based malware inspection while keeping the surrounding security lifecycle first-party:

`resource -> Wardveil Scan -> ClamAV adapter -> scan finding -> Wardveil Policy -> Wardveil Protect/Quarantine -> Wardveil Audit/Security Center`

This preserves engine replaceability. A future scanner, sandbox, reputation service, behavioral engine, or platform-native endpoint sensor can be added without changing the Wardveil product identity or evidence contracts.

## Scan adapter

`reference/wardveil_clamav.py` provides a dependency-free adapter that:

- connects to `clamd` over exactly one configured Unix socket or TCP endpoint;
- uses `INSTREAM` so the daemon does not need direct access to application file paths;
- computes a SHA-256 resource digest for evidence correlation;
- maps `FOUND` to a completed malicious Wardveil Scan input and preserves the ClamAV signature name;
- maps daemon errors, timeouts, malformed replies, and unavailable scanner state to incomplete/unknown rather than clean;
- enforces a Wardveil-side maximum stream size before submission;
- performs no deletion, quarantine, repair, or remediation itself.

The adapter also exposes `PING` and `VERSION` for runtime health evidence.

## Runtime health and clean-verdict gate

`reference/wardveil_clamav_runtime.py` turns the scanner's operational state into data-minimized Wardveil component evidence. It collects or derives:

- daemon reachability;
- ClamAV engine version;
- loaded signature database version;
- loaded signature database update timestamp;
- signature freshness against a configurable maximum age;
- last successful scan timestamp when runtime metrics are supplied;
- scanner error rate when runtime metrics are supplied;
- configured Wardveil stream-size limit;
- transport class without exposing the actual endpoint or socket path.

The default signature-freshness limit is 48 hours and health evidence is valid for five minutes. Both values are configurable for a deployment, but weakening them does not create production acceptance.

A ClamAV `OK` reply becomes a reusable Wardveil `clean` finding only when the associated health evidence is healthy, current, unexpired, daemon-reachable, and based on current signature evidence. Stale, unavailable, future-dated, expired, or otherwise unverified health evidence downgrades a would-be clean finding to `unknown`.

Positive threat evidence is handled differently: a completed ClamAV malware signature match remains `malicious` even when scanner health is degraded. Degraded health must not erase a positive detection; it prevents false reassurance from negative results.

The separate component-health contract is defined by:

- `contracts/wardveil.clamav.health.schema.json`;
- `contracts/wardveil.clamav.runtime-acceptance.json`.

These contracts do not add a new Wardveil runtime security-record type and do not expand the authority of the canonical Scan, Policy, Protect, Quarantine, Response, or Audit contracts.

## Security boundary

The `clamd` protocol is not an authenticated public API. Prefer a local Unix socket for same-host integrations. If TCP is required, keep it on loopback or behind a separately authenticated and encrypted private service boundary; do not expose an unauthenticated `clamd` listener directly to the public Internet.

Wardveil applications should submit content through Wardveil Scan rather than reaching `clamd` directly. This prevents every application from acquiring scanner-specific configuration and keeps policy, evidence, freshness, and error semantics consistent.

## Malware handling

A ClamAV match is authoritative scanner evidence for the represented scan, but the engine does not own the response decision. Wardveil Policy decides the allowed next action. Wardveil Protect and Wardveil Quarantine execute containment or remediation only when explicitly authorized.

Recommended default flow for a confirmed malware match:

1. Emit a Wardveil `scan_finding` with `scan_result=malicious`.
2. Correlate the finding with resource identity and current policy.
3. Block opening, execution, synchronization, delivery, or download where the integrating product has explicit enforcement authority.
4. Quarantine through Wardveil Quarantine rather than deleting inside the scanner adapter.
5. Record the decision and action in Wardveil Audit.
6. Surface the evidence-backed state in Wardveil Security Center.

## Signature updates

Use ClamAV's controlled signature-update mechanism and persistent database storage. Wardveil evaluates the timestamp of the database actually loaded by `clamd`; merely observing an updater process is not sufficient evidence that the scanner is using current signatures.

A running daemon with stale or unknown signatures is degraded or unknown, never fully healthy. A previously healthy health record also expires and cannot indefinitely authorize later clean results.

## Deployment baseline

`deployment/clamav/` provides the source-controlled runtime baseline:

- official ClamAV 1.4 LTS feature image baseline;
- persistent `/var/lib/clamav` signature database volume;
- loopback-only TCP publication by default;
- environment-driven Wardveil transport, limit, freshness, and error-rate settings;
- `scripts/collect_wardveil_clamav_health.py` for JSON evidence collection;
- `scripts/validate_wardveil_clamav_runtime.py` for source-controlled deployment invariants.

The supplied Compose file is a baseline, not a claim that any GoreeCloud VPS is already running it.

## Real-time protection

Do not equate ClamAV installation with complete endpoint antivirus. ClamAV supplies scanning primitives and may participate in platform-specific on-access scanning, but Wardveil should own a separate endpoint-protection/agent layer for filesystem event capture, process and execution controls, policy enforcement, remediation, and cross-platform behavior.

The product direction remains **Wardveil Malware Protection** inside Wardveil Security Center, backed initially by ClamAV for malware signatures and expanded over time with first-party and replaceable engines.

## Integration targets

Priority GoreeCloud consumers are:

- GoreeCloud Mail attachments before delivery or opening;
- GoreeCloud Drive uploads, downloads, shares, and restored content;
- GoreeCloud Browser downloads;
- GoreeCloud AI uploaded files and model/tool artifacts;
- GoreeCloud Code packages, release artifacts, and repository uploads;
- GoreeCloud Messenger attachments;
- Everkeep restore verification before recovered data is released to applications.

Each consumer must preserve the Wardveil fail-closed rule: unsupported, incomplete, unavailable, stale, expired, or invalid scan evidence is not a clean verdict.

## GoreeCloud Mail source-consumer milestone

GoreeCloud Mail is the first GoreeCloud application with an executable source-level Wardveil Scan attachment consumer. The accepted Mail revision is `de4b0844c4973a80c11854318956d50536ddbb9e` in `GoreeCloud/goreecloud-mail`.

The Mail consumer binds Wardveil scan evidence to the exact `mail_attachment` scope and SHA-256 attachment digest, allows opening/downloading only for current authoritative clean evidence, holds suspicious content for review, blocks malicious content, and emits a non-destructive Wardveil Quarantine handoff that still requires explicit executor authority. Mail does not connect directly to ClamAV.

Cross-project source evidence is recorded in `contracts/wardveil.mail.consumer-source-evidence.json`. That record is provenance for implementation and exact-revision CI only. It does not prove that a deployed Mail runtime can reach Wardveil Scan, that a deployed ClamAV service is healthy, that provider attachment bytes were bound correctly in production, or that quarantine executed.

Therefore the ClamAV `application_consumer_integration` production acceptance requirement is not considered satisfied solely by this source milestone. Runtime acceptance remains separately evidence-backed.

## Production acceptance

`contracts/wardveil.clamav.runtime-acceptance.json` intentionally records `production_runtime_status` as `unaccepted`. Source-level adapter tests, health tests, a healthy container, or a passing CI run cannot change that field by themselves.

Production acceptance requires evidence from the deployed environment, including current daemon/signature state, a controlled EICAR positive test, a clean control test, fail-closed error behavior, at least one real application consumer, and evidence that authorized quarantine execution works where that product claims quarantine protection.

Health alone is not a broad Wardveil protection claim. The normalized health status can describe only the narrow `wardveil-clamav-runtime` control scope, and its `claim.protected_by_wardveil` remains false. Application- or service-level protection claims require their own authoritative scan, policy, execution, freshness, and scope evidence.
