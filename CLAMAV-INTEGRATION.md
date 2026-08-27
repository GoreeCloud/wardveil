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

## GoreeCloud Drive source-consumer milestone

GoreeCloud Drive now has an executable source-level Wardveil Scan file consumer at accepted revision `fb2d813063d3f567c9a8db977ffef71ab21c9a0b`. The merged revision has source tree `3a862cb144410d438ee0236dea4b75b1a5090bd9`, identical to the source tree tested by Drive CI run 35 at PR revision `8e82b0a166dcc76e932458870b4955ffbe3c6edb`.

The Drive consumer binds Wardveil evidence to the exact `drive_file` identity and SHA-256 digest. Its current concrete enforcement point is resumable-upload finalization: staged content is scanned before active publication, a current authoritative clean finding with evidence is required for release, and the staged bytes are re-hashed after scanning so a changed object fails closed. Suspicious, malicious, unknown, unsupported, stale, mismatched, non-authoritative, or unavailable verification does not publish the upload. Drive does not connect directly to ClamAV.

The shared evaluator also defines policy-ready semantics for future open, download, share, and Everkeep restore-release paths, but those runtime routes are not claimed as implemented. Everkeep remains authoritative for backup and restore verification; Wardveil verification is an additional security gate before recovered content is released.

Cross-project source evidence is recorded in `contracts/wardveil.drive.consumer-source-evidence.json`. The record preserves the tested-PR-revision versus merged-revision distinction and confirms their identical source tree. It still does not prove deployed authenticated Drive-to-Wardveil transport, deployed scanner/signature health, concurrency-safe finalization, runtime download/share enforcement, Everkeep restore acceptance, or authorized quarantine execution.

Therefore the ClamAV `application_consumer_integration` production acceptance requirement remains unresolved by source milestones alone. Runtime acceptance remains separately evidence-backed.

## Production acceptance

`contracts/wardveil.clamav.runtime-acceptance.json` intentionally records `production_runtime_status` as `unaccepted`. Source-level adapter tests, health tests, a healthy container, or a passing CI run cannot change that field by themselves.

Production acceptance requires evidence from the deployed environment, including current daemon/signature state, a controlled EICAR positive test, a clean control test, fail-closed error behavior, at least one real application consumer, and evidence that authorized quarantine execution works where that product claims quarantine protection.

Health alone is not a broad Wardveil protection claim. The normalized health status can describe only the narrow `wardveil-clamav-runtime` control scope, and its `claim.protected_by_wardveil` remains false. Application- or service-level protection claims require their own authoritative scan, policy, execution, freshness, and scope evidence.
