# Wardveil Security ClamAV Integration

Wardveil Security owns the GoreeCloud malware-protection product boundary. ClamAV is the initial replaceable malware-scanning engine beneath Wardveil Scan; it is not a separate GoreeCloud antivirus product and does not become authoritative for Wardveil policy, quarantine, response, or security-center state.

## Architecture decision

Use ClamAV for signature-based malware inspection while keeping the surrounding security lifecycle first-party:

`resource -> Wardveil Scan -> ClamAV adapter -> scan finding -> Wardveil Policy -> Wardveil Protect/Quarantine -> Wardveil Audit/Security Center`

This preserves engine replaceability. A future scanner, sandbox, reputation service, behavioral engine, or platform-native endpoint sensor can be added without changing the Wardveil product identity or evidence contracts.

## Initial implementation

`reference/wardveil_clamav.py` provides a dependency-free adapter that:

- connects to `clamd` over exactly one configured Unix socket or TCP endpoint;
- uses the documented `INSTREAM` protocol so the daemon does not need direct access to application file paths;
- computes a SHA-256 resource digest for evidence correlation;
- maps `OK` to a completed clean Wardveil Scan input;
- maps `FOUND` to a completed malicious Wardveil Scan input and preserves the ClamAV signature name;
- maps daemon errors, timeouts, malformed replies, and unavailable scanner state to incomplete/unknown rather than clean;
- enforces a Wardveil-side maximum stream size before submission;
- performs no deletion, quarantine, repair, or remediation itself.

The adapter can also expose `PING` and `VERSION` for runtime health and evidence collection.

## Security boundary

The `clamd` protocol does not provide the security properties of an authenticated public API. Prefer a local Unix socket for same-host integrations. If TCP is required, keep it on loopback or a private, authenticated, encrypted service boundary; do not expose an unauthenticated `clamd` listener directly to the public Internet.

Wardveil applications should submit bytes to Wardveil Scan rather than reaching `clamd` directly. This prevents every application from acquiring scanner-specific configuration and keeps policy, evidence, and error semantics consistent.

## Malware handling

A ClamAV match is authoritative evidence from the configured scanner for the represented scan, but the engine does not own the response decision. Wardveil Policy decides the allowed next action. Wardveil Protect and Wardveil Quarantine execute containment or remediation only when explicitly authorized.

Recommended default flow for a confirmed malware match:

1. Emit a Wardveil `scan_finding` with `scan_result=malicious`.
2. Correlate the finding with resource identity and current policy.
3. Block opening, execution, synchronization, delivery, or download where the integrating product supports enforcement.
4. Quarantine the resource through the Wardveil Quarantine boundary rather than deleting it inside the scanner adapter.
5. Record the decision and action in Wardveil Audit.
6. Surface the evidence-backed state in Wardveil Security Center.

## Signature updates

Use ClamAV `freshclam` or an equivalent controlled update mechanism for signature databases. Signature freshness is part of runtime acceptance evidence. A running daemon with stale or unknown databases must not be represented as fully healthy malware protection.

Wardveil runtime health should eventually collect at least:

- ClamAV engine version;
- signature database version and update timestamp;
- daemon reachability;
- last successful scan timestamp;
- scan error rate;
- configured scan-size limits;
- quarantine execution health where applicable.

## Real-time protection

Do not equate ClamAV installation with complete endpoint antivirus. ClamAV provides scanning primitives and, on supported Linux systems, can participate in on-access scanning. Wardveil should own a separate endpoint-protection/agent layer for real-time filesystem event capture, policy enforcement, process protection, remediation, and cross-platform behavior.

The preferred product direction is therefore **Wardveil Malware Protection** inside Wardveil Security Center, backed initially by ClamAV for malware signatures and expanded over time with first-party and replaceable engines.

## Integration targets

Priority GoreeCloud consumers are:

- GoreeCloud Mail attachments before delivery/opening;
- GoreeCloud Drive uploads, downloads, shares, and restored content;
- GoreeCloud Browser downloads;
- GoreeCloud AI uploaded files and model/tool artifacts;
- GoreeCloud Code packages, release artifacts, and repository uploads;
- GoreeCloud Messenger attachments;
- Everkeep restore verification before recovered data is released to applications.

Each consumer must preserve the Wardveil fail-closed rule: unsupported, incomplete, unavailable, or invalid scan evidence is not a clean verdict.

## Runtime deployment baseline

A production deployment should separate the Wardveil application/service process from the scanner daemon while keeping communication local or private. Recommended baseline:

- `clamd` as a long-running supervised service;
- `freshclam` as the controlled signature updater;
- Unix socket access where services share a host;
- dedicated non-root service identities and least-privilege socket permissions;
- explicit maximum file, archive, recursion, and stream limits;
- resource quotas and timeouts to limit decompression bombs and scanner exhaustion;
- Wardveil-side queueing/backpressure for high-volume products;
- health checks that distinguish unavailable, degraded, stale-signature, and healthy scanner states;
- no direct public exposure of the `clamd` socket.

## Acceptance boundary

The reference adapter and CI tests establish protocol and mapping behavior only. They do not establish production malware-detection efficacy, signature freshness, endpoint protection, quarantine success, or product-specific runtime acceptance. Those claims require deployed ClamAV infrastructure and collected Wardveil runtime evidence.
