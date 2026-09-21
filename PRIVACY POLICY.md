# Wardveil Security Privacy Policy

## Status and scope

Wardveil Security is in Development. This repository defines security contracts, reference implementations, validation, evidence models, and bounded runtime integrations. Source presence or CI success does not establish a production deployment, production data-processing practice, or a `Protected by Wardveil` claim.

This policy describes the privacy requirements that Wardveil-controlled software and services must preserve as they are implemented and accepted.

## Privacy authority

GoreeCloud Privacy Shield remains the platform-wide privacy and data-use authority. Wardveil Security is the security and protection authority. Wardveil may consume minimized Privacy Shield status or use Privacy Shield decisions where explicitly integrated, but it must not mint, broaden, replace, or silently infer Privacy Shield authority.

Missing, stale, malformed, unavailable, or unaccepted privacy evidence must fail closed to a non-passing state.

## Data minimization

Wardveil must collect, process, retain, and expose only the information necessary for the security function being performed. Security evidence, audit records, findings, quarantine state, health signals, and operational diagnostics must avoid unnecessary personal content and identifiers.

Reusable credentials, passwords, authentication tokens, private keys, recovery codes, secret values, and unrelated private file contents must not be placed in ordinary Wardveil evidence, logs, dashboards, repository files, or status payloads.

## Security scanning and protected content

A security operation may inspect supported content only within its authorized runtime boundary and for its declared security purpose. The ability to inspect content does not authorize unrelated collection, secondary use, disclosure, or indefinite retention.

Raw protected content should not be copied into shared evidence when a digest, bounded finding, reference, or minimized result is sufficient.

## Logging, telemetry, and evidence

Wardveil-controlled logging and telemetry must be privacy-conscious, purpose-limited, and bounded to operational and security needs. Source validators and synthetic fixtures do not establish production telemetry acceptance.

Any production observability path must separately satisfy GoreeCloud Observability, Privacy Shield, Identity, retention, access-control, and security requirements before it is represented as accepted.

## Third-party and replaceable components

Wardveil may use narrowly scoped supporting components such as ClamAV, SQLite, Cloudflare-hosted candidates, or other approved infrastructure. Those components do not inherit Wardveil authority merely by integration.

A provider or dependency must not receive private data beyond what is required for its accepted purpose and deployment boundary. Provider-specific production use requires its own security, privacy, operational, recovery, and acceptance evidence.

## Identity and access

GoreeCloud Identity remains authoritative for production identities, authentication, authorization, credentials, signing keys, sessions, and related trust. Wardveil must use least privilege, explicit authorization, and bounded service identities for protected operations.

## User-facing privacy state

Security Center and other Wardveil-controlled interfaces must distinguish security state from Privacy Shield privacy state. A Wardveil presentation must not imply that privacy protection exists merely because Wardveil is healthy, or that a Privacy Shield record is a Wardveil-owned enforcement result.

## Retention, deletion, recovery, and export

Privacy Shield governs applicable privacy constraints for retention, deletion, export, transfer, and other data-use effects. Everkeep governs recovery and preservation semantics. Wardveil must preserve those authority boundaries when security evidence participates in backup, restore, quarantine, incident response, or recovery workflows.

## Development and production boundary

Current source includes validated Development foundations and bounded runtime evidence for specific scopes. Overall Wardveil production acceptance, complete privacy integration, current Policy and Observability integration, accepted Everkeep recovery, and Stable qualification remain open.

This policy must be updated when verified implementation or accepted production behavior materially changes.
