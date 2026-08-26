# Wardveil Durable Records and Subscriptions

This document defines the reference persistence and subscription boundary for Wardveil Security Foundation 0.8.

## Principles

- Storage is append-only at the logical record layer.
- Storage does not become authoritative for security state merely because it retains a record.
- Retention expiry controls how long a stored transport/event copy is retained; it does not extend or reinterpret producer-defined security evidence validity.
- Consumer cursors advance only after explicit acknowledgement.
- Failed deliveries remain retryable until the bounded attempt limit is reached.
- Dead-letter state records delivery failure; it does not alter the underlying Wardveil record.
- Security Center rebuilds from retained authoritative records and must still apply its own evidence and presentation rules.

## Retention Classes

The reference model defines bounded classes: `transient`, `security_event`, `incident_evidence`, and `audit_evidence`. A production deployment may use different durations, but retention must be policy-controlled, privacy-aware, and auditable.

Retention cleanup may remove expired stored copies. It must not rewrite surviving records or manufacture replacement security evidence.

## Subscription Semantics

Each consumer maintains an independent cursor. Polling produces records after that cursor and marks them pending. Acknowledgement advances delivery state. Failures increment a bounded attempt counter and may move a delivery to a dead-letter collection after the configured limit.

No cursor advancement is allowed merely because a record was fetched. This preserves at-least-once delivery semantics in the reference model.

## Security Center Rebuild

The reference store can replay retained records into the Wardveil Security Center read model. Rebuild is presentation recovery, not security-state creation. Expired or otherwise invalid security evidence remains subject to the authoritative runtime contract and Security Center rules.

## Production Boundary

The reference implementation is in-memory and dependency-free. It is a conformance starting point, not a production database, event broker, cryptographic ledger, backup system, or GoreeCloud Mesh runtime. Production storage requires durable persistence, access control, encryption, key management, backup/recovery, observability, retention enforcement, schema migration, and product-specific acceptance evidence.
