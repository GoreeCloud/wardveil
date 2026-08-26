# Wardveil Security — GoreeCloud Mesh Event Transport

Wardveil Security may use GoreeCloud Mesh as a coordination and delivery plane for authorized Wardveil security records. Mesh transports and routes Wardveil records; it does not become authoritative for Wardveil security state, evidence semantics, trust decisions, policy decisions, findings, protection execution, quarantine state, incident state, or audit truth.

## Transport principles

- Wardveil records remain authoritative only when emitted by an authorized Wardveil producer or explicitly integrated authoritative producer.
- Mesh may route, persist, fan out, filter, and deliver bounded Wardveil envelopes according to authorization and retention policy.
- Mesh must not manufacture, upgrade, extend, reinterpret, or silently repair Wardveil records.
- The original Wardveil `correlation_id`, `record_id`, producer identity, represented scope, evidence references, timestamps, and validity boundary are preserved end to end.
- Delivery metadata is separate from security evidence. A successful Mesh delivery does not prove that a protection action succeeded.
- A duplicated envelope is not a new security event. Consumers must enforce replay/idempotency rules.
- Expired security evidence remains expired after transport. Mesh cannot extend `valid_until`.
- Sensitive payloads, credentials, secrets, private keys, authentication headers, recovery material, or unnecessary personal data are outside the default event-envelope boundary.

## Envelope

A Wardveil Mesh envelope contains envelope version, unique envelope ID, Wardveil record ID and correlation ID, authoritative producer ID, event type, represented routing scope, creation and expiry timestamps, payload digest, bounded retention class, authorized audience identifiers, replay key, signature metadata, and the original Wardveil runtime record.

The reference implementation uses HMAC-SHA256 only as a deterministic conformance mechanism. Production signing must use a GoreeCloud-approved service-identity and key-management design with rotation, revocation, audit, and least-privilege access. The reference key is never a production credential.

## Consumer authorization

A consumer must be explicitly authorized for the event type and represented resource type before the payload is delivered. Authorization applies to the envelope audience and does not grant the consumer authority to mutate the underlying security state.

Wardveil Security Center subscriptions are read-only by default. Delivery cannot itself prove execution success, quarantine release, incident closure, or any other security mutation.

## Replay protection

Each accepted envelope carries a replay key. Consumers maintain a bounded replay ledger for at least the envelope validity period. Re-delivery of the same replay key returns the original acceptance result and must not cause duplicate protection, quarantine, incident, or audit side effects.

## Retention

Retention is explicit and bounded by event class. Transport retention does not override Privacy Shield, application policy, or producer retention authority. If a shorter applicable retention boundary exists, the shorter boundary wins.

Reference retention classes are `transient`, `security_event`, `incident_evidence`, and `audit_evidence`. A retention class is metadata, not permission to retain indefinitely.

## Failure behavior

Malformed, unsigned or invalidly signed, expired, unauthorized, replay-conflicting, scope-incomplete, non-authoritative, or unsupported envelopes fail closed and are not delivered as valid security records.

Unknown or unsupported scan state remains non-clean after transport. An anomaly remains non-confirmatory after transport. Mesh correlation cannot upgrade either condition.

## Authority boundary

GoreeCloud Mesh is the coordination and governance plane. Wardveil Security remains the security-semantics and security-record authority. Privacy Shield remains the privacy authority. Everkeep remains the resilience and recovery authority. Glaze UI remains the interface system.

This transport reference does not establish production deployment, production key management, durable message-bus acceptance, Stable qualification, or product-specific runtime acceptance.
