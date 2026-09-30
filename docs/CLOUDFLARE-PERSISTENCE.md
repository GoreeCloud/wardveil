# Wardveil Cloudflare Persistence Adapter

This directory contains Wardveil Security's deployment-oriented persistence adapter. It maps the accepted Wardveil persistence contract and Foundation 0.9 execution-state contract onto a Cloudflare Worker plus a SQLite-backed Durable Object namespace.

## Architecture

Each bounded Wardveil tenant/security domain is routed deterministically to one `WardveilPersistenceDO` instance. The Durable Object owns ordered SQLite persistence, consumer checkpoints, runtime execution-authorization claims, execution receipts, retention maintenance evidence, schema metadata, and point-in-time-recovery health evidence for that coordination atom.

The outer Worker is service-binding/RPC-first. Public HTTP exposes only `/healthz` and `/readyz`; record mutation, record reading, checkpoint mutation, execution-state mutation, execution-receipt reading, and tenant storage health are RPC methods intended for explicitly authorized GoreeCloud service bindings. The adapter does not create a public generic security-record or execution mutation API.

## Storage behavior

The v1 persistence schema provides:

- ordered Wardveil records with unique `record_id` values;
- authoritative producer and scope preservation inside the stored payload;
- SHA-256 payload digests;
- bounded retention classes;
- independent non-regressing consumer checkpoints;
- maintenance evidence for retention execution;
- schema-version metadata; and
- Durable Object database-size and PITR bookmark health evidence.

Foundation 0.9 also adds execution-state schema version 1 inside the same Durable Object. It provides:

- one durable claim per runtime-authorization nonce;
- a uniqueness boundary for each executor/idempotency-key pair;
- exact authorization-digest binding;
- persisted correlation, executor, action, scope, issue-time, and expiry bindings;
- fail-closed nonce and idempotency conflicts;
- `execution_reconciliation_required` for a claimed authorization without a finalized receipt;
- durable execution receipts containing the normalized authoritative Wardveil Protect record and its SHA-256 digest;
- receipt-integrity digests and bounded audit-evidence retention; and
- idempotent retrieval of an already finalized receipt without authorizing the side effect again.

Retention enforcement uses the Durable Object alarm API. The reference schedule is every six hours. Expiry removes eligible storage copies, execution claims, and execution receipts only according to their bounded retention rules; it does not reinterpret producer evidence, revoke or extend security validity, or imply deletion from an authoritative source system.

## Transactions and migration

Multi-step record insertion, checkpoint advancement, execution-authorization claiming, and receipt finalization use SQLite Durable Object transactional behavior. The base persistence schema remains version 1, and the execution-state extension has its own version 1 metadata. Unexpected versions fail closed. Future versions must add explicit migration and acceptance work rather than silently interpreting unknown layouts.

The execution-state claim is intentionally written before an external high-impact side effect. If the executor loses certainty after that claim and before a receipt is durably finalized, a retry receives `execution_reconciliation_required` rather than permission to execute again. The Durable Object cannot by itself make an external non-idempotent API exactly-once; the authoritative executor still requires idempotency or an equivalent state-reconciliation mechanism.

## Encryption and recovery

Cloudflare documents SQLite-backed Durable Objects as encrypted at rest automatically with Cloudflare-managed keys and encrypted in transit inside the Cloudflare network. The adapter reports that platform property as storage-health evidence only. It does not claim customer-managed key control.

SQLite-backed Durable Objects expose point-in-time recovery bookmarks. The adapter reports the current bookmark as recovery evidence. A bookmark being available is not proof that a GoreeCloud disaster-recovery exercise succeeded; production recovery acceptance still requires an exercised restore workflow and Everkeep-aligned recovery evidence.

Recovery of execution state must preserve the distinction between finalized and pending claims. A restored pending claim may represent an uncertain external side effect and must not be silently discarded or reset to unused authorization.

## Authority boundary

Persistence is not a security-state authority. The adapter may preserve and deliver authoritative Wardveil records but may not manufacture, upgrade, extend, repair, or reinterpret Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, or Security Center state.

`storage operational` is not equivalent to `Protected by Wardveil`.

`/healthz` is a liveness signal only. `/readyz` exercises the Worker-to-Durable-Object binding and validates the Durable Object schema/storage health path through a dedicated non-authorizing readiness tenant. Neither endpoint grants security-state, execution, or protection authority.

A successful write or execution-state claim proves only that the persistence boundary accepted that state. It does not prove that the underlying protection action executed, that a finding is true, or that an incident is resolved. A finalized execution receipt represents the authoritative Protect result it contains but does not grant the executor authority or prove unrelated controls succeeded.

## Deployment boundary

The source is intentionally deployable but is not recorded as a production deployment by this document. Production acceptance additionally requires:

- a connected Cloudflare account and reviewed Worker/Durable Object deployment;
- `wrangler types` generation and TypeScript compilation against the deployed binding configuration;
- explicit service-binding consumer authorization;
- authenticated executor identity and authorization transport;
- production signing/key-management and rotation/revocation controls;
- tenant/shard sizing and data-location review;
- operational retention verification;
- durable replay/idempotency and execution-receipt runtime evidence;
- executor-side idempotency or authoritative uncertain-outcome reconciliation;
- crash/replay/storage-failure recovery exercises;
- monitoring/alerting and Wardveil Audit/Security Center integration;
- Privacy Shield minimization review for stored record fields;
- Everkeep recovery coordination where applicable; and
- product-specific Stable acceptance.

No Cloudflare deployment, DNS change, public route, credential, secret, or production security-control mutation is implied by merging this adapter source.
