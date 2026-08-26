# Wardveil Cloudflare Persistence Adapter

This directory contains the first deployment-oriented persistence adapter for Wardveil Security Foundation 0.8. It maps the accepted Wardveil persistence contract onto a Cloudflare Worker plus a SQLite-backed Durable Object namespace.

## Architecture

Each bounded Wardveil tenant/security domain is routed deterministically to one `WardveilPersistenceDO` instance. The Durable Object owns ordered SQLite persistence, consumer checkpoints, retention maintenance evidence, schema metadata, and point-in-time-recovery health evidence for that coordination atom.

The outer Worker is service-binding/RPC-first. Public HTTP exposes only `/healthz`; record mutation, record reading, checkpoint mutation, and tenant storage health are RPC methods intended for explicitly authorized GoreeCloud service bindings. The adapter does not create a public generic security-record mutation API.

## Storage behavior

The v1 SQLite schema provides:

- ordered Wardveil records with unique `record_id` values;
- authoritative producer and scope preservation inside the stored payload;
- SHA-256 payload digests;
- bounded retention classes;
- independent non-regressing consumer checkpoints;
- maintenance evidence for retention execution;
- schema-version metadata; and
- Durable Object database-size and PITR bookmark health evidence.

Retention enforcement uses the Durable Object alarm API. The reference schedule is every six hours. Expiry removes the storage copy only; it does not reinterpret producer evidence, revoke or extend security validity, or imply deletion from the authoritative source system.

## Transactions and migration

Multi-step record insertion and checkpoint advancement use SQLite Durable Object transactional behavior. The current adapter supports schema version 1 only and fails closed on an unexpected schema version. Future schema versions must add explicit migration steps and acceptance tests rather than silently mutating unknown data layouts.

## Encryption and recovery

Cloudflare documents SQLite-backed Durable Objects as encrypted at rest automatically with Cloudflare-managed keys and encrypted in transit inside the Cloudflare network. The adapter reports that platform property as storage-health evidence only. It does not claim customer-managed key control.

SQLite-backed Durable Objects expose point-in-time recovery bookmarks. The adapter reports the current bookmark as recovery evidence. A bookmark being available is not proof that a GoreeCloud disaster-recovery exercise succeeded; production recovery acceptance still requires an exercised restore workflow and Everkeep-aligned recovery evidence.

## Authority boundary

Persistence is not a security-state authority. The adapter may preserve and deliver authoritative Wardveil records but may not manufacture, upgrade, extend, repair, or reinterpret Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, or Security Center state.

`storage operational` is not equivalent to `Protected by Wardveil`.

A successful write proves only that a record was accepted into this persistence boundary. It does not prove that the underlying protection action executed, that a finding is true, or that an incident is resolved.

## Deployment boundary

The source is intentionally deployable but is not recorded as a production deployment by this document. Production acceptance additionally requires:

- a connected Cloudflare account and reviewed Worker/Durable Object deployment;
- `wrangler types` generation and TypeScript compilation against the deployed binding configuration;
- explicit service-binding consumer authorization;
- tenant/shard sizing and data-location review;
- operational retention verification;
- recovery drill evidence;
- monitoring/alerting integration;
- Privacy Shield minimization review for stored record fields;
- Everkeep recovery coordination where applicable; and
- product-specific Stable acceptance.

No Cloudflare deployment, DNS change, public route, credential, secret, or production security-control mutation is implied by merging this adapter source.
