# Wardveil Persistence Abstraction

Wardveil persistence stores and transports security records; it does **not** become the authority for the security state contained in those records.

## Goals

- transactional append and checkpoint updates;
- durable consumer checkpoints without regression;
- explicit schema-version handling and fail-closed migration behavior;
- encryption-at-rest provider interfaces without hard-coding a storage vendor;
- integrity verification for persisted records;
- retention enforcement as a storage responsibility that cannot extend producer evidence validity;
- backup creation and restore-verification evidence;
- storage-health evidence that can be shown in Wardveil Security Center without becoming a `Protected by Wardveil` claim.

## Transaction boundary

A transaction may stage security records and consumer checkpoints. Validation and encryption/transformation complete before the adapter mutates persistent state. Any malformed, duplicate, non-authoritative, or regressing input rejects the transaction instead of partially committing it.

## Checkpoints

Consumer checkpoints are independent per consumer. A checkpoint may move forward after the consumer has successfully processed the corresponding records. It may not silently move backward. A checkpoint is delivery state, not security evidence.

## Schema and migration

Persisted records carry an explicit schema version. An adapter must reject unsupported versions and must never perform an implicit downgrade. Production adapters must provide reviewed, reversible migration plans with backup/restore evidence before a destructive schema change.

## Encryption at rest

The reference defines an `EncryptionProvider` interface. The included passthrough implementation deliberately reports `unencrypted_reference` and degraded storage health; it exists only so the abstraction can be tested without pretending encryption is configured. Production adapters must use an approved key-management and encryption implementation and must not place plaintext secrets in persistence merely because storage encryption exists.

## Retention

Retention policy controls how long a stored transport/persistence copy exists. It does not extend `valid_until`, convert stale evidence into current evidence, or prove a protection remains active. Retention changes should themselves be auditable.

## Backup and recovery

Backup availability and restore verification are separate states. A backup being present is not proof that it can be restored. Wardveil may surface backup/recovery evidence, while Everkeep remains the GoreeCloud resilience and recovery authority.

## Storage health

Storage-health evidence can report transaction capability, integrity verification, encryption-at-rest configuration, retention enforcement, backup state, and recovery verification. `StorageHealthEvidence.protection_claim` is always false in the reference contract. Healthy storage is an operational prerequisite, not proof that an identity, device, session, file, account, application, service, or infrastructure control is protected.

## Acceptance boundary

`reference/wardveil_persistence.py` is an in-memory conformance implementation. It does not establish a production database, Cloudflare Durable Object/D1 deployment, event broker, production key management, backup platform, disaster-recovery acceptance, or Stable qualification. A production adapter requires product-specific deployment, persistence, encryption, migration, backup, restore, retention, monitoring, and failure-mode evidence.

## Production qualification boundary

Production persistence qualification is governed by `contracts/wardveil.persistence-production-qualification.schema.json`, validated by `scripts/validate_wardveil_persistence_production_qualification.py`, and recorded only under `qualification/persistence-production/*.json`.

This qualification layer is **non-authorizing** and is **not production acceptance**. A complete qualification must bind an exact Wardveil source revision and tree, persistence implementation, backend/version, deployment boundary, environment, and topology, then carry current content-addressed evidence for durability across restart/recovery, transaction atomicity, concurrent-writer integrity, encryption and key custody, retention enforcement, backup/restore, migration/rollback, tamper detection, storage-failure behavior, access-control isolation, privacy-safe observability, operational monitoring, and the Everkeep recovery boundary.

Passing this qualification cannot by itself authorize deployment, production acceptance, a `Protected by Wardveil` claim, a `Covered` state, a release, or Stable qualification. Production runtime acceptance, target-system execution/readback, approved Identity/key custody, Everkeep recovery acceptance, monitoring, rollback, and the other applicable Integral Platform System gates remain separate.

There are currently no production persistence qualification records. Existing in-memory, SQLite, and Cloudflare persistence references remain bounded to their separately verified source/runtime scopes.

