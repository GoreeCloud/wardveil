# Wardveil Cloudflare Deployment and Acceptance

This document defines the deployment and acceptance boundary for the Wardveil Security persistence Worker and SQLite-backed Durable Object adapter.

## Deployment unit

- Worker: `goreecloud-wardveil-persistence`
- Durable Object binding: `WARDVEIL_PERSISTENCE`
- Durable Object class: `WardveilPersistenceDO`
- Storage: SQLite-backed Durable Object storage
- Public HTTP surface: health/readiness only
- Mutation surface: authenticated Cloudflare service binding / RPC only

## Required deployment properties

Production dispatch is controlled from authoritative `main`, but the deployed bytes are not inferred from the workflow-control commit. The workflow requires `expected_sha` to exactly match `qualification/seal-candidate.json#source_revision`, proves that candidate is an ancestor of the governing `main` revision, then checks out and deploys that exact Seal source. Runtime evidence records both the Seal source/deployed revision and the separate workflow-control revision.

A production candidate must preserve the repository `cloudflare/wrangler.jsonc` configuration or an explicitly reviewed environment-specific derivative from that declared Seal source, including the SQLite Durable Object migration, service-binding-first mutation boundary, explicit compatibility date, observability configuration, and absence of secrets in source control.

Production acceptance requires evidence that: the deployed Worker revision matches an accepted repository revision; `/healthz` reports the expected schema and bounded storage-health state; authorized internal RPC can append/read records; duplicate IDs fail safely; consumer checkpoints cannot regress; retention alarms create maintenance evidence without rewriting surviving records; payload digests verify after readback; PITR availability is distinguished from restore verification; observability captures Worker/Durable Object failures; and no public endpoint grants generic write, checkpoint, retention, migration, or recovery authority.

## Security boundary

Cloudflare storage, encryption-at-rest, transport security, PITR availability, health status, and successful deployment are infrastructure evidence only. They do not create, extend, reinterpret, or upgrade Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, or Security Center state.

A successful `/healthz` response means the persistence adapter is reachable and can report its own bounded storage health. It does **not** mean a user, account, session, device, file, application, service, or infrastructure resource is protected by Wardveil.

## Recovery boundary

PITR availability is not restore verification. Recovery acceptance requires an explicit recovery exercise against a safely isolated target, integrity verification after restoration, checkpoint/record consistency checks, and evidence suitable for Everkeep coordination. Everkeep remains GoreeCloud's resilience and recovery authority.

## Production acceptance state

Source validation and Cloudflare Pages preview success do not prove that the Worker/Durable Object backend has been deployed or accepted in production. A newer workflow-control commit also does not silently replace the frozen Seal source being qualified. Until live exact-candidate Worker evidence is collected, production runtime status remains **unaccepted**.


## October 4, 2026 deployment preflight

GitHub Actions run `37236563970` dispatched the governed production workflow from authoritative `main` for exact Seal source `cc493530c02925a4404c54d2767c15d9fbfa0835`.

Candidate identity, ancestry, and exact checkout checks passed. The run then stopped at the required environment-input preflight before Wrangler setup or any deployment step.

The production environment did not provide the three required inputs named by the workflow: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `WARDVEIL_HEALTH_URL`.

No Worker deployment, runtime probe, Durable Object mutation, or production acceptance evidence occurred. Runtime acceptance remains unaccepted until those environment inputs are provisioned through the authorized configuration process and a fresh exact-candidate run succeeds.
