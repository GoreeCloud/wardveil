# Wardveil Cloudflare Runtime Evidence Collection

This document defines the guarded collection path for live Wardveil Cloudflare persistence evidence after the persistence Worker and internal acceptance probe are deployed.

## Collection model

The production deployment workflow deploys the persistence Worker and the non-public `goreecloud-wardveil-acceptance-probe` on one exact approved `main` revision. It then starts a local-only Wrangler acceptance runner inside GitHub Actions. The runner uses a Cloudflare remote service binding to call the deployed acceptance probe without introducing a public acceptance-probe route.

The deployed acceptance probe in turn calls `goreecloud-wardveil-persistence` through its internal service binding. This preserves the production service-to-service path while keeping record mutation unavailable through the generic public HTTP surface.

Cloudflare remote bindings are a development/testing transport mechanism for reaching deployed resources from locally executing Worker code. They do not make the target Worker public and do not transfer Wardveil security authority to Wrangler, GitHub Actions, or Cloudflare transport.

## Evidence collected in one guarded run

One successful deployment-and-collection run can establish revision-bound evidence for:

- exact deployed revision matching;
- the canonical persistence `/healthz` endpoint;
- authorized service-binding append/read;
- duplicate-record rejection;
- consumer-checkpoint non-regression;
- persisted payload-digest verification;
- Durable Object PITR capability/bookmark availability;
- execution of the real Durable Object retention `alarm()` handler in the dedicated acceptance tenant;
- a bounded failure-path marker independently observed through Cloudflare Worker tail evidence; and
- absence of a generic public `POST /records` mutation surface.

Acceptance records are `test_only`, use the `transient` retention class, and are scoped to the dedicated `wardveil-runtime-acceptance` tenant. Shortened alarm scheduling is accepted only for that tenant; it cannot target arbitrary production tenants. The bounded observability exercise deliberately fails without mutating a production record and must be corroborated by Cloudflare tail output rather than by the probe's return value alone.

## Evidence intentionally left pending

The deployment workflow must not self-certify recovery authority. After the expanded runtime probe and independent Cloudflare tail observation complete, the remaining acceptance requirement is:

- an Everkeep-governed restore-verification exercise against the same exact deployed revision.

PITR availability is not restore verification. Deployment success is not runtime acceptance. Storage health is not evidence that an identity, session, device, file, account, application, service, or other resource is Protected by Wardveil.

## Acceptance-state boundary

The workflow emits a machine-readable revision-bound evidence manifest into the GitHub Actions log and job summary. The manifest must remain `acceptance_status: unaccepted` until every required check in the canonical Cloudflare runtime-acceptance contract has passed for the same exact deployed revision.

The internal acceptance probe itself may report only `unaccepted` or `degraded`; it has no capability to promote production status to `accepted`. Even when retention and observability exercises pass, Everkeep restore verification remains a separate acceptance authority.

## Authority boundaries

Wardveil remains authoritative only for Wardveil-native security records and semantics within its declared scope. Cloudflare provides infrastructure and transport. GoreeCloud Mesh provides coordination. Privacy Shield remains the privacy and minimization authority. Everkeep remains the resilience, backup, restore, and recovery-verification authority.

No evidence-collection workflow may manufacture, extend, reinterpret, or upgrade security state, producer evidence validity, incident closure, malware cleanliness, authorization, trust, or a Protected by Wardveil claim.
