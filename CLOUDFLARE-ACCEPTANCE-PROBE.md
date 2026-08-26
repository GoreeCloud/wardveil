# Wardveil Cloudflare Runtime Acceptance Probe

The Wardveil runtime acceptance probe is a separate internal Cloudflare Worker used to collect privileged production evidence from the Wardveil persistence Worker without exposing record mutation through a public HTTP API.

## Boundary

The probe is not a security-state authority, protection authority, recovery authority, or general-purpose administration API. It exists only to exercise the already-defined Wardveil Cloudflare runtime acceptance contract against an exact deployed revision.

The probe communicates with `goreecloud-wardveil-persistence` through a Cloudflare service binding named `WARDVEIL_PERSISTENCE_SERVICE`. Its Wrangler configuration disables `workers.dev` exposure and preview URLs, and its `fetch()` handler always returns HTTP 404. The acceptance operations are available only through Worker RPC.

## Revision Binding

The probe refuses to run unless the caller-supplied revision exactly matches the `EXPECTED_REVISION` value configured at deployment. `UNSET_AT_DEPLOYMENT` is never accepted. This prevents evidence collected against one Worker revision from being silently attached to another revision.

## Internal Acceptance Checks

A successful `runAcceptance(expectedRevision)` invocation can collect evidence for:

- authorized service-binding append and read;
- duplicate record rejection;
- persisted payload digest verification;
- consumer checkpoint non-regression;
- PITR capability/bookmark availability;
- execution of the real Durable Object retention alarm handler in the dedicated acceptance tenant.

Probe records use the `transient` retention class, are explicitly marked `test_only`, and use the dedicated `wardveil-runtime-acceptance` tenant/security domain. The short acceptance alarm is allowed only for that tenant and uses the same production `alarm()` handler that performs retention enforcement. It cannot be scheduled for arbitrary tenants.

## Bounded Observability Exercise

`runObservabilityFailure(expectedRevision, marker)` triggers an intentionally failing acceptance-only RPC in the dedicated acceptance tenant. The persistence Worker emits a structured `wardveil_acceptance_observability_probe` marker and then throws the expected `acceptance_observability_probe` error. The deployment workflow must independently observe that marker through Cloudflare Worker tail evidence before marking `observability_failure_evidence` passed.

The controlled failure does not mutate production records, grant remediation authority, or prove that unrelated security controls are observable.

## Evidence That Remains External

The following still require a different authority or observation path:

- deployed revision match from the deployment control plane;
- canonical public `/healthz` response;
- an Everkeep-governed restore verification exercise;
- independent Cloudflare tail observation of the bounded failure marker;
- confirmation that the public mutation surface remains absent.

The probe therefore cannot set production status to `accepted` by itself.

## Authority Rules

- Storage health is not Wardveil protection.
- Successful service-binding RPC is not proof that unrelated Wardveil controls executed.
- PITR availability is not restore verification.
- A retention-alarm acceptance exercise proves only the bounded maintenance path exercised for the acceptance tenant.
- An observability marker proves only that the bounded failure was captured through the configured observation path.
- A probe result does not extend producer evidence validity.
- Everkeep retains resilience and recovery authority.
- Privacy Shield minimization requirements continue to apply to acceptance-test records.
- GoreeCloud Mesh coordination does not gain security-state authority through this probe.

## Deployment

The probe must be deployed only after the persistence Worker revision being evaluated is known. Deployment must replace `EXPECTED_REVISION` with that exact revision through environment-specific Wrangler configuration or an equivalent controlled deployment mechanism; it must not be committed with a production revision baked into source.

The probe should be invoked from an authorized internal operator/coordinator Worker or equivalent Cloudflare-internal service-binding path. A public mutation or generic public acceptance endpoint must not be created merely to make testing easier.
