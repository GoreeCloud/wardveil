# Wardveil Service Identity and Signing Key Lifecycle

## Purpose

Wardveil Foundation 0.9 separates three security questions that must not collapse into one another:

1. **Who is this service?** — first-party service identity.
2. **May this service perform this Wardveil role?** — capability assignment.
3. **Which current key proves this authorization came from that issuer?** — signing-key identity and lifecycle.

A service name, valid signature, durable claim, GoreeCloud Mesh delivery, or Wardveil Policy decision does not independently grant authority over a target resource.

The machine-readable contract is `contracts/wardveil.service-identity.json`. The dependency-free reference is `reference/wardveil_service_identity.py`.

## Service identities

Foundation 0.9 defines explicit service identities with status and capability bindings.

Canonical capability names in this stage are:

- `issue_execution_authorization` — permits an active Wardveil Policy issuer to create an execution authorization;
- `execute_protection_action` — permits an active protection executor identity to be the bound executor of that authorization.

Statuses are:

- `active` — identity may be evaluated for its declared capabilities;
- `suspended` — identity fails closed without destroying its historical evidence identity;
- `revoked` — identity fails closed and must not be trusted for new authorization or execution verification.

Unknown, not-yet-valid, expired, suspended, revoked, or capability-mismatched identities fail closed.

## Signing-key identity

Every Foundation 0.9 execution authorization now carries `signing_key_id` as part of the signed material.

The key ID is metadata. The signing secret or private key is not.

The key ID lets a verifier select the correct currently trusted key during rotation and provides evidence about which key authorized an action without storing secret material in the authorization envelope.

Signing key material must never be stored in:

- authorization envelopes;
- durable execution claims or receipts;
- Wardveil Audit records;
- Security Center records;
- application source;
- repository configuration;
- logs or CI output.

## Key lifecycle

Foundation 0.9 defines three key states:

- `active` — may sign and verify while within its validity window;
- `retired` — may not sign, but may verify during a bounded rotation overlap;
- `revoked` — may neither sign nor verify, even if a previous overlap window has not elapsed.

The reference keyring caps rotation overlap at 24 hours. That is a conformance maximum for the source model, not a production recommendation. Production should use the shortest overlap compatible with safe rollout and clock/transport behavior.

Rotation performs two distinct actions:

1. retire the old key and bound its remaining verification window;
2. activate a new key for signing.

Revocation is stronger than retirement. A revoked key fails immediately.

## Authorization flow

The stronger Foundation 0.9 flow is:

`authoritative evidence -> Wardveil Policy -> active issuer identity -> active signing key -> key-ID-bound execution authorization -> durable claim -> active executor identity -> target executor -> Wardveil Protect result -> durable receipt -> Wardveil Audit`

The identity-aware reference helpers are:

- `create_identity_bound_execution_authorization(...)`;
- `verify_identity_bound_execution_authorization(...)`.

The original direct HMAC helper remains available as a dependency-free compatibility/conformance path. It is not the production identity model.

## Cloudflare key-storage candidate

For the Cloudflare-hosted Wardveil candidate runtime, secret material must be supplied through an encrypted secret binding rather than committed configuration.

Cloudflare Secrets Store is the preferred reusable account-level option when it satisfies production availability, permission, operational, and support requirements at deployment time. A per-Worker secret binding remains an alternative implementation mechanism.

The repository must contain only binding names or deployment metadata. It must not contain the secret value.

Production deployment must verify at deployment time that:

- the secret is scoped for Workers;
- the deployment principal has only the permissions required to bind the secret;
- the Wardveil Worker can access the binding in the intended environment;
- the secret value is not exposed by source, configuration, CI output, logs, acceptance evidence, or failure messages;
- rotation and revocation can be completed without requiring a source-code change for the secret value itself.

No production secret is created or stored by this source milestone.

## GoreeCloud Mesh

GoreeCloud Mesh may carry authenticated authorization messages between first-party systems, but Mesh transport identity and Wardveil execution identity remain separate checks.

A valid Mesh delivery cannot reactivate a suspended or revoked Wardveil service identity, cannot make a revoked signing key valid, and cannot grant a target executor a capability it does not possess.

## Privacy Shield

Privacy Shield data-minimization requirements apply to service-identity evidence.

Identity and key metadata should use stable first-party identifiers, bounded reason codes, timestamps, statuses, capabilities, and key IDs. Raw user content, credentials, cookies, authorization headers, session tokens, private keys, signing secrets, and unrelated browsing or application activity are not required.

## Everkeep

Everkeep remains the resilience and recovery authority. Wardveil key recovery or emergency rotation procedures may rely on approved Everkeep preservation/recovery controls, but this does not transfer security-policy or execution authority to Everkeep.

Recovery must never silently restore a revoked key to active trust.

## Production acceptance

This source milestone remains `unaccepted` for production runtime use.

Acceptance still requires evidence for:

- an approved production signature algorithm and key-management system;
- production service-identity issuance and authentication;
- least-privilege issuer/executor capability assignment;
- deployed secret/key bindings without source exposure;
- runtime key rotation overlap behavior;
- immediate key revocation behavior;
- suspended/revoked service-identity behavior;
- unknown-key and algorithm-mismatch failure behavior;
- authenticated authorization transport;
- deployed durable execution state;
- at least one authorized high-impact executor;
- Audit and Security Center evidence containing key/identity metadata without secrets;
- tested recovery and emergency revocation procedures.

Passing source CI proves conformance of this implementation and its contracts. It does not prove deployed production identity, deployed key storage, or production execution protection.
