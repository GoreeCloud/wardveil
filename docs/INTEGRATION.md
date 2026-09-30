# Wardveil Security Integration Guide

## Purpose

This guide defines how GoreeCloud applications and services integrate with Wardveil Security while preserving the technical authority of the systems that actually enforce security.

Wardveil integration has two distinct surfaces:

1. evidence-backed security state and presentation; and
2. bounded runtime execution for explicitly authorized cross-service protection actions.

Neither surface transfers authority merely because Wardveil is present.

## Integration principles

1. **Preserve the underlying authority.** A Wardveil surface may summarize security state, and a Wardveil authorization may request an action, but the underlying producer or executor retains authority for the controls and resources it owns.
2. **Do not turn branding into evidence.** Wardveil branding alone is not proof that a control succeeded.
3. **Use evidence-scoped protection claims.** Display **Protected by Wardveil** only when the current displayed scope has authoritative evidence supporting that protection state.
4. **Keep security details useful but minimized.** Do not expose secrets, reusable credentials, private keys, tokens, recovery codes, sensitive topology, raw diagnostics, or unnecessary personal information merely to make a Wardveil view appear detailed.
5. **Use Glaze UI.** Wardveil-facing user interfaces follow Glaze UI semantics and accessibility expectations.
6. **Keep product identities intact.** Wardveil may appear within GoreeCloud applications without replacing those products or their technical responsibilities.
7. **Keep Privacy Shield intact.** GoreeCloud Privacy Shield remains the platform-wide privacy-control identity and shared privacy foundation. Wardveil may present sanitized Privacy Shield status but does not absorb its authority or runtime acceptance boundary.
8. **Separate policy from execution.** An authoritative Wardveil Policy decision is not, by itself, permission for a service to mutate another system.
9. **Fail closed on authorization uncertainty.** A required runtime authorization that is missing, stale, invalid, tampered, mismatched, unsupported, or replay-conflicted must not be executed.

## Appropriate uses

Appropriate Wardveil integrations include:

- security posture summaries and settings;
- actionable security warnings and recommendations;
- device, identity, session, and contextual trust state;
- vulnerability and security-update status;
- exposure and network-protection status;
- integrity and verification status;
- security-event history and audit presentation;
- file, attachment, download, package, URL, and payload scanning;
- quarantine and incident-response workflows;
- sanitized Privacy Shield status inside a broader protection view;
- explicitly authorized cross-service enforcement through the Wardveil 0.9 runtime authorization contract.

## Inappropriate uses

Do not use Wardveil to:

- rename a technical authority that already has a defined role;
- imply that a service is secure merely because Wardveil branding is present;
- conceal which system, policy, service, user, device, or control produced a security state;
- create a security module solely from a reserved Wardveil name;
- duplicate authentication, firewall, VPN, secrets-management, vulnerability-management, backup, recovery, or Privacy Shield responsibilities without an approved architecture;
- collect additional telemetry or sensitive data merely to populate Wardveil presentation;
- convert Privacy Shield protection into a `Protected by Wardveil` claim;
- treat a policy record, GoreeCloud Mesh delivery, or runtime-authorization envelope as proof that the target action actually executed;
- bypass the target executor's own action/resource permissions because Wardveil authorized a request.

## Minimum presentation contract

A Wardveil-integrated surface should be able to answer, where applicable:

- **What is the security state?**
- **What scope does the state apply to?**
- **What authoritative system or control produced the state?**
- **When was the state last evaluated?**
- **Is the state verified, warning, degraded, unknown, or not applicable?**
- **What action can an authorized user or service take?**
- **What information is intentionally withheld for privacy or least privilege?**

Missing evidence is not passing evidence. Unknown, stale, unavailable, skipped, or unverified required security evidence must remain non-passing and must never be silently converted into a protected state.

## Interoperable status records

Applications that need a shared machine-readable representation should use `STATUS.md` and `contracts/wardveil.status.schema.json`.

The normalized presentation vocabulary is:

- **Protected** — current evidence supports the defined protection scope.
- **Attention** — action or review is recommended.
- **Degraded** — a protection or evidence path is operating below its intended state.
- **Unknown** — the required evidence is unavailable, stale, incomplete, or not yet verified.
- **Not applicable** — the control does not apply to the current scope.

These labels are presentation semantics only. They do not replace application-specific state machines or policy definitions.

A `Protected by Wardveil` claim is permitted only for the explicit scope of a record whose normalized state is protected, whose underlying source is authoritative, and whose required evidence is current. The claim must fail closed to false whenever those conditions are not satisfied.

Privacy Shield status uses its own producer-to-consumer contract. Wardveil's permitted read-only mapping is defined separately in `PRIVACY-SHIELD.md`; Privacy Shield records never independently authorize `Protected by Wardveil`.

## Runtime execution integration

Foundation 0.9 defines `RUNTIME-AUTHORIZATION.md` and `contracts/wardveil.runtime-authorization.json` as the canonical cross-service execution boundary.

The intended high-impact flow is:

`authoritative evidence -> Wardveil Trust/Policy -> policy decision -> execution authorization -> target executor -> Wardveil Protect result -> Wardveil Audit`

Before executing a supported cross-service high-impact action, an executor must validate:

- the supported runtime-authorization contract and signature algorithm;
- an authoritative, current policy record;
- the exact SHA-256 digest and identity of that policy record;
- the exact action and target scope;
- the exact intended executor identity;
- correlation identity;
- issue time and expiry, with authorization never outliving policy validity;
- replay nonce and idempotency key;
- cryptographic integrity of the authorization material.

A mismatch or validation failure must fail closed. Exact retries of an already accepted authorization may be idempotent, but nonce reuse for different authorization material must be rejected.

After Wardveil authorization succeeds, the target executor must still authenticate its caller as required and enforce its own least-privilege action/resource authority. A valid Wardveil authorization cannot grant permissions the executor does not already possess.

High-impact actions still require a concrete execution handler. The resulting protection action and audit receipt are evidence of execution; the authorization envelope alone is not.

## GoreeCloud Mesh boundary

GoreeCloud Mesh remains the coordination and governance plane. Mesh may carry evidence, policy records, or runtime authorization over an approved authenticated delivery path.

Mesh delivery authenticity and Wardveil execution authorization are separate checks. Successful delivery does not create execution authority, and a valid execution authorization does not prove transport security by itself.

## Cryptography and secrets boundary

The dependency-free source reference uses `HMAC-SHA256-reference-only` for conformance testing. It does not prescribe production signing technology or key storage.

Signing keys, private keys, reusable credentials, session tokens, cookies, and other reusable authentication material must never be embedded in Wardveil authorization envelopes or shared evidence records.

Production runtime acceptance requires approved key management, authenticated transport, executor authentication, durable replay/idempotency state, key rotation and revocation procedures, durable audit receipts, and runtime failure/replay testing.

## Security and privacy boundary

Wardveil integrations should prefer bounded, structured, privacy-conscious evidence. Broad presentation, observability, and authorization paths should avoid reusable secrets, passwords, authentication material, request or response bodies, cookies, private keys, recovery codes, unnecessary network identifiers, and raw exception content unless a separately authorized security workflow genuinely requires them.

The authoritative system should retain detailed evidence when required. Wardveil-facing integrations should normally receive only the minimum state, source attribution, timestamps, internal scope identifiers, evidence references, and authorized action information necessary for the decision.

For Privacy Shield specifically, Wardveil accepts only status that explicitly excludes raw private activity, credentials, and identifying content. Wardveil does not request browsing, DNS, network, or application-private activity merely to render Privacy Shield status.

## Production acceptance boundary

Source contracts, reference HMAC verification, tests, and CI do not prove deployed runtime protection. Each executor integration needs target-environment evidence for its transport, identity, replay/idempotency durability, key management, audit persistence, failure behavior, and local permission enforcement before production acceptance.

A runtime-authorization envelope by itself never authorizes a broad `Protected by Wardveil` claim.

## Canonical icon boundary

The canonical Wardveil icon may be used only according to `ICON.md`. Icon presence never substitutes for status semantics, execution evidence, or production runtime acceptance.

## Original identity boundary

Wardveil Security is an original GoreeCloud identity created for GoreeCloud's platform-wide security system. Current GoreeCloud project records do not identify a conflicting Wardveil Security identity.

Formal trademark or name-clearance work is optional future due diligence. It is not a current integration or technical acceptance gate.
