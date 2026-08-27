# Wardveil Security Threat Model

## Purpose

This threat model defines the security boundary for Wardveil Security itself. Wardveil must never become a source of false assurance, a secret store, or an authority that silently overrides the systems that actually enforce security.

Foundation 0.9 adds a bounded runtime execution-authorization path. That path is intentionally separate from presentation, policy decision, transport delivery, and the target executor's own resource authority. Presentation-only integrations remain read-only with respect to underlying controls unless they separately implement the authorized execution contract.

## Protected assets

Wardveil protects:

- the integrity and provenance of security evidence;
- the distinction between authoritative and derived state;
- the integrity of policy decisions and execution authorization;
- exact target/action/executor binding for high-impact actions;
- replay and idempotency correctness;
- auditability of security-changing operations;
- the privacy of data carried through shared Wardveil contracts.

## Trust boundaries

1. **Authoritative producer** — an application, service, policy engine, scanner, identity system, firewall, backup system, or other control that owns underlying technical state.
2. **Wardveil adapter** — code that converts authoritative state into a Wardveil contract.
3. **Wardveil Trust/Policy** — Wardveil-native decision services that evaluate evidence and produce scoped, expiring decisions.
4. **Authorization issuer/verifier** — the boundary that binds a supported Policy decision to an exact executor request.
5. **Transport** — GoreeCloud Mesh or another approved authenticated channel carrying records or authorization without inheriting their technical authority.
6. **Target executor** — the application, service, or infrastructure adapter that owns permission to perform a requested action on a target resource.
7. **Wardveil consumer** — a GoreeCloud interface that renders Wardveil status through Glaze UI.
8. **Operator** — an authorized administrator interpreting state, evidence age, scope, incidents, quarantine, and remediation.

No boundary may implicitly grant another boundary authority it does not already possess.

## Primary threats and required controls

### False protection claims

A consumer could display `protected` when evidence is missing, stale, incomplete, unavailable, or unverified.

**Controls:** fail closed; require explicit scope, evidence source, observation time, and freshness; never infer success from Wardveil branding, transport success, a policy decision, or an authorization envelope alone.

### Evidence spoofing or provenance loss

Untrusted or incorrectly attributed evidence could be rendered or consumed as authoritative.

**Controls:** identify authoritative producers; preserve source identity; validate supported contracts, record identity, evidence references, and freshness; unknown provenance is non-passing.

### Scope confusion

A valid result for one control, resource, device, executor, action, or time window could be presented or executed as a broader authorization.

**Controls:** status and authorization are scope-bound; runtime authorization binds the exact policy digest, record ID, correlation ID, action, scope, and executor; aggregation never broadens producer authority.

### Policy-as-command confusion

A service could treat any valid Wardveil Policy decision as a command to mutate another system.

**Controls:** policy decision and execution authority are separate; high-impact cross-service execution requires the Foundation 0.9 runtime authorization contract plus the target executor's own action/resource authority.

### Authorization substitution or tampering

An attacker could reuse a valid authorization with a different policy, action, target, executor, or correlation identity.

**Controls:** bind and sign the exact policy-record SHA-256 digest, policy ID, correlation ID, action, scope, executor ID, replay nonce, idempotency key, issue time, and expiry; compare signatures in constant time; any mismatch fails closed.

### Stale or future authorization

An old authorization could be replayed after policy changed, or a future-dated authorization could extend authority incorrectly.

**Controls:** short validity window; maximum five-minute authorization TTL; authorization may never outlive policy validity; reject expired, malformed, or future-dated authorization outside permitted clock skew.

### Replay and nonce collision

A valid high-impact request could be executed repeatedly, or a nonce could be reused for different authorization material.

**Controls:** replay nonce plus idempotency key; exact retry may be accepted only as the same authorization identity; conflicting nonce reuse fails closed; executor idempotency prevents repeating the mutation; production requires durable shared replay/idempotency state appropriate to executor scope.

### Replay-ledger loss or split brain

In-memory or partitioned replay state could allow the same authorization to be accepted by multiple executor instances.

**Controls:** the source ledger is reference-only; production acceptance requires a durable/shared consistency model, explicit failure behavior when the ledger is unavailable, and concurrency/restart tests. Ledger unavailability must not silently downgrade replay protection.

### Signing-key leakage or misuse

A leaked authorization signing key could allow forged requests.

**Controls:** never include signing secrets in authorization envelopes, shared evidence, source, diagnostics, or public configuration; production requires approved key management, least-privilege key access, rotation, revocation, audit, and compromise procedure. The dependency-free HMAC reference is not production key-management acceptance.

### Transport-authentication confusion

A correctly authenticated GoreeCloud Mesh delivery could be mistaken for authorization to execute, or a valid authorization could be assumed to prove secure transport.

**Controls:** validate transport and execution authorization independently. Mesh remains the coordination/governance plane; transport authenticity does not create target authority.

### Executor privilege expansion

A target executor could accept actions or resource types beyond its delegated authority because the request carries Wardveil authorization.

**Controls:** executor identity is explicitly bound; the executor still validates its own allowed actions and resource types; a valid authorization cannot compensate for missing local authority or a missing high-impact execution handler.

### Execution-evidence confusion

An authorization could be presented as proof that an action succeeded.

**Controls:** authorization records intent and bounded permission, not execution result. Wardveil Protect result and durable Wardveil Audit/authoritative executor evidence establish outcome. `Protected by Wardveil` requires current evidence of actual verification or enforcement for the represented scope.

### Sensitive-data leakage

Security evidence or authorization may expose credentials, tokens, internal topology, user data, diagnostics, source content, or exploit details.

**Controls:** minimize evidence; prohibit reusable secrets, signing keys, and recovery material; prefer internal scope IDs, digests, reason codes, and evidence references; keep unrestricted diagnostics outside shared Wardveil records.

### Stale-state replay

Old passing status evidence could remain visible after a control fails.

**Controls:** require timestamps and freshness evaluation; stale required evidence becomes `unknown` or a more severe state, never `protected`.

### Parser and contract abuse

Oversized, deeply nested, ambiguous, unsupported, or unexpected records could cause denial of service or inconsistent interpretation.

**Controls:** schema/contract validation, bounded strings and collections, explicit enums, unsupported-version rejection, and consumer-side limits.

### UI deception

A consumer could hide warnings, use color alone, remove source attribution, or make degraded state visually indistinguishable from protected state.

**Controls:** Glaze UI accessibility requirements; text labels; persistent scope/source context; no color-only meaning; security state remains understandable with reduced motion, high zoom, and assistive technology.

### Supply-chain compromise

Repository workflows or dependencies could alter Wardveil contracts or validation behavior.

**Controls:** dependency-light validators, immutable workflow action revisions, least-privilege workflow permissions, exact checked-out revision verification, and security-sensitive review of contract changes. Repository branch-protection state is an independent governance control and must not be claimed active until GitHub confirms it.

### False production acceptance

Passing source tests using reference HMAC, in-memory replay state, or local Protect idempotency could be described as deployed secure execution.

**Controls:** runtime authorization contract remains `unaccepted` until approved production key management, authenticated transport, durable replay/idempotency storage, executor authentication, clock enforcement, audit persistence, key rotation/revocation, and runtime failure/replay tests are evidenced.

## Aggregation rule

Wardveil aggregation remains conservative. A summary must not be more favorable than the weakest required evidence for the represented scope. `unknown` required evidence prevents `protected`. `degraded` or `attention` remain visible until authoritative evidence supports a different state.

## Remediation and execution boundary

Wardveil 0.9 does not create a generic unrestricted cross-platform command channel. It defines a bounded execution-authorization contract for supported high-impact cross-service Wardveil actions.

A Policy decision is not execution authority. A runtime authorization does not transfer underlying resource authority. A target executor must authenticate and authorize its own operation, enforce replay/idempotency rules, and produce auditable outcome evidence.

## Review triggers

Review this threat model when the status schema changes, a new evidence source or executor is added, aggregation semantics change, the runtime authorization contract or production cryptography changes, Wardveil gains a new mutation path, a public API is introduced, replay/idempotency architecture changes, or a security incident reveals a new trust boundary.
