# Wardveil Security Threat Model

## Purpose

This threat model defines the security boundary for Wardveil Security itself. Wardveil is a presentation and interoperability layer; it must never become a source of false assurance, a secret store, or an authority that silently overrides the systems that actually enforce security.

## Protected assets

Wardveil protects the integrity of security-state presentation, the provenance of security evidence, the distinction between authoritative and derived state, and the privacy of data carried through shared Wardveil contracts.

## Trust boundaries

1. **Authoritative producer** — an application, service, policy engine, scanner, identity system, firewall, backup system, or other control that owns the underlying technical state.
2. **Wardveil adapter** — code that converts authoritative state into the Wardveil status contract.
3. **Wardveil consumer** — a GoreeCloud interface that renders Wardveil status through Glaze UI.
4. **Operator** — an authorized administrator interpreting status, evidence age, scope, and remediation guidance.

No boundary may implicitly grant another boundary authority it does not already possess.

## Primary threats and required controls

### False protection claims

A consumer could display `protected` when evidence is missing, stale, incomplete, unavailable, or unverified.

**Controls:** fail closed; require explicit scope, evidence source, observation time, and freshness; never infer success from Wardveil branding or transport success alone.

### Evidence spoofing or provenance loss

Untrusted or incorrectly attributed evidence could be rendered as authoritative.

**Controls:** consumers must identify the authoritative source; adapters must not rewrite source identity to Wardveil; unknown provenance is non-passing.

### Scope confusion

A valid result for one control, resource, device, or time window could be presented as platform-wide protection.

**Controls:** status is always scope-bound; aggregation must preserve the weakest relevant state and must not broaden a producer's authority.

### Sensitive-data leakage

Security evidence can contain credentials, tokens, internal topology, user data, diagnostics, or exploit details.

**Controls:** minimize evidence; prohibit reusable secrets and recovery material; use bounded summaries; keep unrestricted diagnostics outside shared Wardveil records.

### Stale-state replay

Old passing evidence could remain visible after a control fails.

**Controls:** require timestamps and freshness evaluation; stale required evidence becomes `unknown` or a more severe state, never `protected`.

### Parser and contract abuse

Oversized, deeply nested, ambiguous, or unexpected status records could cause denial of service or inconsistent interpretation.

**Controls:** JSON Schema validation, bounded strings and collections, explicit enums, rejection of additional properties where practical, and consumer-side input limits.

### UI deception

A consumer could hide warnings, use color alone, remove source attribution, or make degraded state visually indistinguishable from protected state.

**Controls:** Glaze UI accessibility requirements; text labels; persistent scope/source context; no color-only meaning; security state must remain understandable with reduced motion, high zoom, and assistive technology.

### Privilege expansion

Wardveil integration could accidentally gain mutation privileges over authoritative controls.

**Controls:** read-only integration by default; any future remediation action requires a separate explicit authorization contract, least privilege, auditability, and confirmation appropriate to impact.

### Supply-chain compromise

Repository workflows or dependencies could alter Wardveil contracts or validation behavior.

**Controls:** keep validators dependency-light, pin workflow actions to immutable revisions where feasible, use least-privilege workflow permissions, validate exact checked-out revisions, and review contract changes as security-sensitive changes.

## Aggregation rule

Wardveil aggregation must be conservative. A summary must not be more favorable than the weakest required evidence for the represented scope. `unknown` required evidence prevents `protected`. `degraded` or `attention` must remain visible until authoritative evidence supports a different state.

## Remediation boundary

Wardveil 0.4 remains status- and presentation-focused. It does not define a generic execute/remediate API. Applications may link to their own authorized remediation workflows, but Wardveil must not create an unaudited cross-platform command channel.

## Review triggers

Review this threat model when the status schema changes, a new evidence source is added, aggregation semantics change, Wardveil gains mutation/remediation capability, a public API is introduced, or a security incident reveals a new trust boundary.
