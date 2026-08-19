# Wardveil Security by GoreeCloud

Wardveil Security is GoreeCloud's platform-wide security and protection identity and shared security-state interoperability layer.

It provides a consistent way to identify and present security posture, protection state, warnings, recommendations, audit information, and security-focused experiences across GoreeCloud without replacing the technical systems that produce or enforce that state.

> **Current status:** Foundation 0.4 development. Wardveil Security is documented as an original GoreeCloud identity. The canonical Wardveil icon remains pending, so Wardveil is not yet visually showcase-ready.

## Core boundary

Wardveil is an identity, status-contract, and presentation layer. Authentication systems, authorization controls, firewalls, private networking, application security controls, vulnerability management, backup and recovery systems, and other authoritative controls remain responsible for their own technical state.

Wardveil must never turn missing evidence into reassurance, broaden a producer's authority, become a secret store, or create an unaudited cross-platform remediation channel.

## Approved naming

- **Wardveil Security by GoreeCloud** — full attributed presentation
- **Wardveil Security** — primary product and technology name
- **Wardveil** — approved short name
- **Protected by Wardveil** — approved evidence-scoped protection-status phrase

Reserved concepts such as Wardveil Access, Wardveil Network, Wardveil Integrity, Wardveil Threats, Wardveil Verify, Wardveil Watch, and Wardveil Security Center are not approved module or product names.

## Relationship model

- **Glaze UI** defines how GoreeCloud looks, feels, adapts, and interacts.
- **Wardveil Security** defines how GoreeCloud identifies and presents platform-wide security and protection.
- **Privacy Shield** remains GoreeCloud Browser's first-party Browser-level privacy and content-protection subsystem.

Wardveil-facing interfaces use Glaze UI. Wardveil may present Privacy Shield status in broader security views, but Privacy Shield retains its own name and technical role.

## Shared contracts

- `STATUS.md` defines the status semantics.
- `contracts/wardveil.status.schema.json` defines the machine-readable status structure.
- `THREAT-MODEL.md` defines trust boundaries, misuse cases, aggregation safety, and the remediation boundary.
- `ADOPTION.md` defines the minimum integration and acceptance requirements for GoreeCloud consumers.
- `SECURITY.md` defines repository security and sensitive-information boundaries.
- `ICON.md` defines the canonical visual-identity contract and showcase gate.

The normalized states are `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`. Missing, stale, unavailable, incomplete, or unverified required evidence must never be promoted to a passing state.

**Protected by Wardveil** may be asserted only for the explicit scope of a record backed by current authoritative evidence. Wardveil branding itself is never evidence that a control succeeded.

## Security architecture principles

Wardveil integrations are read-only by default. Each record must preserve authoritative-source identity, explicit scope, observation time, and freshness meaning. Shared evidence is data-minimized and must not contain reusable secrets, active credentials, private keys, tokens, recovery material, unrestricted diagnostics, or unnecessary personal data.

Aggregated security views must be conservative: a summary cannot be more favorable than the weakest required evidence in its represented scope. Required `unknown` evidence blocks `protected`.

Wardveil 0.4 does not define a generic remediation API. Applications may link to their own authorized remediation workflows, but technical mutation remains owned and audited by the authoritative system.

## Icon and visual identity

Wardveil Security requires its own canonical icon before the identity is visually showcased inside a GoreeCloud application, service, website, dashboard, documentation hero, or release asset. The approved concept and asset requirements are defined in `ICON.md`. The actual icon artwork has not yet been generated or approved.

The preferred mark uses two softly curved, layered veil panels folding inward around a small protected central core, with spacing or overlap producing a restrained W-shaped negative space. It should suggest layered privacy and protection without becoming a conventional stock shield.

## Validation

Run:

```bash
python3 scripts/validate_wardveil.py
```

The validator checks canonical naming, authority boundaries, icon/showcase gating, status-contract invariants, protection-claim fail-closed behavior, repository secret exclusions, and required documentation. Canonical SVG validation is separately enforced by `scripts/validate_wardveil_icon.py` when the approved asset exists.

## Adoption

A GoreeCloud project must not claim Wardveil integration based on branding alone. Adoption requires authoritative-source mapping, protected/non-passing/stale-evidence tests, sensitive-field exclusion, accessible state presentation, and exact-revision CI evidence as defined in `ADOPTION.md`.

## Original identity and optional future due diligence

Wardveil Security is documented here as an original GoreeCloud identity. This project record is not a trademark registration or a legal guarantee of exclusivity in every jurisdiction. Formal name or trademark due diligence may be performed later if expanded public or commercial use makes it useful; it is not a current GoreeCloud engineering blocker.
