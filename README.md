# Wardveil Security by GoreeCloud

Wardveil Security is GoreeCloud's platform-wide security and protection identity.

It provides a consistent way to identify and present security posture, protection state, warnings, recommendations, audit information, and security-focused experiences across GoreeCloud without replacing the technical systems that produce or enforce that state.

> **Current status:** Private foundation. The GoreeCloud naming decision is approved internally; external name-conflict and legal clearance remain pending. The canonical Wardveil icon is also pending, so Wardveil is not yet visually showcase-ready.

## Role

Wardveil may represent security posture and capabilities involving:

- access and authorization;
- network protection and exposure control;
- application and service security;
- integrity and verification;
- vulnerability and security-update status;
- device trust and security posture;
- credential, key, token, and secret protection;
- threat and suspicious-activity visibility;
- security-event history and audit information;
- compromise response and security-related recovery.

Wardveil is an identity and presentation layer. Authentication systems, authorization controls, firewalls, private networking, application security controls, vulnerability management, backup and recovery systems, and other authoritative controls remain responsible for their own technical state.

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

## Repository purpose

This repository is the source-controlled foundation for shared Wardveil identity, integration, status, security, and validation contracts. It provides reusable security-facing presentation semantics while keeping technical authority with the applications, services, policies, and controls that actually enforce security.

The repository must not become a dumping ground for unrelated security implementation, reusable secrets, private keys, tokens, credentials, production topology, or sensitive operational evidence.

## Status contract

Wardveil 0.2 adds a privacy-conscious interoperable status contract for GoreeCloud applications and services.

- `STATUS.md` defines the semantic contract.
- `contracts/wardveil.status.schema.json` defines the machine-readable structure and normalized values.
- `examples/wardveil.status.example.json` provides a non-sensitive conforming example.

The normalized states are `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`. Missing, stale, unavailable, or unverified required evidence must never be promoted to a passing state.

**Protected by Wardveil** may be asserted only for the explicit scope of a record backed by current authoritative evidence. Wardveil branding itself is never evidence that a control succeeded.

## Security and privacy

`SECURITY.md` defines the repository security boundary. Wardveil records and examples are data-minimized and must not contain reusable secrets, active credentials, private keys, tokens, recovery material, or unrestricted private diagnostics. `.gitignore` provides an additional source-control guard for common secret-bearing files.

## Icon and visual identity

Wardveil Security requires its own canonical icon before the identity is showcased inside a GoreeCloud application, service, website, dashboard, documentation hero, or release asset.

The approved concept and asset requirements are defined in `ICON.md`. The actual icon artwork has not yet been generated or approved. A generic security glyph, shield, GoreeCloud logo, Privacy Shield icon, emoji, or another GoreeCloud product icon must not be presented as the official Wardveil icon.

The preferred Wardveil mark uses two softly curved, layered veil panels folding inward around a small protected central core, with the spacing or overlap producing a restrained W-shaped negative space. It should suggest layered privacy and protection without becoming a conventional stock shield.

## Visual direction

Wardveil should communicate protection, trust, privacy, clarity, and control through a calm, polished, modern GoreeCloud identity. It should avoid stereotypical hacker imagery, skulls, aggressive threat graphics, and generic antivirus styling.

The future canonical Wardveil visual identity must remain distinct from the GoreeCloud platform logo, Glaze UI, Privacy Shield, GoreeCloud Identity, GoreeCloud Monitor, and other GoreeCloud product identities.

## Showcase gate

Wardveil is not visually showcase-ready until its canonical icon exists, is explicitly approved, is stored in this repository as the canonical vector source, and passes small-size, monochrome, light-theme, dark-theme, and identity-distinction review. Public showcase also remains subject to the separate external name-conflict and legal-clearance boundary.

Status-contract and text-based integration may proceed before this gate passes. Temporary artwork may not be represented as the official Wardveil identity.

## Validation

Run:

```bash
python3 scripts/validate_wardveil.py
```

The validator checks canonical naming, authority boundaries, legal status, icon/showcase gating, status-contract invariants, protection-claim fail-closed behavior, repository secret exclusions, and required documentation.

## Legal and public-release boundary

This repository does not establish trademark clearance, domain availability, package-name availability, or freedom to operate. Public branding or release decisions must remain separate from the internal GoreeCloud naming decision until the appropriate external name-conflict review is complete.
