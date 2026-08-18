# Wardveil Security Identity Contract

## Canonical identity

Wardveil Security is the official GoreeCloud platform-wide security and protection identity.

Approved presentations are:

- **Wardveil Security by GoreeCloud** — full attributed presentation.
- **Wardveil Security** — primary product and technology name.
- **Wardveil** — approved short name.
- **Protected by Wardveil** — approved protection-status phrase when supported by current technical evidence.

The words **by GoreeCloud** establish ownership and attribution. They do not need to appear after every Wardveil reference when the GoreeCloud relationship is already clear.

## Meaning

The name combines two protective ideas:

- **Ward** — guarding, protection, and keeping something safe.
- **Veil** — privacy, controlled visibility, and protection from unnecessary exposure.

Wardveil therefore represents a protective layer around GoreeCloud without reducing security to antivirus, firewalling, identity, or any other single technology.

## Scope

Wardveil may present security posture and capabilities involving:

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

This scope does not automatically create a new service, security control, or product module. Any future Wardveil component must receive its own documented Role and Purpose and implementation authority when required.

## Authority boundary

Wardveil is a security identity and presentation layer. It does not replace the systems that authenticate users, authorize access, filter traffic, manage private networking, protect credentials, apply security updates, detect vulnerabilities, perform backups, verify recovery, or enforce application-specific controls.

When Wardveil displays or summarizes technical state, the underlying authoritative system or record remains the source of truth.

## Status and evidence contract

Wardveil may normalize authoritative technical state for presentation, but it does not originate or certify that state.

The approved normalized presentation states are:

- **Protected** — current authoritative evidence supports the explicit scope;
- **Attention** — review or action is recommended;
- **Degraded** — a protection or evidence path is below its intended state;
- **Unknown** — required evidence is unavailable, stale, incomplete, or unverified;
- **Not applicable** — the control does not apply to the current scope.

Missing evidence is not passing evidence. A `Protected by Wardveil` claim is permitted only for the explicit scope of a status record whose normalized state is protected, whose identified source is authoritative, and whose required evidence is current.

The interoperable semantics and machine-readable structure are defined in `STATUS.md` and `contracts/wardveil.status.schema.json`. Status records must remain data-minimized and must not copy reusable secrets, active credentials, private keys, tokens, recovery material, unrestricted diagnostics, or unnecessary private topology into broad Wardveil presentation.

## Relationship to Glaze UI

Glaze UI remains GoreeCloud's shared design and interaction language. Wardveil is not a replacement design system.

Wardveil interfaces, status surfaces, settings, dashboards, alerts, and future dedicated security experiences must use Glaze UI or an approved platform-native equivalent consistent with GoreeCloud application-branding requirements.

## Relationship to Privacy Shield

GoreeCloud Privacy Shield remains the first-party Browser-level privacy and content-protection subsystem within GoreeCloud Browser.

Wardveil does not rename or absorb Privacy Shield. Wardveil may present Privacy Shield status within a broader security view while preserving Privacy Shield's own identity and Browser-specific technical authority.

## Reserved terminology

The following names are reserved concepts and are **not approved module or product names**:

- Wardveil Access
- Wardveil Network
- Wardveil Integrity
- Wardveil Threats
- Wardveil Verify
- Wardveil Watch
- Wardveil Security Center

Additional component names require a separate documented approval before implementation as named Wardveil products or modules.

## Canonical icon requirement

Wardveil Security must have its own canonical icon before Wardveil is showcased as a visual identity inside any GoreeCloud application, service, dashboard, website, documentation hero, release asset, or equivalent branded surface.

The canonical icon description, asset requirements, prohibited motifs, and showcase gate are defined in `ICON.md`.

Until the icon exists and is approved, GoreeCloud software may implement internal Wardveil functionality and text-based Wardveil presentation, but it must not present a temporary, generic, inherited, or application-specific security icon as if it were the official Wardveil visual identity.

The intended mark is based on two softly curved, layered veil panels that fold inward around a small protected central core. Their spacing or overlap should create a subtle W-shaped negative space without relying on a literal standalone W or a generic stock shield.

## Visual direction

Wardveil should communicate protection, trust, privacy, clarity, and control through a calm, polished, modern identity integrated with Glaze UI.

Avoid stereotypical cybersecurity imagery such as neon hacker motifs, skulls, aggressive threat graphics, or generic antivirus styling.

The future canonical Wardveil visual identity must remain distinguishable from the GoreeCloud platform logo, Glaze UI, Privacy Shield, GoreeCloud Identity, GoreeCloud Monitor, and other GoreeCloud product identities.

## Legal boundary

The GoreeCloud naming decision is approved internally. This repository does not establish trademark clearance, domain availability, package-name availability, or freedom to operate in any jurisdiction or commercial context.

External name-conflict and legal review must be completed before Wardveil is treated as a legally cleared public brand.
