# Wardveil Security Conformance

A GoreeCloud-controlled integration conforms to this Wardveil foundation when the following requirements are satisfied.

## Identity

- Uses only approved Wardveil naming for approved purposes.
- Does not promote a reserved Wardveil component name as an implemented product or module without separate approval.
- Preserves GoreeCloud product identity and does not present Wardveil as a replacement for the application itself.

## Authority

- Identifies Wardveil as a security identity and presentation layer.
- Preserves the technical authority of the underlying security system, policy, service, application, or control.
- Does not treat Wardveil metadata, labels, icons, headers, or visual treatment as evidence that a security control succeeded.
- Does not convert missing, stale, skipped, or unavailable required evidence into a passing state.

## Status contract

- Uses the normalized Wardveil states only as presentation semantics: `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`.
- Identifies the bounded scope to which each status applies.
- Identifies the authoritative system and control that produced the security state.
- Records the evidence observation time and preserves source-defined freshness behavior.
- Treats stale, unavailable, incomplete, or unverified required evidence as non-passing.
- Keeps source-specific state available where useful without replacing the source system's state machine.
- Uses `contracts/wardveil.status.schema.json` when exchanging interoperable Wardveil status records.

## Protection claims

- Uses **Protected by Wardveil** only for a defined scope with current authoritative evidence.
- Sets a machine-readable protection claim to false whenever the normalized state is not protected, the source is not authoritative, or required evidence is not current.
- Avoids blanket protection claims that cannot be substantiated.
- Keeps warning, degraded, unknown, and not-applicable states distinguishable where those conditions are possible.

## Privacy and least privilege

- Does not expose reusable secrets, passwords, private keys, tokens, recovery codes, or other sensitive authentication material in Wardveil presentation.
- Avoids unnecessary topology, raw diagnostics, personal information, or internal failure details.
- Uses the minimum information necessary for the user's role and the intended security decision.
- Does not create a new telemetry channel merely for Wardveil adoption.
- Uses sanitized summaries or non-secret references instead of copying unrestricted evidence into Wardveil records.
- Documents intentional redaction categories without reproducing the redacted values.

## Glaze UI

- Uses Glaze UI or an approved platform-native equivalent for GoreeCloud-controlled Wardveil interfaces.
- Preserves accessibility, clear status communication, responsive behavior, and privacy-conscious presentation.
- Avoids stereotypical hacker, skull, neon-threat, or generic antivirus presentation.
- Keeps Wardveil visually distinguishable from the GoreeCloud platform identity, Privacy Shield, and other GoreeCloud products.

## Canonical icon and showcase

- Treats `ICON.md` as the canonical icon-description and visual-identity contract.
- Does not use a generic shield, lock, emoji, GoreeCloud platform logo, Privacy Shield icon, application icon, or temporary security glyph as the official Wardveil icon.
- Does not visually showcase Wardveil inside an application, service, website, dashboard, documentation hero, or release asset until the canonical icon has been created and explicitly approved.
- Stores the approved canonical vector source at `branding/wardveil-security-icon.svg` before declaring Wardveil visually showcase-ready.
- Verifies small-size, monochrome, light-theme, dark-theme, and identity-distinction behavior before showcase approval.
- Keeps all derived assets faithful to the same canonical Wardveil mark.

## Privacy Shield

- Preserves Privacy Shield as GoreeCloud Browser's named first-party Browser-level privacy and content-protection subsystem.
- Does not rename Privacy Shield to Wardveil.
- May present Privacy Shield state inside a broader Wardveil view without changing Privacy Shield's technical authority.

## Repository and release boundary

- Stores no reusable secrets or production credentials in this repository.
- Preserves `.gitignore` exclusions for common secret-bearing files and protected local artifacts.
- Preserves `SECURITY.md` private-reporting and evidence-minimization requirements.
- Keeps public-release and legal-clearance decisions separate from internal naming approval.
- Treats external name-conflict and legal clearance as pending until separately verified and documented.

## Stable-use gate

Before a GoreeCloud application treats a Wardveil integration as production-ready, the application should validate the exact source or release candidate and preserve evidence appropriate to its own Role and Purpose. Wardveil conformance cannot approve the application's underlying security implementation on its behalf.

Before a GoreeCloud application or service **showcases Wardveil visually**, the canonical Wardveil icon gate must also pass. Until then, internal functionality, status-contract integration, and text-based presentation may proceed, but temporary artwork must not be represented as the official Wardveil visual identity.
