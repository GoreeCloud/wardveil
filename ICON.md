# Wardveil Security Visual Identity Contract

## Status

The Wardveil Security icon is **approved** and visually showcase-ready for appropriate Wardveil contexts.

The authoritative branding source is maintained in the unified GoreeCloud branding repository:

- Repository: `GoreeCloud/goreecloud-branding-assets`
- Canonical path: `systems/wardveil-security/wardveil-security-icon.svg`
- Local synchronized derivative: `branding/wardveil-security-icon.svg`

The local SVG is retained for Wardveil packaging, validation, Security Center rendering, and repository-local integration. It is a synchronized derivative and must not become an independent branding authority.

## Canonical concept

The Wardveil Security icon is a calm, modern protective emblem formed from **two softly curved, layered veil panels that fold inward around a compact protected central core**. Their inward motion creates a restrained **W-shaped central opening** without placing a literal W on a generic shield.

The mark communicates layered protection, trust, controlled visibility, containment, and calm security while remaining distinct from Privacy Shield, Everkeep, Glaze UI, GoreeCloud Mesh, the GoreeCloud platform mark, and application-specific identities.

## Visual character

The approved mark:

- fits within the GoreeCloud Glaze UI visual family;
- uses a strong silhouette that remains recognizable at compact sizes;
- supports full-color or semantic-color presentation and a clean monochrome form;
- does not depend on gradients, blur, or translucency for recognition;
- remains usable in light and dark interfaces;
- avoids a conventional stock shield outline, padlock, keyhole, eye, skull, crossed weapons, hacker imagery, binary-code decoration, neon threat styling, or a standalone letter W;
- must not be replaced by the GoreeCloud platform logo, Privacy Shield icon, another application icon, an emoji, or a temporary security glyph.

## Construction

1. Two independent veil-like protective panels form the primary outer shape.
2. Each panel curves inward rather than meeting as a hard geometric shield point.
3. Their spacing creates the restrained Wardveil W-shaped opening.
4. A compact central protected core sits inside the enclosure without becoming a lock, eye, or checkmark.
5. The full mark remains balanced and recognizable without text.

## Asset and synchronization requirements

The canonical source of truth is `GoreeCloud/goreecloud-branding-assets` path `systems/wardveil-security/wardveil-security-icon.svg`.

The repository-local `branding/wardveil-security-icon.svg` must remain synchronized with that source. PNG, web/PWA, Linux desktop, Android, iOS, documentation, social, favicon, and other derivatives must originate from the unified canonical SVG rather than being independently redrawn.

Any future Wardveil visual revision must be approved and committed to the unified branding repository first. After approval, synchronized derivatives may be propagated into Wardveil and other consumers.

## SVG security and portability requirements

The canonical SVG and synchronized local derivative must remain static, self-contained, deterministic, and safe to process. They must use valid UTF-8 SVG with a finite positive viewBox; avoid scripts, event handlers, executable URI schemes, external network references, remote fonts, linked stylesheets, embedded HTML, raster images, animation, active content, DTD/entity declarations, and unresolved external references; and remain suitable for deterministic platform-specific derivation.

Repository validation in `scripts/validate_wardveil_icon.py` continues to validate the local synchronized derivative and the machine-readable visual state. Those technical checks protect the consumer copy; they do not transfer branding authority away from `GoreeCloud/goreecloud-branding-assets`.

## Approval record

Wardveil's canonical icon was explicitly approved and promoted in the Wardveil repository in August 2026, including the subsequently approved revamped geometry. The exact approved geometry has now been centralized without geometry changes in `GoreeCloud/goreecloud-branding-assets`.

Branding approval does not establish security protection, runtime integration, ClamAV acceptance, or `Protected by Wardveil` evidence. Those claims remain governed by Wardveil's technical contracts and current authoritative evidence.
