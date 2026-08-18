# Wardveil Security Icon Contract

## Requirement

Wardveil Security must have its own canonical icon before Wardveil is used as a showcased visual identity inside a GoreeCloud application, service, dashboard, website, documentation hero, release asset, or other branded surface.

A text label, generic shield, inherited GoreeCloud logo, Glaze UI mark, Privacy Shield icon, application icon, emoji, or temporary security glyph is not an acceptable substitute for the canonical Wardveil icon.

The actual icon artwork is **not generated or approved in this foundation change**.

## Canonical icon description

The Wardveil Security icon should be a calm, modern protective emblem formed from **two softly curved, layered veil panels that fold inward around a small protected central core**. The two panels should create a subtle **W-shaped negative space** through their overlap and inward movement, making the mark recognizable as Wardveil without placing a literal letter W on top of a generic shield.

The outer silhouette may gently suggest protection or enclosure, but it should **not use a conventional stock shield outline**. The layered panels should feel like controlled privacy boundaries: open enough to communicate visibility and clarity, but structured enough to communicate defense and containment. The central core represents the user, device, service, data, or trusted state being protected.

The icon should feel polished and confident rather than aggressive. It should visually communicate:

- protection;
- privacy;
- trust;
- controlled visibility;
- layered defense;
- clarity;
- calm security;
- GoreeCloud ownership.

## Visual character

The icon must:

- fit naturally within the GoreeCloud Glaze UI visual family;
- use a strong, simple silhouette that remains recognizable at small sizes;
- support selective depth, layering, and restrained translucency in full-color presentation;
- retain a clean monochrome form for system, accessibility, symbolic, and constrained contexts;
- avoid visual dependence on gradients, blur, or translucency for recognition;
- remain legible in light and dark interfaces;
- remain distinguishable from the GoreeCloud platform logo, Privacy Shield, GoreeCloud Identity, GoreeCloud Monitor, and all application-specific icons;
- avoid looking like an antivirus vendor, cryptocurrency mark, gaming badge, or generic cybersecurity stock icon.

## Prohibited motifs

The canonical Wardveil icon must not primarily rely on:

- a generic shield with a checkmark;
- a padlock or keyhole;
- a literal eye;
- a skull;
- crossed weapons;
- hacker hood imagery;
- binary-code decoration;
- neon threat styling;
- a standalone letter W;
- the GoreeCloud platform logo with a security badge added to it;
- the Privacy Shield icon or a modified version of another GoreeCloud product icon.

## Composition guidance

The preferred construction is:

1. Two independent veil-like protective panels form the primary outer shape.
2. Each panel curves inward rather than meeting as a hard geometric shield point.
3. Their spacing or overlap creates a restrained W-shaped negative space.
4. A small central protected core sits inside the enclosure without becoming a lock, eye, or checkmark.
5. The full mark remains balanced and recognizable without text.

Perfect bilateral symmetry is not required. Slight controlled asymmetry may help the mark feel distinctive and avoid resembling existing shield logos, provided the icon remains visually stable.

## Asset requirements

Once approved, the canonical source should be stored as:

`branding/wardveil-security-icon.svg`

Derived assets may then be created for approved platform needs, including PNG, web/PWA, Linux desktop, Android, iOS, documentation, and social presentation. Every derived asset must preserve the same underlying mark.

The canonical vector source should be suitable for deriving at least:

- 16 px symbolic use;
- 24 px and 32 px interface use;
- 48 px and 64 px application/service surfaces;
- 128 px and 256 px high-density presentation;
- 512 px release or showcase presentation.

## Canonical SVG security and portability requirements

The canonical SVG is a source asset that may be consumed by browsers, desktop environments, mobile build pipelines, documentation systems, and GoreeCloud applications. It therefore must remain static, self-contained, deterministic, and safe to process.

The canonical SVG must:

- be valid UTF-8 XML in the standard SVG namespace;
- declare a finite, positive `viewBox` so derived assets are resolution-independent;
- remain within a bounded source size and structural-complexity limit;
- contain only static vector geometry, grouping, definitions, gradients, clipping, masks, titles, and descriptions required by the mark;
- use unique, valid IDs and only resolvable internal `#fragment` references;
- avoid external network references, remote fonts, linked stylesheets, external `<use>` targets, and data-URI resources;
- avoid scripts, event-handler attributes, executable URI schemes, DTD/entity declarations, animation, embedded HTML, raster images, video, audio, canvas, filters, and other active or non-portable content;
- avoid text and font-dependent glyph construction so the Wardveil mark remains independent of installed fonts and cannot collapse into a literal letter-based identity;
- avoid mixed foreign namespaces or XML base-URI overrides that could change how relative references resolve;
- remain suitable for deterministic derivation into platform-specific assets without fetching or executing external content.

Repository validation for this contract is implemented in `scripts/validate_wardveil_icon.py`. The validator runs both deterministic hostile/valid fixture self-tests and repository-state validation in GitHub Actions. If the canonical SVG is absent, the validator requires the machine-readable visual state to remain pending and the showcase state to remain blocked. If the SVG exists, validation fails unless the visual identity and showcase states are explicitly approved and the asset passes the SVG safety and portability checks.

These technical checks do not approve the artwork aesthetically. Explicit identity approval, small-size review, monochrome review, Glaze UI light/dark review, and identity-distinction review remain separate required acceptance decisions.

## Showcase gate

Wardveil Security is **not visually showcase-ready** until all of the following are true:

- the canonical icon artwork exists;
- the icon has been explicitly approved as the Wardveil identity;
- the canonical SVG is stored in this repository;
- the canonical SVG passes the repository security and portability validator;
- small-size and monochrome legibility have been reviewed;
- light and dark Glaze UI presentation has been reviewed;
- the icon is confirmed distinct from existing GoreeCloud identities.

The Wardveil identity is documented as original to GoreeCloud with no conflicting Wardveil Security identity identified in current GoreeCloud project records. Formal trademark or name-clearance work is optional future due diligence and is not part of this visual showcase gate.

Until this gate passes, applications may develop internal Wardveil functionality and text-based integration, but they must not present a temporary icon as if it were the official Wardveil visual identity.
