# Wardveil Security Candidate Icon Review

This document defines the review protocol for `branding/candidates/wardveil-security-icon.svg` before any canonical promotion occurs.

## Approval boundary

The candidate is not the canonical Wardveil identity. Presence of this file, successful CI, or successful SVG safety validation does not constitute visual approval. The canonical path must remain absent and machine-readable showcase state must remain blocked until explicit approval is recorded.

## Required review matrix

Review the same underlying mark at 16, 24, 32, 48, 64, 128, 256, and 512 CSS pixels. The mark should retain a recognizable two-panel enclosure, central core, and restrained W-shaped negative-space relationship without collapsing into a shield, padlock, eye, or standalone W.

Review a monochrome presentation using `currentColor` with no dependence on gradients, blur, external assets, fonts, or raster content. The candidate must remain intelligible when opacity differences are reduced by constrained rendering or accessibility conditions.

Review the mark on representative Glaze UI light and dark surfaces. The shape must remain legible without requiring a background-specific geometry change. Contrast and layering should remain calm and clear rather than neon, aggressive, or threat-oriented.

Review identity distinction against the GoreeCloud platform logo, Privacy Shield, GoreeCloud Identity, GoreeCloud Monitor, and application-specific icons. Similarity in the overall GoreeCloud visual family is acceptable; confusing silhouette, enclosure, central symbol, or negative-space construction is not.

## Technical acceptance

Run:

`python3 scripts/validate_wardveil_icon_candidate.py`

This validates the candidate with the same static SVG security and portability parser used for the eventual canonical asset while additionally requiring that the canonical path remain absent during candidate-only review.

## Promotion criteria

Promotion is permitted only after all of the following are explicitly recorded:

- candidate SVG technical validation passes;
- small-size review passes;
- monochrome review passes;
- Glaze UI light review passes;
- Glaze UI dark review passes;
- identity-distinction review passes;
- the icon is explicitly approved as the Wardveil Security visual identity.

Only then may the candidate be copied unchanged to `branding/wardveil-security-icon.svg`, machine-readable visual/showcase states be changed to approved, and the canonical repository validator be allowed to pass the approved-icon path.
