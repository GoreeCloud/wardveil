# Wardveil Security Public Website

This directory contains the source for the public Wardveil Security Center at `https://security.goreecloud.com/`.

## Current presentation target

The Security Center targets current Stable **GLAZE UI V1.1 / 1.1.0**.

The website activates `data-glaze-version="1.1"`, uses the official `css/glaze-v1.1.0.css` entrypoint, supports the V1.1 Light, Dark, and Deep Dark appearance contract, and keeps transient navigation chrome visually distinct from durable security content. Durable security, evidence, state, and authority content remains on solid surfaces; Glaze presentation never creates or upgrades security state.

`glaze.lock.json` identifies the immutable V1.1 Stable release commit and all 13 Git blob identities in the web import graph. The build retrieves only that exact release source, verifies every Git blob identity, and publishes the verified CSS into the local `/assets/glaze/` output. The published browser artifact has no runtime UI network dependency.

## Cloudflare Pages contract

- Repository: `GoreeCloud/goreecloud-wardveil-security`
- Production branch: `main`
- Root directory: repository root
- Build command: `python3 website/build.py`
- Build output directory: `website/dist`
- Custom domain: `security.goreecloud.com`

`website/dist` is generated build output and is not a separate design or branding authority.

## Visual identity

The build copies the approved Wardveil identity from `branding/wardveil-security-icon.svg`. That repository-local file is a synchronized derivative of the canonical `GoreeCloud/goreecloud-branding-assets` source and must remain byte-identical to the approved Sentinel Fold asset.

The standalone **Sentinel Fold** emblem is the approved primary Wardveil Security mark. `Wardveil Security`, `Security Center`, and `by GoreeCloud` are supporting identity/context and are not part of the emblem. The public site must not redraw or independently reinterpret the mark.

## Public content boundary

The Security Center reflects Wardveil Foundation 0.9 and may describe Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, Security Center, runtime authorization, durable execution safety, normalized state semantics, and bounded platform relationships.

ClamAV may be described only as an initial replaceable signature-based engine beneath supported Wardveil Scan paths. Source integration, scanner health, branding, transport success, a successful build, or website publication does not establish broad `Protected by Wardveil` acceptance.

Fast-changing deployment details belong in authoritative Wardveil evidence and acceptance records rather than static marketing copy. The public website therefore uses conservative language and does not infer current protection from old deployment history.

## Responsive and accessibility requirements

The Security Center intentionally recomposes for desktop, tablet, and phone layouts. Mobile navigation must not depend on horizontal scrolling. General interactive targets follow the 48 px Glaze floor, with the V1.1 56 px Touch Assistance contract available where enabled.

The site preserves visible focus, reduced motion, reduced transparency, increased contrast, forced colors, safe viewport insets, text reflow, and print fallbacks. Browser geometry validation remains a separate release gate from source validation.

## Validation

Run:

```bash
python3 website/validate.py
python3 website/validate_responsive.py
python3 website/browser_responsive_smoke.py
```

The validator verifies the current Wardveil identity and Foundation version, canonical icon publication, the immutable GLAZE UI V1.1 Stable source graph, local browser artifact references, security headers, public-safe content, internal anchors/assets, responsive/accessibility rules, and the absence of superseded active Glaze 1.5/2.x presentation markers.

## Acceptance boundary

Only `website/dist` is intended for Pages publication. Passing source validation or creating a preview does not establish production website acceptance, Wardveil runtime acceptance, scanner acceptance, product-specific protection acceptance, or overall Stable qualification. The exact candidate revision must pass applicable source and rendered review, and the deployed revision must be independently verified on `security.goreecloud.com` before publication acceptance is claimed.
