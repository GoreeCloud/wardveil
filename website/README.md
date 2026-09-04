# Wardveil Security Public Website

This directory contains the source for the public Wardveil Security Center at `https://security.goreecloud.com/`.

## Current presentation target

The governed consumer baseline is **GLAZE UI V1.1 / 1.1.0**. Security Center source targets that contract, but publication is currently blocked by a verified defect in the immutable `v1.1.0` CSS dependency graph.

The source activates `data-glaze-version="1.1"`, uses the intended `css/glaze-v1.1.0.css` entrypoint, supports the V1.1 Light, Dark, and Deep Dark appearance contract, and keeps transient navigation chrome visually distinct from durable security content. Durable security, evidence, state, and authority content remains on solid surfaces; Glaze presentation never creates or upgrades security state.

`glaze.lock.json` identifies the immutable V1.1 release commit and all 13 expected Git blob identities. Those bytes are necessary but not sufficient publication evidence: published `glaze-v1.components.css` imports missing `./glaze-v1.candidate.css`, so the locked graph is not transitively complete.

Security Center does not recreate that missing Candidate file or locally rewrite immutable `v1.1.0`. A corrected immutable Stable Glaze release must be published, explicitly re-pinned here, and revalidated before V1.1 publication or consumer conformance can be claimed.

## Fail-closed build boundary

`website/build.py` now fetches every locked stylesheet, verifies each Git blob, and validates every same-directory CSS `@import` against the complete locked set **before modifying `website/dist`**. A byte-perfect but dependency-incomplete release therefore fails without manufacturing a new browser artifact.

`website/validate_glaze_import_closure.py` exposes the same dependency check as the first dedicated V1.1 CI gate. Current immutable `v1.1.0` is expected to fail that gate until the upstream release is corrected.

After a corrected immutable Stable release is available, Security Center must explicitly re-pin it and complete fresh source, responsive, rendered-browser, accessibility, preview/deployment, and deployed-byte verification. Prior green V1.1 checks that did not test transitive import closure do not establish current publication acceptance.

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

The site preserves visible focus, reduced motion, reduced transparency, increased contrast, forced colors, safe viewport insets, text reflow, and print fallbacks. Browser geometry validation remains a separate release gate from source validation and must be rerun after a valid immutable Glaze graph is available.

## Validation

Run the dependency gate first:

```bash
python3 website/validate_glaze_import_closure.py
```

After that passes on a corrected immutable Stable release, run:

```bash
python3 website/validate.py
python3 website/validate_responsive.py
python3 website/browser_responsive_smoke.py
```

The validators verify the current Wardveil identity and Foundation version, canonical icon publication, immutable GLAZE UI source identity and dependency closure, local browser artifact references, security headers, public-safe content, internal anchors/assets, responsive/accessibility rules, and the absence of superseded active Glaze 1.5/2.x presentation markers.

## Acceptance boundary

Only `website/dist` is intended for Pages publication. Passing non-publication source checks or creating a preview does not establish production website acceptance, Wardveil runtime acceptance, scanner acceptance, product-specific protection acceptance, or overall Stable qualification. The exact candidate revision must pass applicable source and rendered review after the dependency graph is valid, and the deployed revision must be independently verified on `security.goreecloud.com` before publication acceptance is claimed.
