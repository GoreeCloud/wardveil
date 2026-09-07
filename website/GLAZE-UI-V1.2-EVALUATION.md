# Wardveil Security Center — GLAZE UI V1.2 Stable Evaluation

Status: **Non-production evaluation**  
Active production target: **GLAZE UI V1.1 / 1.1.0 Stable**  
Design-system release evaluated: **GLAZE UI V1.2 / 1.2.0 Stable**  
Stable promotion merge revision: `f285b9145e27e6e7027b075c37299d101945c272`  
V1.2 source-qualification anchor: `b0eadf9a60f73d45caffb62ffc7e9e0334cddc97`

## Purpose

This record evaluates the current GLAZE UI V1.2 Stable Frosted Neutral/Living Frosted contract against Wardveil Security Center without changing the active production presentation contract, Cloudflare Pages build artifact, Wardveil security authority, or downstream production acceptance state.

The V1.2 governing rule is: **Neutral glass is the material. Color is an accent.**

V1.2 became Stable on September 6, 2026. That shared design-system lifecycle change does not automatically migrate Wardveil. Wardveil production remains on its last accepted V1.1 presentation until a separate Wardveil-specific migration and acceptance decision is completed.

## Isolation model

- Production continues to build `website/dist` through `website/build.py`.
- Stable-contract evaluation builds `website/dist-v1.2-evaluation` through `website/build_v1_2_evaluation.py`.
- Production `website/index.html` remains V1.1-only and does not declare `data-glaze-upgrade="v1.2-stable-evaluation"`.
- The evaluation artifact is derived from production source at build time instead of maintaining a divergent copy of Security Center content.
- The evaluation stylesheet is repository-local and intentionally bounded to the Wardveil surface under test; it is not represented as a byte-identical copy of the upstream Glaze Stable entrypoint.
- The evaluation stylesheet, validator, browser harness, and evidence manifest bind to the exact V1.2 Stable promotion revision and source-qualification anchor recorded above.
- No Cloudflare Pages production build setting change is included.

## Security Center material mapping

Wardveil is a critical-system/security surface. The evaluation therefore uses a stricter material budget than a general consumer application:

- The persistent site header is the **only** Frosted Neutral region exercised by the evaluation.
- Security content cards, evidence summaries, normalized state descriptions, malware-protection boundaries, reporting guidance, and other reading surfaces remain Solid/Surface with no backdrop blur.
- No security status color is changed into a material substrate.
- No favorable security state may be inferred from transparency, blur, specular edges, brightness, depth, or accent color.
- No Deep Glaze or Live Glaze region is introduced.
- Reduced Transparency resolves the evaluated header to a solid Raised surface.
- Increased Contrast strengthens the evaluated header boundary.
- Forced Colors removes custom glass treatment and uses system colors.
- Unsupported backdrop filtering resolves to a solid Raised surface.

## Appearance coverage

The evaluation covers System/Light, Dark, and Deep Dark appearance behavior while preserving the existing production V1.1 appearance namespace/control behavior in the source from which the isolated artifact is derived.

Reference V1.2 substrate values exercised by this bounded Wardveil subset include:

- Light overlay glass: neutral `rgba(250,250,250,0.82)`; green, teal, aqua, and amber substrate bias is not permitted.
- Dark overlay glass: `rgba(42,42,45,0.82)`.
- Deep Dark overlay glass: `rgba(24,24,27,0.86)`.
- Standard evaluation blur: `28px`.

These local evaluation values are downstream mapping evidence, not a replacement source of truth for the central V1.2 contract.

## Automated optical-review evidence

The dedicated evaluation workflow produces five deterministic review screenshots from the exact checked-out Wardveil revision after the active production V1.1 validation and isolated V1.2 Stable contract validation pass:

- Light desktop at 1180 × 900.
- Light mobile at 390 × 844.
- Dark desktop at 1180 × 900.
- Deep Dark desktop at 1180 × 900.
- Reduced Transparency desktop at 1180 × 900.

The PNG files are accompanied by a machine-readable manifest containing the V1.2 Stable revision, Wardveil source revision, viewport and appearance state, header material readings, primary surface background, byte size, and SHA-256 digest for every capture. CI publishes the evidence as `wardveil-v1.2-frosted-neutral-optical-review` for 14 days using an immutable `actions/upload-artifact` revision.

This evidence exists to make human visual review reproducible. Automated screenshot generation is not itself human optical approval.

## Acceptance boundary

Passing repository automation establishes only that the isolated evaluation artifact is mechanically consistent with the bounded V1.2 Stable contract recorded here. It does not establish:

- human optical approval;
- final visual acceptance;
- assistive-technology acceptance;
- production Cloudflare Pages acceptance;
- Wardveil runtime security acceptance;
- downstream Wardveil V1.2 consumer conformance;
- Release Candidate or Stable lifecycle for Wardveil itself; or
- authority to update the active Security Center production build from V1.1 to V1.2.

The V1.2 design system is already Stable; this evaluation must therefore never describe V1.2 itself as Candidate or RC. Conversely, V1.2 Stable status must never be used as a substitute for Wardveil-specific downstream acceptance.

Rollback is immediate by discarding the evaluation artifact or branch; production remains on V1.1 throughout this evaluation.
