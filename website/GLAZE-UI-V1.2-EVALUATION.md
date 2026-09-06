# Wardveil Security Center — GLAZE UI V1.2 Frosted Neutral Evaluation

Status: **Non-production evaluation**  
Active production target: **GLAZE UI V1.1 / 1.1.0 Stable**  
Candidate evaluated: **GLAZE UI V1.2 / 1.2.0-candidate**  
Upstream candidate revision: `94e0db139da2b9a3f7ead7744cbcd0ad9d7627bd`

## Purpose

This record evaluates the GLAZE UI V1.2 Frosted Neutral Candidate against Wardveil Security Center without changing the active production presentation contract, Cloudflare Pages build artifact, Wardveil security authority, or downstream production acceptance state.

The candidate governing rule is: **Neutral glass is the material. Color is an accent.**

## Isolation model

- Production continues to build `website/dist` through `website/build.py`.
- Candidate evaluation builds `website/dist-v1.2-evaluation` through `website/build_v1_2_evaluation.py`.
- Production `website/index.html` remains V1.1-only and does not declare `data-glaze-upgrade="v1.2-frosted-neutral"`.
- The candidate artifact is derived from the production source at build time instead of maintaining a divergent copy of Security Center content.
- The evaluation stylesheet is repository-local and intentionally bounded to the Wardveil surface under test; it is not represented as a byte-identical copy of the upstream Glaze candidate entrypoint.
- The candidate stylesheet and validation bind to the exact upstream revision recorded above.

## Security-Center material mapping

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

The evaluation covers System/Light, Dark, and Deep Dark appearance behavior while preserving the existing V1.1 appearance namespace and control behavior.

Reference candidate substrate values exercised by the Wardveil subset include:

- Light overlay glass: the evaluated substrate remains neutral `rgba(250,250,250,0.82)`; green, teal, aqua, and amber substrate bias is not permitted.
- Dark overlay glass: `rgba(42,42,45,0.82)`.
- Deep Dark overlay glass: `rgba(24,24,27,0.86)`.
- Standard candidate blur: `28px`.

## Acceptance boundary

Passing repository automation establishes only that the isolated evaluation artifact is mechanically consistent with the bounded contract recorded here. It does not establish:

- human optical approval;
- final visual acceptance;
- assistive-technology acceptance;
- production Cloudflare Pages acceptance;
- Wardveil runtime security acceptance;
- GLAZE UI V1.2 Release Candidate or Stable status;
- downstream V1.2 consumer conformance; or
- authority to update the active Security Center from V1.1 to V1.2.

Rollback is immediate by discarding the evaluation artifact or branch; production remains on V1.1 throughout this evaluation.
