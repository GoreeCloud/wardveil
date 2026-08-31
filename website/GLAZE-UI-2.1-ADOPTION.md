# Wardveil Security Center — Glaze UI 2.1 Adoption

Status: **Adoption Candidate**  
Target: **Glaze UI 2.1.0 Stable**  
Canonical Glaze UI release commit: `c49113eb8b93c267613fdf1bbca1f814495acad7`  
Canonical tag: `v2.1.0`

## Scope

This record maps the Wardveil Security Center public web surface to Glaze UI 2.1 Stable without changing Wardveil's security authority or production-security acceptance state.

The site preserves its existing information architecture and Sentinel Fold identity while adopting the 2.1 material/accessibility contract. Content remains on solid product surfaces. Translucent material is limited to bounded interaction/navigation surfaces.

## Consumed 2.1 contract

- Canvas and Surface remain the content foundation.
- `soft-glaze` is used only for persistent navigation/header and selected bounded presentation chrome.
- The Security Center uses the **administration** material-budget recipe: no Deep Glaze or Live Glaze is required by this site, and translucent material remains subordinate to content.
- General interactive targets retain a 48 px floor; Touch Assistance maps to a 56 px floor.
- Reduced Transparency and Forced Colors force solid presentation and remove blur.
- Reduced Motion removes nonessential transforms/transitions.
- Increased Contrast strengthens boundaries.
- Browser zoom / large-text reflow remains content-preserving; layout collapses rather than clipping or hiding security state.
- Unsupported backdrop filtering falls back to solid/tonal surfaces.

## Repository-local mapping

`website/glaze-ui-2.1.0.css` is a Security Center-specific Stable subset mapped to the canonical Glaze UI 2.1 material and accessibility contracts. It is not represented as a byte-identical copy of the Glaze UI repository entrypoint. `website/validate.py` binds this subset to the exact Glaze UI 2.1 release commit and checks the application-specific invariants used by this site.

`website/index.html` declares `goreecloud-glaze-ui=2.1.0` and maps its header/hero/reporting interaction chrome to explicit Glaze material roles. `website/site.css` remains Wardveil-owned product styling layered after the design-system subset.

## Acceptance boundary

Passing repository validation establishes source-level adoption evidence only. It does **not** by itself establish final product acceptance, human Visual Excellence approval, deployed-site acceptance, or production eligibility under the Glaze UI consumer gate.

Wardveil Security remains the authority for security truth. Glaze UI standardizes presentation only and cannot turn a visual state into evidence that a security control actually executed.
