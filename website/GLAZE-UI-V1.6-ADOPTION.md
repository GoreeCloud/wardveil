# Wardveil Security Center — GLAZE UI V1.6 Source Adoption

Status: **Source Adoption Candidate / consumer acceptance pending**  
Target: **GLAZE UI V1.6 / 1.6.0 Stable**  
Canonical release source: `a7180679ea851389e0f3004515f9a25f420e716d`  
Canonical runtime entrypoint: `js/glaze-v1.6.0.mjs`  
Known-good rollback baseline: **1.5.1**

## Scope

This record maps the Wardveil Security Center public web source to the current GLAZE UI V1.6 / 1.6.0 Stable consumer target without changing Wardveil's security authority or production-security acceptance state.

The Security Center is a bounded administration/information surface. Its source mapping uses the V1.6 presentation-only contract for solid content surfaces, bounded Soft Glaze navigation chrome, semantic interaction sizing, appearance handling, accessibility fallbacks, responsive reflow, and performance-aware material reduction.

Wardveil Security remains authoritative for security facts. A favorable color, material, rendered page, source build, or Glaze UI state cannot create a Protected claim or prove that a security control executed.

## Consumed V1.6 behavior

- `data-glaze-version="1.6"` identifies the active source target.
- Content and security-reading surfaces remain solid Surface planes.
- Soft Glaze remains bounded to persistent navigation chrome.
- General interactive targets retain a 48 px floor; Touch Assistance maps to a 56 px floor.
- System, Light, Dark, and Deep Dark presentation remain user-controlled and local.
- Reduced Transparency removes backdrop-dependent presentation.
- Reduced Motion removes nonessential transitions and smooth scrolling.
- Increased Contrast strengthens boundaries and text cues.
- Forced Colors resolves to system colors without relying on custom material effects.
- Constrained and Minimal performance states reduce or remove blur without changing capability/security truth.
- Unsupported backdrop filtering falls back to a solid raised surface.
- Narrow-screen and safe-area behavior preserve content and navigation rather than hiding security state.

The broader V1.6 runtime contains additional presentation systems that this static public surface does not exercise. Their absence from this bounded source mapping is not represented as acceptance evidence for those capabilities.

## Repository-local mapping

`website/glaze-ui-v1.6.0.css` is a Security Center-specific CSS subset for the V1.6 presentation behavior used by this site. It is not represented as a byte-identical copy of the canonical Glaze runtime.

`website/index.html` and `website/404.html` declare GLAZE UI 1.6.0 as the active source target. `website/site.css` remains Wardveil-owned product styling layered after the design-system subset.

Historical `GLAZE-UI-V1.1-ADOPTION.md`, `glaze-ui-v1.1.0.css`, `GLAZE-UI-2.1-ADOPTION.md`, and `glaze-ui-2.1.0.css` are retained only as migration provenance and must not ship in the active build.

## Acceptance boundary

Passing repository validation establishes **source/build migration evidence only**. It does not by itself establish human rendered review, representative browser/device accessibility acceptance, performance qualification, rollback acceptance, deployed-byte identity, consumer-registry acceptance, production eligibility, Wardveil runtime acceptance, or Stable qualification.

The canonical Glaze consumer registry currently requires V1.6.0 for Security Center and does not grant downstream acceptance automatically.

Wardveil Security remains the authority for security truth; GLAZE UI remains presentation-only.
