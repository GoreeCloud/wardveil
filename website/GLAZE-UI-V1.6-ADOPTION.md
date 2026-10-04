# Wardveil Security Center — Legacy GLAZE UI V1.6 Deployment Mapping

Status: **Legacy / transitional deployment package; current canonical source is elsewhere**  
Local package target: **GLAZE UI V1.6 / 1.6.0 Stable (historical mapping)**  
Historical release source: `a7180679ea851389e0f3004515f9a25f420e716d`  
Historical runtime entrypoint: `js/glaze-v1.6.0.mjs`  
Known-good local rollback baseline: **1.5.1**

## Scope

This record governs the retained `GoreeCloud/wardveil/website` package only. That package remains a V1.6 presentation mapping because it is preserved as legacy/transitional deployment and rollback material for the historical `security.goreecloud.com` path.

It is **not** the current canonical Security Center source authority.

The canonical current Security Center source is `GoreeCloud/static-websites/sites/main/security/index.html`. At static-websites revision `531744f2a82133caca8ddde00fa782415d1a42e1`, that canonical route targets Glaze V1.7 / `1.7.0` with consumer state `source-adopted-unaccepted`.

Wardveil Security remains authoritative for security facts. A favorable color, material, rendered page, source build, or Glaze state cannot create a Protected claim or prove that a security control executed.

## Retained V1.6 behavior

The legacy package intentionally preserves its historical V1.6 mapping:

- `data-glaze-version="1.6"` identifies the retained local package target.
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

The broader historical V1.6 runtime contains additional presentation systems that this static package does not exercise. Their absence is not acceptance evidence for those capabilities.

## Repository-local mapping

`website/glaze-ui-v1.6.0.css` is a Security Center-specific CSS subset for the V1.6 presentation behavior retained by this package. It is not represented as a byte-identical copy of the canonical Glaze runtime.

`website/index.html` and `website/404.html` continue to declare GLAZE UI 1.6.0 because they are the retained legacy package. `website/site.css` remains Wardveil-owned product styling layered after that historical design-system subset.

Historical `GLAZE-UI-V1.1-ADOPTION.md`, `glaze-ui-v1.1.0.css`, `GLAZE-UI-2.1-ADOPTION.md`, and `glaze-ui-2.1.0.css` remain migration provenance and do not ship in the active local V1.6 build.

## Acceptance boundary

Passing repository validation establishes that this **legacy V1.6 deployment package** remains internally consistent and deterministic. It does not make V1.6 the current canonical Glaze target and does not grant current Security Center consumer acceptance.

Current V1.7 consumer acceptance is governed by `docs/integrations/security-center-static-site.md` and the canonical `GoreeCloud/static-websites` source.

Human rendered review, representative browser/device accessibility acceptance, performance/resilience qualification, rollback acceptance, canonical deployed-byte identity, legacy cutover/retirement, production eligibility, Wardveil runtime acceptance, and Stable qualification remain separately governed.

Wardveil Security remains the authority for security truth; Glaze remains presentation-only.
