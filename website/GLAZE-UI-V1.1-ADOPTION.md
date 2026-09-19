# Wardveil Security Center — GLAZE UI V1.1 Adoption

Status: **Historical active-source baseline / migration required**  
Active source: **GLAZE UI V1.1 / 1.1.0**  
Current shared Stable consumer target: **GLAZE UI V1.6 / 1.6.0**  
Canonical Stable promotion commit: `15cc76d2bcd4065552dc31c77145b63f34d9e7b2`

## Scope

This record documents the Wardveil Security Center's retained GLAZE UI V1.1 / 1.1.0 source baseline without changing Wardveil's security authority or production-security acceptance state. GLAZE UI V1.6 / 1.6.0 is the current shared Stable consumer authority; Security Center migration and independent acceptance remain pending.

The site preserves its existing information architecture and Sentinel Fold identity while adopting the current V1.1 material, interaction, appearance, accessibility, and target-size contracts. Content and consequential security-reading surfaces remain solid. Soft/translucent material is limited to bounded navigation and interaction chrome.

The earlier `GLAZE-UI-2.1-ADOPTION.md` record and `glaze-ui-2.1.0.css` asset are retained only as historical pre-reset evidence. They are not the active site target after this adoption candidate.

## Consumed V1.1 contract

- `data-glaze-version="1.1"` activates the historical V1.1 namespace used by the active Security Center source.
- Canvas, Base, Raised, and solid Surface roles remain the content foundation.
- Soft Glaze is used only for the persistent navigation/header surface exercised by this site.
- General interactive targets retain a 48 px floor; Touch Assistance maps to a 56 px floor.
- Light, Dark, and Deep Dark use the V1.1 explicit appearance namespace.
- Reduced Transparency removes backdrop-dependent presentation and resolves the header to a solid Raised surface.
- Reduced Motion removes nonessential transforms and smooth scrolling while preserving behavior.
- Increased Contrast strengthens boundaries before adding chroma.
- Forced Colors removes custom material effects and preserves system colors and focus semantics.
- Unsupported backdrop filtering falls back to solid/tonal presentation.
- The V1.1 Deep Teal + Soft Amber atmosphere is subordinate to content and semantic truth; color never creates or strengthens a Wardveil security state.

## Repository-local mapping

`website/glaze-ui-v1.1.0.css` is a Security Center-specific subset mapped to the historical GLAZE UI V1.1 contracts exercised by this public surface. It is not represented as a byte-identical copy of the canonical design-system entrypoint.

`website/validate.py` binds the active subset to the exact V1.1 Stable promotion commit, validates the active version declaration, material budget, accessibility fallbacks, appearance namespace, source/build identity, security headers, and historical-target isolation.

`website/index.html` and `website/404.html` declare GLAZE UI `1.1.0` as the active target. Wardveil-owned `website/site.css` remains product styling layered after the design-system subset.

## Acceptance boundary

Passing repository validation establishes source-level Adoption Candidate evidence only. It does **not** by itself establish human optical approval, final product acceptance, deployed-site acceptance, physical-device acceptance, or production eligibility under the GLAZE UI consumer gate.

The canonical Glaze consumer registry must not mark Security Center production-eligible merely because this repository retains and validates its historical V1.1 source baseline.

Wardveil Security remains the authority for security truth. GLAZE UI standardizes presentation only and cannot turn visual styling, a status color, an icon, or a successfully rendered page into evidence that a security control actually executed.

Security Center must migrate directly to the current GLAZE UI V1.6 / 1.6.0 Stable consumer target and complete repository-local acceptance; retained intermediate release evidence does not establish current conformance.
