# Wardveil Security Semantic Color Presentation

Wardveil consumes Glaze UI semantic color roles only as a presentation layer. Color never creates, upgrades, or substitutes for Wardveil security evidence, authority, or normalized state.

## State mapping

| Wardveil state | Preferred Glaze UI role |
| --- | --- |
| `protected` | `protected` |
| `attention` | `warning` |
| `degraded` | `danger` |
| `unknown` | `unavailable` |
| `not_applicable` | `surface` |

Every colored state must remain accompanied by a textual label and, where space permits, an icon or other non-color indicator. Compact and wearable surfaces may reduce wording but must not remove the state label or evidence/freshness boundary.

## Authority boundary

The Glaze UI role is derived after Wardveil has normalized authoritative evidence. A green-like or otherwise positive theme rendering must never cause an `attention`, `degraded`, `unknown`, or `not_applicable` record to be interpreted as `protected`. Branding colors must not replace these semantic roles.

Theme implementations may change pigments for light, dark, high-contrast, grayscale, color-vision-deficiency, or customized appearances while preserving the semantic role and non-color indicators.
