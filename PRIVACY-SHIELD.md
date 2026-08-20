# Wardveil Security Privacy Shield Status Consumer

## Purpose

This contract defines how Wardveil Security may present GoreeCloud Privacy Shield status without absorbing Privacy Shield's privacy authority, inventing security evidence, or collecting raw private activity.

Privacy Shield is the platform-wide GoreeCloud privacy and privacy-control identity. Wardveil Security is the separate platform-wide security and protection identity. A Wardveil surface may display minimized Privacy Shield status as contextual information inside a broader protection view, but that presentation does not transfer enforcement authority between the two systems.

## Source contract

Wardveil consumes only status records conforming to the canonical Privacy Shield producer-to-consumer contract owned by `GoreeCloud/goreecloud-privacy-shield` at `contracts/privacy-shield.status.schema.json`.

The Privacy Shield producer remains authoritative for:

- adapter identity and runtime authority;
- declared privacy capabilities;
- capability state;
- runtime acceptance requirements;
- production approval;
- generation time;
- the explicit privacy guarantees carried by the status record.

Wardveil must not infer missing Privacy Shield capabilities or promote a runtime's acceptance state.

## Privacy boundary

A Privacy Shield record is eligible for Wardveil presentation only when it explicitly declares all of the following:

- `raw_private_activity_included` is `false`;
- `contains_credentials` is `false`;
- `contains_identifiers` is `false`;
- `runtime_acceptance_required` is `true`.

If any required guarantee is absent, malformed, or weakened, Wardveil must reject the record for normal presentation and treat the source as unknown/unavailable rather than attempting partial interpretation.

Wardveil must not request browsing history, visited URLs, search queries, DNS queries, network flows, cookies, request bodies, authentication headers, passwords, tokens, private keys, setup keys, recovery information, user identifiers, device identifiers, tracker-learning evidence, per-site exception contents, or raw application telemetry merely to populate a Privacy Shield summary.

## Presentation mapping

Privacy Shield and Wardveil intentionally use different state vocabularies. Wardveil may map a sanitized Privacy Shield status to its presentation vocabulary only with the following conservative rules:

| Privacy Shield state | Wardveil presentation | Rationale |
| --- | --- | --- |
| `protected` | `protected` only when `production_approved=true`; otherwise `unknown` | A protection presentation must not outrun runtime acceptance. |
| `partial` | `attention` | Protection is incomplete and should remain visible for review. |
| `attention` | `attention` | The source already reports that review or action is needed. |
| `unavailable` | `unknown` | Missing status is not passing evidence. |
| `development` | `unknown` | Development state is not accepted protection evidence. |

A Privacy Shield record mapped to Wardveil `protected` still does **not** authorize `claim.protected_by_wardveil=true`. Privacy Shield remains the authority for the privacy capability. Wardveil is presenting the source state, not claiming that Wardveil itself enforced that privacy protection.

## Aggregation boundary

Privacy Shield status is informational security-context evidence and is excluded from Wardveil's primary required-control protection aggregation by default.

A product may show Privacy Shield beside Wardveil security controls, but it must not make a `Protected by Wardveil` claim more favorable because Privacy Shield is protected, and it must not make Privacy Shield appear to be a Wardveil-owned enforcement module.

If a future product needs Privacy Shield to participate in a specific composite posture decision, that scope and requirement must be explicitly defined in that product's own integration contract before aggregation. Availability alone is not authorization to aggregate.

## Provenance

A Wardveil presentation must preserve enough source attribution to identify Privacy Shield and the authoritative runtime producer. The minimum useful presentation is:

- Privacy Shield product identity;
- producer runtime authority;
- generation timestamp;
- normalized high-level state;
- declared capability states;
- production-approval state;
- an explicit statement that Wardveil is a read-only presenter of the record.

The Wardveil icon or `Protected by Wardveil` label must not replace the canonical Privacy Shield identity when the displayed information is specifically Privacy Shield state.

## Failure behavior

Wardveil fails closed for Privacy Shield presentation when:

- the status object is malformed;
- the schema version is unsupported;
- producer identity or runtime authority is missing;
- required privacy guarantees are missing or unsafe;
- runtime acceptance is not explicitly required;
- production approval is not a boolean;
- state is unsupported;
- capabilities are malformed or duplicated.

Failure produces `unknown`, never `protected`.

## Reference validation

`contracts/wardveil.privacy-shield.vectors.json` records the canonical mapping cases. `scripts/validate_wardveil_privacy_shield.py` validates those mappings and the privacy/authority invariants without importing or duplicating Privacy Shield runtime logic.

This is a presentation interoperability contract only. It does not create a Privacy Shield runtime inside Wardveil Security.
