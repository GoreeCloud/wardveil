# Wardveil Security Privacy Shield Status Consumer

## Purpose

This contract defines how Wardveil may present minimized GoreeCloud Privacy Shield status without absorbing Privacy Shield authority, inventing evidence, or collecting private activity.

Privacy Shield remains the authoritative platform-wide GoreeCloud privacy capability. Wardveil is the separate platform-wide security capability and may only present the producer's minimized status as contextual information.

## Source contract

Wardveil consumes the public-safe interoperability boundary owned by GoreeCloud Privacy Shield. This public repository intentionally excludes restricted producer repository identity, exact producer source revisions, internal validation-run identifiers, provider-selection artifacts, internal evidence paths, and other non-public operational provenance.

The public boundary is limited to the status schema version and the privacy and authority invariants required for fail-closed consumption.

Wardveil must not infer missing capabilities, repair malformed producer data, or promote a producer acceptance state.

## Public producer-source evidence

`contracts/wardveil.privacy-shield.consumer-source-evidence.json` is a public-safe interoperability record rather than a mirror of restricted producer source-control or operational records.

It records only:

- producer product identity;
- expected status schema version;
- read-only integration scope;
- fail-closed validation requirements;
- privacy-minimization requirements;
- producer-authority preservation;
- current runtime and provider-production acceptance state;
- remaining high-level acceptance gates.

Exact restricted producer-source provenance remains controlled by the producer authority and is deliberately excluded from this public repository. Public Wardveil source therefore does not claim to independently prove a restricted producer commit, source tree, workflow run, provider candidate, or internal topology.

Source evidence does not establish runtime acceptance. Provider production acceptance remains unaccepted. A material public interoperability-contract change must be reviewed before Wardveil updates this consumer boundary.

For any shared interaction beyond read-only presentation, Wardveil still requires separately governed Privacy Shield runtime acceptance, deployed authenticated transport acceptance, target-environment evidence, and independent Wardveil runtime acceptance. Public interoperability evidence alone never authorizes execution, production acceptance, aggregation into required-control protection, or a `Protected by Wardveil` claim.

## Runtime acceptance boundary

Wardveil defines a separate fail-closed runtime-acceptance boundary in `contracts/wardveil.privacy-shield.runtime-acceptance.json`, with record structure defined by `contracts/wardveil.privacy-shield.runtime-acceptance.schema.json`.

A future accepted shared interaction must bind the applicable producer and Wardveil source identities, the exact minimized status record, authenticated encrypted transport, target-environment evidence, privacy-minimization evidence, a production-approved producer runtime, and independent Wardveil consumer acceptance. Evidence must be content-addressed and freshness-bounded.

The shared-interaction record is non-authorizing. It cannot transfer Privacy Shield authority into Wardveil, authorize target execution, establish overall Wardveil production acceptance, or create a `Protected by Wardveil` claim.

No runtime acceptance record exists merely because the acceptance directory exists. Source validation is not runtime acceptance.

## Privacy boundary

A Privacy Shield status record is eligible for normal Wardveil presentation only when it explicitly declares that raw private activity is excluded, credentials are excluded, identifiers are excluded, and runtime acceptance remains required.

At the schema boundary, this means `raw_private_activity_included=false`, `contains_credentials=false`, `contains_identifiers=false`, and `runtime_acceptance_required=true`. These field-level invariants are part of the public interoperability contract and fail closed if weakened or omitted.

If a required guarantee is absent, malformed, expired, future-dated, or weakened, Wardveil must fail closed to an unknown or unavailable presentation state.

Wardveil must not request raw browsing, network, authentication, account, device, or user activity merely to populate a status summary.

## Full-record validation

Wardveil validates the complete status record before applying any presentation mapping. Validation is fail-closed and preserves Privacy Shield as producer authority.

An invalid record must be corrected and reissued by the authoritative producer. Wardveil does not silently normalize malformed identifiers, timestamps, capabilities, or acceptance state.

## Presentation mapping

Wardveil maps producer states conservatively:

| Privacy Shield state | Wardveil presentation |
| --- | --- |
| `protected` with producer production approval | `protected` |
| `protected` without producer production approval | `unknown` |
| `partial` | `attention` |
| `attention` | `attention` |
| `unavailable` | `unknown` |
| `development` | `unknown` |

A Privacy Shield state displayed as protected still does not authorize `claim.protected_by_wardveil=true`.

## Aggregation boundary

Privacy Shield status is informational security-context evidence and is excluded from Wardveil's primary required-control protection aggregation by default.

A product may present Privacy Shield beside Wardveil security controls, but it must not make a Wardveil protection claim more favorable merely because Privacy Shield reports a protected state.

## Provenance

A Wardveil presentation must preserve enough public-safe attribution to identify Privacy Shield as the producer, the record generation time, the normalized presentation state, declared capability states, producer production-approval state, and the fact that Wardveil is a read-only presenter.

Restricted source-control provenance and non-public operational evidence are not part of the public presentation contract.

## Failure behavior

Malformed, unsupported, unsafe, expired, ambiguous, or insufficiently accepted producer data fails closed to `unknown`, never to `protected`.

## Reference validation

`contracts/wardveil.privacy-shield.vectors.json` records canonical presentation cases. `scripts/validate_wardveil_privacy_shield.py` validates mapping and privacy/authority invariants. `scripts/validate_privacy_shield_consumer_source_evidence.py` validates that the public producer-source evidence remains minimized and contains only the approved public-safe field set.

This is a presentation interoperability contract only. It does not create a Privacy Shield runtime inside Wardveil.
